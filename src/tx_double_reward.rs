//! Bitcoin: reward back to the sender!

#![feature(yeet_expr)]

use crate::reward::LocalStorage;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TestnetVersion};
use bitcoin_hashes::Hash;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use log::{debug, info};
use once_cell::sync::Lazy;
use std::io;
use std::ops::AddAssign;
use std::path::Path;
use zmq::{Socket, SocketType};

const REWARD_SOURCE_WIF: &str = "cSrmvREBQvmGLwv9XvHSY6trK8Dm8Tv9aEKAWCaRQcvQuC3uMUVP";
const TO_REWARD_ADDRESS: &str = "mxmmXFMhzrmb6ViLPKudQfWz5uQNe17ANq";

const FEE: Amount = Amount::from_sat(500);
const NETWORK: Network = Network::Testnet(TestnetVersion::V4);
/// Reward doubled amount of the received coins
const RETURN_RATE: u64 = 2;
const LOCAL_DATA_PATH: &str = "local-data.json";

/// `txindex=1` should be enabled in bitcoin-core in order to find the previous outpoint
/// transaction.
static RPC: Lazy<Client> =
    Lazy::new(|| bitcoin_rpc().expect("Bitcoin-core RPC client initialization failed"));

const ZMQ_ADDRESS: &str = match NETWORK {
    Network::Bitcoin => "tcp://127.0.0.1:28332",
    Network::Testnet(TestnetVersion::V4) => "tcp://127.0.0.1:48000",
    _ => unimplemented!(),
};

const BITCOIN_RPC_ADDRESS: &str = match NETWORK {
    Network::Bitcoin => "localhost:8332",
    Network::Testnet(TestnetVersion::V4) => "localhost:48332",
    _ => unimplemented!(),
};

fn main() -> anyhow::Result<()> {
    set_up_logging("./tx-double-reward.log")?;
    info!("ZMQ address: {ZMQ_ADDRESS}");
    info!("Bitcoin-core RPC address: {BITCOIN_RPC_ADDRESS}");
    info!("Reward source WIF: {REWARD_SOURCE_WIF}");
    info!("To-reward address: {TO_REWARD_ADDRESS}");
    info!(
        "Local data: {:?}",
        LocalStorage::new(LOCAL_DATA_PATH)?.load()?
    );
    info!("Fee: {FEE}");
    info!("Network: {NETWORK}");
    info!("Return rate: {RETURN_RATE}");
    info!("Testing RPC connection...");
    info!("Block count: {}", RPC.get_block_count().unwrap());
    let zmq = zmq_connect("hashblock")?;
    let mut reward_source = reward::Source::new(LocalStorage::new(LOCAL_DATA_PATH)?)?;
    info!("Waiting for new blocks...");
    loop {
        // received a new block...
        let message = zmq.recv_msg(0)?;
        // ZMQ message:
        // | hashblock | <32-byte block hash in Little Endian> | <uint32 sequence number in Little Endian>
        // only take the block hash portion
        let Ok(mut hash): Result<[u8; 32], _> = message.as_ref().try_into() else {
            continue;
        };
        // bitcoin blocks internally use little-endian uint256
        hash.reverse();
        let hash = bitcoincore_rpc::bitcoin::BlockHash::from_byte_array(hash);
        reward_source.handle_new_block(hash)?;
    }
}

fn zmq_connect(subscript: &str) -> anyhow::Result<Socket> {
    let zmq = zmq::Context::new();
    let socket = zmq.socket(SocketType::SUB)?;
    socket.connect(ZMQ_ADDRESS)?;
    socket.set_subscribe(subscript.as_bytes())?;
    Ok(socket)
}

fn bitcoin_rpc() -> bitcoincore_rpc::Result<Client> {
    Client::new(
        BITCOIN_RPC_ADDRESS,
        Auth::UserPass(String::from("bitcoinrpc"), String::from("123")),
    )
}

mod reward {
    use crate::{reward, FEE, NETWORK, RETURN_RATE, REWARD_SOURCE_WIF, RPC, TO_REWARD_ADDRESS};
    use anyhow::anyhow;
    use bitcoin::absolute::LockTime;
    use bitcoin::address::script_pubkey::BuilderExt;
    use bitcoin::script::{PushBytes, ScriptBufExt, ScriptExt};
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::SighashCache;
    use bitcoin::transaction::Version;
    use bitcoin::{
        consensus, Address, Amount, EcdsaSighashType, OutPoint, PublicKey, Script, ScriptBuf,
        Sequence, Transaction, TxIn, TxOut, Txid,
    };
    use bitcoin_demo::{bitcoin_old_to_new, EncodeHex};
    use bitcoin_hashes::Hash;
    use bitcoincore_rpc::RpcApi;
    use log::{debug, info};
    use once_cell::sync::Lazy;
    use serde::{Deserialize, Serialize};
    use std::fs::File;
    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use yeet_ops::yeet;

    static SOURCE_ADDRESS_SCRIPT_PUBKEY: Lazy<ScriptBuf> = Lazy::new(|| {
        let prk = bitcoin::PrivateKey::from_wif(REWARD_SOURCE_WIF).unwrap();
        let pubkey = prk.public_key(&Default::default());
        Address::p2pkh(pubkey, NETWORK).script_pubkey()
    });

    static SOURCE_ADDRESS_PUBKEY: Lazy<PublicKey> = Lazy::new(|| {
        let prk = bitcoin::PrivateKey::from_wif(REWARD_SOURCE_WIF).unwrap();
        prk.public_key(&Default::default())
    });

    static SOURCE_ECDSA_SECRET: Lazy<SecretKey> = Lazy::new(|| {
        let prk = bitcoin::PrivateKey::from_wif(REWARD_SOURCE_WIF).unwrap();
        prk.inner
    });

    fn p2pkh_to_script_pubkey(address: &str) -> ScriptBuf {
        let address = address
            .parse::<Address<_>>()
            .unwrap()
            .require_network(NETWORK)
            .unwrap();
        let script = address.script_pubkey();
        assert!(script.is_p2pkh());
        script
    }
    pub static TO_REWARD_PUBKEY: Lazy<ScriptBuf> =
        Lazy::new(|| p2pkh_to_script_pubkey(TO_REWARD_ADDRESS));

    pub struct Source {
        outpoint: OutPoint,
        balance: Amount,
        storage: LocalStorage,
    }

    impl Source {
        pub fn new(storage: LocalStorage) -> anyhow::Result<Self> {
            let data = storage.load()?;
            Ok(Self {
                outpoint: data.outpoint.parse()?,
                balance: Amount::from_sat(data.balance),
                storage,
            })
        }

        /// The last signing phase.
        ///
        /// This should be called after the transaction built well. SigHash type: All.
        fn sign(&self, tx: &mut Transaction) -> anyhow::Result<()> {
            info!("Signing...");
            assert_eq!(tx.input.len(), 1);
            let sig_hash_type = EcdsaSighashType::All;
            let cache = SighashCache::new(tx.clone());
            let hash = cache.legacy_signature_hash(
                0,
                SOURCE_ADDRESS_SCRIPT_PUBKEY.as_ref(),
                sig_hash_type as u32,
            )?;
            let message = Message::from_digest(hash.to_byte_array());
            let ecdsa_signature = Secp256k1::default()
                .sign_ecdsa(&message, &*SOURCE_ECDSA_SECRET)
                .serialize_der();
            let mut bitcoin_signature = ecdsa_signature.to_vec();
            bitcoin_signature.push(sig_hash_type as u8);
            tx.input[0].script_sig = ScriptBuf::builder()
                .push_slice(<&PushBytes>::try_from(bitcoin_signature.as_slice())?)
                .push_key(*SOURCE_ADDRESS_PUBKEY)
                .into_script();
            Ok(())
        }

        pub fn send(
            &mut self,
            amount: Amount,
            script_pubkey: &Script,
        ) -> anyhow::Result<bitcoincore_rpc::bitcoin::Txid> {
            info!("Send reward: amount {}, target: {}", amount, script_pubkey);
            let mut tx = Transaction {
                version: Version::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    witness: Default::default(),
                    sequence: Sequence::FINAL,
                    previous_output: self.outpoint,
                    script_sig: Default::default(), /* placeholder for the signature use */
                }],
                output: vec![
                    // reward
                    TxOut {
                        value: amount,
                        script_pubkey: script_pubkey.into(),
                    },
                    // change
                    TxOut {
                        value: self.balance - amount - FEE,
                        script_pubkey: SOURCE_ADDRESS_SCRIPT_PUBKEY.clone(),
                    },
                ],
            };
            debug!("Reward tx: {:?}", tx);
            self.sign(&mut tx)?;
            let txid = RPC.send_raw_transaction(consensus::serialize(&tx).as_slice())?;
            // update the reward pool outpoint
            info!("Updating the latest outpoint and reward-source balance...");
            self.outpoint = OutPoint {
                txid: bitcoin_old_to_new(&txid),
                // change output in the reward transaction is fixed to #1
                vout: 1,
            };
            self.balance -= FEE + amount;
            let local_data = LocalData {
                outpoint: format!("{}", self.outpoint),
                balance: self.balance.to_sat(),
            };
            self.storage.store(&local_data)?;
            debug!("Updated LocalData: {:?}", local_data);
            Ok(txid)
        }

        pub fn handle_new_block(
            &mut self,
            hash: bitcoincore_rpc::bitcoin::BlockHash,
        ) -> anyhow::Result<()> {
            let block = RPC.get_block(&hash)?;
            info!(
                "Received new block: {}, tx count: {}",
                hash,
                block.txdata.len()
            );
            for tx in block.txdata {
                // if the last digit of the (displayed) txid is even
                let last_digit_even = tx.compute_txid().to_byte_array()[0] % 2 == 0;

                let send_amount: bitcoincore_rpc::bitcoin::Amount = tx
                    .output
                    .iter()
                    .filter(|&x| x.script_pubkey.as_bytes() == TO_REWARD_PUBKEY.as_bytes())
                    .map(|x| x.value)
                    .sum();
                let send_amount: Amount = bitcoin_old_to_new(&send_amount);
                if send_amount != Amount::ZERO {
                    info!(
                        "Received transaction: {}, amount: {}, txid is even: {}",
                        tx.compute_txid(),
                        send_amount,
                        last_digit_even,
                    );
                    if !last_digit_even {
                        info!("This transaction has an odd txid! We don't send reward back to it.");
                        continue;
                    }
                    // this transaction sent coins to the "reward address"; reward it
                    // ...but we only take the first tx-in to reward
                    let first_in = &tx.input[0];
                    // it's supposed not to be a coinbase input
                    assert!(!first_in.previous_output.is_null());
                    let Ok(prev_tx) = RPC.get_raw_transaction(&first_in.previous_output.txid, None)
                    else {
                        // Can't find? Just ignore it.
                        debug!("Sender outpoint tx not found");
                        continue;
                    };
                    debug!("Sender outpoint tx: {:?}", prev_tx);
                    let prev_txo = &prev_tx.output[first_in.previous_output.vout as usize];
                    // Rewards should be sent to this scriptPubKey. This is defined as the sender's
                    // wallet address.
                    let prev_txo_script_pubkey = &prev_txo.script_pubkey;
                    let result = self.send(
                        send_amount * RETURN_RATE,
                        &ScriptBuf::from_bytes(prev_txo_script_pubkey.to_bytes()),
                    );
                    info!("Reward transaction result: {:?}", result);
                }
            }
            Ok(())
        }
    }

    pub struct LocalStorage {
        path: PathBuf,
    }

    #[derive(Serialize, Deserialize, Debug, Default)]
    pub struct LocalData {
        outpoint: String,
        balance: u64, /* in sats */
    }

    impl LocalStorage {
        pub fn new(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
            let path = path.into();

            if !path.exists() {
                serde_json::to_writer_pretty(File::create(&path)?, &LocalData::default())?;
                yeet!(anyhow!(
                    "Please complete the storage file: {}",
                    path.display()
                ));
            }

            Ok(Self { path })
        }

        pub fn load(&self) -> anyhow::Result<LocalData> {
            Ok(serde_json::from_reader(File::open(&self.path)?)?)
        }

        pub fn store(&self, value: &LocalData) -> anyhow::Result<()> {
            Ok(serde_json::to_writer_pretty(
                File::create(&self.path)?,
                &value,
            )?)
        }
    }
}

pub fn set_up_logging(file: impl AsRef<Path>) -> anyhow::Result<()> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                humantime::format_rfc3339(std::time::SystemTime::now()),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        .chain(io::stdout())
        .chain(fern::log_file(file)?)
        .apply()?;
    Ok(())
}
