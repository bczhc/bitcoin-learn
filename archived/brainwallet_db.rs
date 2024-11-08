#![feature(try_blocks)]
#![allow(incomplete_features, const_evaluatable_unchecked)]
#![feature(generic_const_exprs)]

use std::io::{stdin, BufRead, BufReader};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::Arc;
use std::thread::spawn;

use bincode::config::standard;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::{Address, Network};
use bitcoincore_rpc::{Auth, RpcApi};
use rayon::prelude::{ParallelBridge, ParallelIterator};
use rocksdb::{SingleThreaded, TransactionDB, DB};
use sha2::Sha256;

use bitcoin_demo::{
    blake3, cli_args, hash, hash_iter, secret_to_pubkey, secret_to_pubkey_uncompressed, sha256,
    sha256d, timestamp,
};

fn main() {
    let db_path = "./db";
    let args = cli_args();
    if !args.is_empty() {
        // lookup mode
        let db = DB::open_default(db_path).unwrap();
        for line in stdin().lines() {
            let line = line.unwrap();
            let Some(get) = db.get(&line).unwrap() else {
                println!("Input: {}; None", line);
                continue
            };
            let value = bincode::decode_from_slice::<Value, _>(&get, standard()).unwrap();
            assert_eq!(value.1, get.len());
            let value = value.0;
            println!(
                "Input: {}, Private key: {}, method: {}, message: {:?}",
                line,
                hex::encode(value.0),
                value.1,
                value.2
            )
        }

        return;
    }

    let (sender, receiver) = sync_channel::<Record>(20480);

    // start_provider1(sender);
    // start_provider2(sender);
    start_provider3(sender);
    // start_provider4(sender);

    let open = || TransactionDB::<SingleThreaded>::open_default(db_path).unwrap();
    let db = open();
    let mut transaction = db.transaction();

    let mut start_time = timestamp();
    let mut count = 0_u64;
    let mut serialize_buf = [0_u8; 1024];
    for x in receiver {
        // println!("{:?}", x);
        // continue;
        let key = x.0;
        let write_size = bincode::encode_into_slice(&x.1, &mut serialize_buf, standard()).unwrap();

        transaction.put(&key, &serialize_buf[..write_size]).unwrap();

        count += 1;
        if timestamp() - start_time >= 60_000 {
            transaction.commit().unwrap();
            transaction = db.transaction();
            println!("\n{}\n", count);
            start_time = timestamp();
            count = 0;
        }
    }
    transaction.commit().unwrap();
}

/// hash(password)
fn start_provider1(sender: SyncSender<Record>) {
    spawn(move || {
        let reader = BufReader::new(stdin());
        let lines = reader.lines().filter_map(|x| x.ok());
        lines.par_bridge().for_each_with(sender, |tx, x| {
            let _: anyhow::Result<()> = try {
                let line = x;

                let k1 = Secp256k1::new();
                macro_rules! key_3addrs_add {
                    ($key:expr, $method:literal) => {
                        let key = $key;
                        let addr1 = Address::p2pkh(&secret_to_pubkey(&k1, &key), Network::Bitcoin)
                            .to_string();
                        let addr2 =
                            Address::p2wpkh(&secret_to_pubkey(&k1, &key), Network::Bitcoin)?
                                .to_string();
                        let addr3 = Address::p2pkh(
                            &secret_to_pubkey_uncompressed(&k1, &key),
                            Network::Bitcoin,
                        )
                        .to_string();
                        tx.send(Record(
                            addr1,
                            Value(key, $method, Message::String(line.clone())),
                        ))
                        .unwrap();
                        tx.send(Record(
                            addr2,
                            Value(key, $method, Message::String(line.clone())),
                        ))
                        .unwrap();
                        tx.send(Record(
                            addr3,
                            Value(key, $method, Message::String(line.clone())),
                        ))
                        .unwrap();
                    };
                }

                let line_bytes = line.as_bytes();
                let key = hash!(Sha256, line_bytes);
                key_3addrs_add!(key, 1);
                let key = hash!(Sha256, line_bytes, 2);
                key_3addrs_add!(key, 2);
                let key = hash!(Sha256, line_bytes, 3);
                key_3addrs_add!(key, 3);
                let key = hash!(Sha256, line_bytes, 65536);
                key_3addrs_add!(key, 4);
                let key = hash!(blake3::Hasher, line_bytes);
                key_3addrs_add!(key, 5);
                // let key = hash!(blake3::Hasher, line_bytes, 65536);
                // key_3addrs_add!(key, 6);
                let key = sha256(hex::encode(sha256(line_bytes)).as_bytes());
                key_3addrs_add!(key, 7);
                let key = sha256(&hash!(ripemd::Ripemd160, line_bytes));
                key_3addrs_add!(key, 8);
                let key = hash!(ripemd::Ripemd256, &sha256(line_bytes));
                key_3addrs_add!(key, 9);
                let key = hash!(ripemd::Ripemd256, line_bytes);
                key_3addrs_add!(key, 10);
                let key = hash!(Sha256, line_bytes, 100);
                key_3addrs_add!(key, 11);
                let key = hash!(Sha256, line_bytes, 256);
                key_3addrs_add!(key, 12);
                let key = sha256(&hash!(md5::Md5, line_bytes, 1));
                key_3addrs_add!(key, 13);
            };
        });
    });
}

/// block hash as the secret
fn start_provider2(sender: SyncSender<Record>) {
    spawn(move || {
        let client = bitcoincore_rpc::Client::new(
            "localhost:8332",
            Auth::UserPass(String::from("bitcoinrpc"), String::from("123")),
        )
        .unwrap();
        let block_count = client.get_block_count().unwrap();
        (0..=block_count)
            .inspect(|x| eprintln!("{}", x))
            .map(|h| client.get_block_hash(h).unwrap())
            .par_bridge()
            .for_each_with(sender, |s, h| {
                let k1 = Default::default();
                let bh: [u8; 32] = *h.as_ref();
                let rbh = {
                    let mut a = bh;
                    a.reverse();
                    a
                };
                let block_hash_string = h.to_string();

                derive_addrs(&k1, bh, s, Message::Binary(Vec::new()), 14);
                derive_addrs(&k1, rbh, s, Message::Binary(Vec::new()), 15);
                let key = sha256(&bh);
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(bh)), 16);
                let key = sha256(&rbh);
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbh)), 17);
                let key = sha256d(&bh);
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(bh)), 18);
                let key = sha256d(&rbh);
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbh)), 19);
                let key = sha256(block_hash_string.as_bytes());
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbh)), 20);
                let key = sha256d(block_hash_string.as_bytes());
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbh)), 21);
                let key = blake3(&rbh);
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbh)), 22);
            });
    });
}

/// block merkle root and txid as the secret
fn start_provider3(sender: SyncSender<Record>) {
    spawn(move || {
        let client = bitcoincore_rpc::Client::new(
            "localhost:8332",
            Auth::UserPass(String::from("bitcoinrpc"), String::from("123")),
        )
        .unwrap();
        let block_count = client.get_block_count().unwrap();
        let client = Arc::new(client);
        let for_each_client = Arc::clone(&client);

        (0..=block_count)
            .inspect(|x| eprintln!("{}", x))
            .par_bridge()
            .for_each_with((for_each_client, sender), |(client, s), height| {
                let k1 = Default::default();
                let b = client.get_block_hash(height).unwrap();
                let b = client.get_block(&b).unwrap();

                let bytes: [u8; 32] = *b.header.merkle_root.as_ref();
                let rbytes = {
                    let mut a = bytes;
                    a.reverse();
                    a
                };
                let hex_string = b.header.merkle_root.to_string();

                derive_addrs(&k1, bytes, s, Message::Binary(Vec::new()), 23);
                derive_addrs(&k1, rbytes, s, Message::Binary(Vec::new()), 24);
                let key = sha256(&bytes);
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(bytes)), 25);
                let key = sha256(&rbytes);
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbytes)), 26);
                let key = sha256d(&bytes);
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(bytes)), 27);
                let key = sha256d(&rbytes);
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbytes)), 28);
                let key = sha256(hex_string.as_bytes());
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbytes)), 29);
                let key = sha256d(hex_string.as_bytes());
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbytes)), 30);
                let key = blake3(&rbytes);
                derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbytes)), 31);

                for tx in b.txdata {
                    let id = tx.txid();
                    let bytes: [u8; 32] = *id.as_ref();
                    let rbytes = {
                        let mut a = bytes;
                        a.reverse();
                        a
                    };
                    let hex_string = id.to_string();

                    derive_addrs(&k1, bytes, s, Message::Binary(Vec::new()), 32);
                    derive_addrs(&k1, rbytes, s, Message::Binary(Vec::new()), 33);
                    let key = sha256(&bytes);
                    derive_addrs(&k1, key, s, Message::Binary(Vec::from(bytes)), 34);
                    let key = sha256(&rbytes);
                    derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbytes)), 35);
                    let key = sha256d(&bytes);
                    derive_addrs(&k1, key, s, Message::Binary(Vec::from(bytes)), 36);
                    let key = sha256d(&rbytes);
                    derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbytes)), 37);
                    let key = sha256(hex_string.as_bytes());
                    derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbytes)), 38);
                    let key = sha256d(hex_string.as_bytes());
                    derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbytes)), 39);
                    let key = blake3(&rbytes);
                    derive_addrs(&k1, key, s, Message::Binary(Vec::from(rbytes)), 40);
                }
            });
    });
}

/// Derive three different addresses from one secret
/// key, and send.
///
/// - p2pkh (from compressed public key)
/// - p2pkh (from uncompressed public key)
/// - p2wpkh
#[inline]
fn derive_addrs(
    k1: &Secp256k1<All>,
    ec: [u8; 32],
    sender: &SyncSender<Record>,
    message: Message,
    method: u32,
) {
    let pubkey1 = secret_to_pubkey(k1, &ec);
    let pubkey2 = secret_to_pubkey_uncompressed(k1, &ec);
    let addr1 = Address::p2pkh(&pubkey1, Network::Bitcoin);
    let addr2 = Address::p2pkh(&pubkey2, Network::Bitcoin);
    let addr3 = Address::p2wpkh(&pubkey1, Network::Bitcoin).unwrap();

    sender
        .send(Record(
            addr1.to_string(),
            Value(ec, method, message.clone()),
        ))
        .unwrap();
    sender
        .send(Record(
            addr2.to_string(),
            Value(ec, method, message.clone()),
        ))
        .unwrap();
    sender
        .send(Record(addr3.to_string(), Value(ec, method, message)))
        .unwrap();
}

#[derive(Debug, bincode::Encode, bincode::Decode)]
struct Record(String /* address */, Value);
#[derive(Debug, bincode::Encode, bincode::Decode)]
struct Value(
    [u8; 32], /* ec */
    u32,      /* derive method */
    Message,  /* hash input message */
);

#[derive(Debug, bincode::Encode, bincode::Decode, Clone)]
enum Message {
    String(String),
    Binary(Vec<u8>),
}
