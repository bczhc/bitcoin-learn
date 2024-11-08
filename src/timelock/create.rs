use bitcoin::absolute::{Height, LockTime};
use bitcoin::address::script_pubkey::{BuilderExt, ScriptExt};
use bitcoin::address::ParseError;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CLTV, OP_DROP};
use bitcoin::opcodes::OP_TRUE;
use bitcoin::script::{PushBytes, ScriptBufExt};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    absolute, Address, Amount, EcdsaSighashType, Network, NetworkKind, OutPoint, PrivateKey,
    ScriptBuf, Sequence, TestnetVersion, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_demo::{confirm_to_broadcast, ecdsa_sign, EncodeHex};

const FEE: Amount = Amount::from_sat(300);

fn main() -> anyhow::Result<()> {
    /* ========== INPUTS ========== */
    let timestamp = "2024-10-21T17:00:00+08:00"
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .timestamp() as u32;
    println!("{}", timestamp);
    let lock_time = absolute::LockTime::Seconds(absolute::Time::from_consensus(timestamp)?);
    let redeem = ScriptBuf::builder()
        .push_lock_time(lock_time)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_opcode(OP_TRUE)
        .into_script();
    println!("Redeem: {}", redeem.hex());
    let receiver_script = redeem.to_p2sh()?;

    let sender_wif = "cSyembsXLAoYEbnrzDGmkD4oKM8fwoqVNPf5jQJ4RqeGnvrtxozQ";
    let input_outpoint_txid = "e22bd3c92b1a5d83df3b033050b0f03d6566a00d995d00f622add1c436154747";
    let input_outpoint_index = 1;
    let input_utxo_total_amount = 485508;
    let receiver_amount = 1500;
    /* ============================= */

    let network = Network::Testnet(TestnetVersion::V4);
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let sender_prk = PrivateKey::from_wif(sender_wif)?;
    assert_eq!(sender_prk.network, NetworkKind::Test);

    let sender_address = Address::p2pkh(sender_prk.public_key(&secp), network);

    let mut tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::from_consensus(0),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: input_outpoint_txid.parse()?,
                vout: input_outpoint_index,
            },
            script_sig: ScriptBuf::new(), /* placeholder */
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(receiver_amount),
                // script_pubkey: to_address.script_pubkey(),
                script_pubkey: receiver_script,
            },
            // don't forget the change!!
            TxOut {
                value: Amount::from_sat(input_utxo_total_amount - receiver_amount - FEE.to_sat()),
                script_pubkey: sender_address.script_pubkey(),
            },
        ],
    };

    let cache = SighashCache::new(&tx);
    let signing_hash = cache.legacy_signature_hash(
        0,
        &sender_address.script_pubkey(),
        EcdsaSighashType::All as u32,
    )?;
    let signature = ecdsa_sign(&sender_prk.inner, signing_hash.to_byte_array());
    let sender_puk = sender_prk.public_key(&secp);

    let mut tx_sig = signature.serialize_der().to_vec();
    tx_sig.push(EcdsaSighashType::All as u8);

    let script_sig = ScriptBuf::builder()
        .push_slice(<&PushBytes as TryFrom<&[u8]>>::try_from(&tx_sig)?)
        .push_key(sender_puk)
        .into_script();
    // put the signature back to script_sig
    // we can broadcast it now!
    tx.input[0].script_sig = script_sig;

    confirm_to_broadcast(&tx);
    Ok(())
}

fn parse_address(address: &str) -> Result<Address, ParseError> {
    address
        .parse::<Address<_>>()?
        .require_network(Network::Testnet(TestnetVersion::V4))
}

fn op_return_script(msg: &[u8]) -> anyhow::Result<ScriptBuf> {
    Ok(ScriptBuf::new_op_return(<&PushBytes>::try_from(msg)?))
}
