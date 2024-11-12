//! <https://mempool.space/testnet4/tx/39bfdee89fade142f4b4b637fff54ddf8f7dba44bd23a2605e7bd02e8550ff69>

use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_DROP, OP_DUP, OP_EQUALVERIFY, OP_HASH160};
use bitcoin::opcodes::OP_TRUE;
use bitcoin::script::ScriptBufExt;
use bitcoin::sighash::SighashCache;
use bitcoin::{
    Address, Amount, EcdsaSighashType, KnownHrp, OutPoint, PrivateKey, PubkeyHash, Script,
    ScriptBuf, TxOut, Witness,
};
use bitcoin_demo::signing_helper::sign_sighash;
use bitcoin_demo::{
    broadcast_tx, default_tx, generic_pay_to_one, ideal_checked_op_return, parse_address,
    script_hex, wif_to_pubkey, wif_to_secret, TESTNET4,
};

fn main() -> anyhow::Result<()> {
    let wif = "cSDuf6wbKeTnnJJiiqp5ZSku3pV2UZ9Snpz9FpZGaakVKyba8Z7W";
    let private = PrivateKey::from_wif(wif)?;
    let public = private.public_key(&Default::default());
    let witness_script = witness_script(public.pubkey_hash());
    println!("{}", witness_script);

    let p2wsh = Address::p2wsh(&witness_script, KnownHrp::Testnets)?;
    println!("{}", p2wsh);
    assert_eq!(
        p2wsh.to_string(),
        "tb1qlfmthtp8htj9jk84r68xrk83qqag3vll8tmthwlphwpahjmrwtzs87w5lp"
    );

    let txid = generic_pay_to_one(
        TESTNET4,
        wif,
        "7501e19cc1c97e4a7f41bf5b7a9364d45a08353de543de5c9f8d5c19d27237b3:1",
        script_hex!("001480da730eb450099517b27d94a1073888290b8c5b"),
        Amount::from_sat(400448),
        true,
        &p2wsh.to_string(),
        Amount::from_sat(400448 - 300),
    )?;
    println!("{}", txid);

    spend(OutPoint { txid, vout: 0 }, &witness_script, wif)?;
    Ok(())
}

fn spend(outpoint: OutPoint, witness_script: &Script, wif: &str) -> anyhow::Result<()> {
    let mut tx = default_tx();
    tx.input[0].previous_output = outpoint;

    tx.output = vec![
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ideal_checked_op_return("见证放入其他数据测试".as_bytes()),
        },
        TxOut {
            value: Amount::from_sat(400148 - 300),
            script_pubkey: parse_address("tb1qsrd8xr452qye29aj0k22zpec3q5shrzms98rj8", TESTNET4)?
                .script_pubkey(),
        },
    ];

    let sighash_type = EcdsaSighashType::All;
    let mut cache = SighashCache::new(tx.clone());
    let sighash =
        cache.p2wsh_signature_hash(0, witness_script, Amount::from_sat(400148), sighash_type)?;
    let signature = sign_sighash(sighash, &wif_to_secret(wif).unwrap(), sighash_type);
    let mut witness = Witness::new();
    witness.push("随便一些什么额外的数据".as_bytes());
    witness.push(signature);
    witness.push(wif_to_pubkey(wif).unwrap().inner.serialize());
    witness.push(
        witness_script.as_bytes(), /* witness script as the last item */
    );

    tx.input[0].witness = witness;

    println!("{}", broadcast_tx(&tx).unwrap());
    Ok(())
}

/// Witness script (redeem-script).
///
/// Unlocking process:
///
/// ```text
/// <inscription-data>
/// <signature>
/// <pubkey>
///
/// DUP
/// HASH160
/// <pubkey-hash>
/// EQUALVERIFY
/// CHECKSIGVERIFY
/// DROP
/// TRUE
///
/// ```
fn witness_script(pubkey_hash: PubkeyHash) -> ScriptBuf {
    ScriptBuf::builder()
        .push_opcode(OP_DUP)
        .push_opcode(OP_HASH160)
        .push_slice(pubkey_hash.as_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_opcode(OP_DROP)
        .push_opcode(OP_TRUE)
        .into_script()
}
