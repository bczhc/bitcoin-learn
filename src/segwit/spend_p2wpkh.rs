use bitcoin::key::Secp256k1;
use bitcoin::sighash::SighashCache;
use bitcoin::{Amount, EcdsaSighashType, OutPoint, PrivateKey, TxOut, Witness};
use bitcoin_demo::signing_helper::sign_sighash;
use bitcoin_demo::{broadcast_tx, default_tx, parse_address, script_hex, wif_to_secret, TESTNET4};

fn main() -> anyhow::Result<()> {
    let wif = "cSDuf6wbKeTnnJJiiqp5ZSku3pV2UZ9Snpz9FpZGaakVKyba8Z7W";
    let outpoint_amount = Amount::from_sat(401348_u64);
    let mut tx = default_tx();
    tx.output = vec![TxOut {
        value: outpoint_amount - Amount::from_sat(300), /* fee */
        script_pubkey: parse_address("tb1qsrd8xr452qye29aj0k22zpec3q5shrzms98rj8", TESTNET4)?
            .script_pubkey(),
    }];
    tx.input[0].previous_output = OutPoint {
        txid: "399b2281eba2a555ee02a057ba4e9d57739677d8dce5c04539ef56db6410c15e".parse()?,
        vout: 0,
    };
    // scriptSig leaves empty when spending a segwit output
    tx.input[0].script_sig = Default::default();

    // Follow the new signing algorithm in BIP143... which is a bit complicated
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(tx.clone());
    let sighash = cache.p2wpkh_signature_hash(
        0,
        script_hex!("001480da730eb450099517b27d94a1073888290b8c5b"),
        outpoint_amount,
        EcdsaSighashType::All,
    )?;
    let signature = sign_sighash(sighash, &wif_to_secret(wif)?, EcdsaSighashType::All);

    let mut witness = Witness::new();
    witness.push(signature);
    witness.push(
        PrivateKey::from_wif(wif)?
            .public_key(&secp)
            .inner
            .serialize(),
    );

    tx.input[0].witness = witness;

    println!("{:?}", broadcast_tx(&tx));
    Ok(())
}
