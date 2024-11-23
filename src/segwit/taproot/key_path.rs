use bitcoin::key::{TapTweak, UntweakedKeypair};
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Address, Amount, KnownHrp, OutPoint, TapNodeHash, TapSighashType, TxOut, Witness};
use bitcoin_demo::{
    confirm_to_broadcast, default_tx, ideal_checked_op_return, script_hex_owned, sha256, EncodeHex,
};
use hex_literal::hex;

fn main() -> anyhow::Result<()> {
    use bitcoin::secp256k1 as secp;
    let secp: secp::Secp256k1<_> = Default::default();
    let secret = sha256("Chikipi".as_bytes());
    println!("Secret: {}", secret.hex());
    let secret = SecretKey::from_slice(&secret)?;

    let pk = secp::PublicKey::from_secret_key(&secp, &secret);
    // Add two tapscripts. For the scripts, see `tweak.rs`.
    let script_root = hex!("df2208e7ab006fb6211cca5c5dc42002088d4a3f22afd361c829c72f7fd8251a");
    let address = Address::p2tr(
        &secp,
        pk.into(),
        Some(TapNodeHash::from_byte_array(script_root)),
        KnownHrp::Testnets,
    );
    println!("Address: {}", address);

    // ===================== SPEND =====================
    let outpoint = OutPoint {
        txid: "251a84dbdc515fc8748425bc4061f9a386bb298531962f1d579e52507426bd50".parse()?,
        vout: 0,
    };
    let mut tx = default_tx();
    tx.input[0].previous_output = outpoint;
    tx.output = vec![
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ideal_checked_op_return("Taproot key-spend 花费测试".as_bytes()),
        },
        // change
        TxOut {
            value: Amount::from_sat(1500),
            script_pubkey: script_hex_owned!("001480da730eb450099517b27d94a1073888290b8c5b"),
        },
    ];

    let mut cache = SighashCache::new(tx.clone());
    let prevouts = Prevouts::One(
        0,
        TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: script_hex_owned!(
                "51200da89757c359da8514ecfd95895c839da9ba6baeafd59c4419d82022ff8696d6"
            ),
        },
    );
    let sighash = cache.taproot_key_spend_signature_hash(
        0,
        &prevouts,
        TapSighashType::AllPlusAnyoneCanPay,
    )?;

    // The secret key used to sign must be done the same tweak we've done to the public key first.
    let keypair = UntweakedKeypair::from_secret_key(&secp, &secret);
    let tweaked_keypair = keypair.tap_tweak(&secp, Some(TapNodeHash::from_byte_array(script_root)));

    // In pay-to-taproot, the trailing sighash flag is optional.
    // So the signature is 64 or 65 bytes. (Schnorr signature is standardized to always 64 bytes)
    let signature = secp.sign_schnorr(
        &Message::from_digest(sighash.to_byte_array()),
        &tweaked_keypair.to_inner(),
    );
    // In key-path mode, witness has only one field (the signature).
    let mut witness = Witness::new();
    witness.push(signature.serialize());
    tx.input[0].witness = witness;

    confirm_to_broadcast(&tx);

    Ok(())
}
