use bitcoin::key::{TapTweak, UntweakedKeypair, UntweakedPublicKey};
use bitcoin::opcodes::all::{OP_EQUAL, OP_PUSHNUM_2};
use bitcoin::script::ScriptBufExt;
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootMerkleBranch};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, KnownHrp, OutPoint, ScriptBuf, TapNodeHash, TapSighashType, TxOut, Witness,
};
use bitcoin_demo::secp256k1::PublicKeyExt;
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
    let witness_program = address.witness_program().unwrap();
    let taproot = witness_program.program().as_bytes();
    println!("Taproot: {}", taproot.hex());

    // ===================== SPEND (key-path) =====================
    let outpoint = OutPoint {
        txid: "251a84dbdc515fc8748425bc4061f9a386bb298531962f1d579e52507426bd50".parse()?,
        vout: 0,
    };
    let mut tx = default_tx();
    // P2TR requires transaction version two.
    tx.version = Version::TWO;
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

    let tweaked_pubkey_x = tweaked_keypair.to_inner().public_key().coordinates().0;
    assert_eq!(tweaked_pubkey_x, taproot);

    // In pay-to-taproot, the trailing sighash flag is optional. The default is All, but we're
    // using All | AnyoneCanPay, so it should be added.
    // So the signature is 64 or 65 bytes. (Schnorr signature is standardized to always 64 bytes)
    let signature = secp.sign_schnorr(
        &Message::from_digest(sighash.to_byte_array()),
        &tweaked_keypair.to_inner(),
    );
    let mut buf = [0_u8; 64 + 1];
    buf[..64].copy_from_slice(&signature.serialize());
    buf[64] = TapSighashType::AllPlusAnyoneCanPay as u8;
    // In key-path mode, witness has only one field (the signature).
    let mut witness = Witness::new();
    witness.push(buf);
    tx.input[0].witness = witness;

    // ready to broadcast
    // confirm_to_broadcast(&tx);

    // ===================== SPEND (script-path) =====================
    let outpoint = OutPoint {
        txid: "251a84dbdc515fc8748425bc4061f9a386bb298531962f1d579e52507426bd50".parse()?,
        vout: 1,
    };
    let mut tx = default_tx();
    tx.version = Version::TWO;
    tx.input[0].previous_output = outpoint;
    tx.input[0].witness = Witness::default();
    tx.output = vec![
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ideal_checked_op_return("Taproot script-path 花费测试".as_bytes()),
        },
        // change
        TxOut {
            value: Amount::from_sat(1500),
            script_pubkey: script_hex_owned!("001480da730eb450099517b27d94a1073888290b8c5b"),
        },
    ];

    let tapscript1 = ScriptBuf::builder().push_opcode(OP_EQUAL).into_script();
    let tapscript2 = ScriptBuf::builder()
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_EQUAL)
        .into_script();
    let path = [
        // TODO: use bitcoin lib
        TapNodeHash::from_byte_array(hex!(
            "90de350ea8c68793e5ca61801f2532c1d30aa605274326ed1296eaa9a22e4976"
        )),
    ];

    let inputs = [hex!("43617474697661"), hex!("43617474697661")];
    // witness format: <script-input>... <tapscript> <control-block>
    let mut witness = Witness::new();
    for input in inputs {
        witness.push(input);
    }
    witness.push(tapscript1.as_bytes());
    let cb = ControlBlock {
        leaf_version: LeafVersion::TapScript,
        // Y-coordinate parity is the one of the TWEAKED PUBKEY!
        output_key_parity: tweaked_keypair.public_parts().1,
        internal_key: UntweakedPublicKey::from(pk),
        merkle_branch: TaprootMerkleBranch::from(path),
    };
    let cb = cb.serialize();
    witness.push(&cb);

    tx.input[0].witness = witness;

    confirm_to_broadcast(&tx);

    Ok(())
}

#[cfg(test)]
mod test {
    use bitcoin::consensus;
    use bitcoin::taproot::ControlBlock;
    use hex_literal::hex;

    #[test]
    fn decode() {
        let cb = hex!("c1d0a26de792c74854e23e1a17945e6dbab6129537cf1ebf69caf38d796b59badd90de350ea8c68793e5ca61801f2532c1d30aa605274326ed1296eaa9a22e4976");
        let cb = ControlBlock::decode(&cb).unwrap();
        println!("{:?}", cb);
    }
}
