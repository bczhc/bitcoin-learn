//! Spend p2tr outputs.
//!
//! Transaction:
//!
//! <https://mempool.space/testnet4/tx/873e9c7a6a768e8a4a94f0dc1520e20f0f9d3e3fc4bc447186de9ab8e469d330>
//!
//! The first input is spent by key-path, and the second one is spent by script-path.

use bitcoin::key::{TapTweak, UntweakedKeypair, UntweakedPublicKey};
use bitcoin::opcodes::all::{OP_EQUAL, OP_PUSHNUM_2};
use bitcoin::script::ScriptBufExt;
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafNode, LeafVersion, TaprootMerkleBranch};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, KnownHrp, OutPoint, ScriptBuf, TapNodeHash, TapSighashType, TxOut, Witness,
};
use bitcoin_demo::secp256k1::PublicKeyExt;
use bitcoin_demo::{
    confirm_to_broadcast, default_tx, default_txin, ideal_checked_op_return, script_hex_owned,
    sha256, EncodeHex,
};
use hex_literal::hex;

fn main() -> anyhow::Result<()> {
    use bitcoin::secp256k1 as secp;

    let tapscript1 = ScriptBuf::builder().push_opcode(OP_EQUAL).into_script();
    let tapscript2 = ScriptBuf::builder()
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_EQUAL)
        .into_script();
    let leaf1 = LeafNode::new_script(tapscript1.clone(), LeafVersion::TapScript);
    let leaf2 = LeafNode::new_script(tapscript2, LeafVersion::TapScript);
    // Later in the script-path demo, we will only spend using tapscript1. The merkle path
    // is its sibling node: tapscript2.
    let path = [leaf2.node_hash()];

    let script_merkle_root = TapNodeHash::from_node_hashes(leaf1.into(), leaf2.into());

    let secp: secp::Secp256k1<_> = Default::default();
    let secret = sha256("Chikipi".as_bytes());
    println!("Secret: {}", secret.hex());
    let secret = SecretKey::from_slice(&secret)?;

    let pk = secp::PublicKey::from_secret_key(&secp, &secret);
    let address = Address::p2tr(
        &secp,
        pk.into(),
        Some(script_merkle_root),
        KnownHrp::Testnets,
    );
    println!("Address: {}", address);
    let witness_program = address.witness_program().unwrap();
    let taproot = witness_program.program().as_bytes();
    println!("Taproot: {}", taproot.hex());

    // ===================== SPEND =====================
    let mut tx = default_tx();
    // P2TR requires transaction version two.
    tx.version = Version::TWO;
    tx.input = vec![
        default_txin(OutPoint {
            txid: "81ac09f208135efaf099252c3e035c0d7066a59ffc199ac4972ae249b93a58fc".parse()?,
            vout: 1,
        }),
        default_txin(OutPoint {
            txid: "81ac09f208135efaf099252c3e035c0d7066a59ffc199ac4972ae249b93a58fc".parse()?,
            vout: 2,
        }),
    ];
    tx.output = vec![
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ideal_checked_op_return("漏洞百出。".as_bytes()),
        },
        // change
        TxOut {
            value: Amount::from_sat(3500),
            script_pubkey: script_hex_owned!("001480da730eb450099517b27d94a1073888290b8c5b"),
        },
    ];

    // Now we begin to sign the first input (key-path spend).

    let mut cache = SighashCache::new(tx.clone());
    let prevouts = Prevouts::One(
        0,
        TxOut {
            value: Amount::from_sat(2000),
            script_pubkey: script_hex_owned!(
                "5120e2ec6dcf201a9527e98e822897c2c422689f3ebfa21339cc1289791c180136fb"
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
    let tweaked_keypair = keypair.tap_tweak(&secp, Some(script_merkle_root));

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

    // And now, handle the second input (script-path spend).

    // Pick two identical arbitrary data to unlock the script: OP_EQUAL.
    let inputs = [hex!("43617474697661"), hex!("43617474697661")];
    // witness format: <script-input>... <tapscript> <control-block>
    let mut witness = Witness::new();
    for input in inputs {
        witness.push(input);
    }
    witness.push(tapscript1.as_bytes());
    let cb = ControlBlock {
        leaf_version: LeafVersion::TapScript,
        // Y-coordinate parity is the one of the TWEAKED PUBKEY! Not the original pubkey.
        // The doc also states this.
        output_key_parity: tweaked_keypair.public_parts().1,
        internal_key: UntweakedPublicKey::from(pk),
        merkle_branch: TaprootMerkleBranch::from(path),
    };
    let cb = cb.serialize();
    witness.push(&cb);

    tx.input[1].witness = witness;

    confirm_to_broadcast(&tx);

    Ok(())
}

#[cfg(test)]
mod test {
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::sha256t;
    use bitcoin::taproot::{ControlBlock, LeafVersion};
    use bitcoin::{Script, TapLeafHash, TapLeafTag, TapTweakTag};
    use bitcoin_demo::script_hex;
    use hex_literal::hex;

    #[test]
    fn decode() {
        let cb = hex!("c1d0a26de792c74854e23e1a17945e6dbab6129537cf1ebf69caf38d796b59badd90de350ea8c68793e5ca61801f2532c1d30aa605274326ed1296eaa9a22e4976");
        let cb = ControlBlock::decode(&cb).unwrap();
        println!("{:?}", cb);
    }

    #[test]
    fn issue() {
        fn from_script(script: &Script, ver: LeafVersion) -> TapLeafHash {
            let mut eng = sha256t::Hash::<TapLeafTag>::engine();
            ver.to_consensus()
                .consensus_encode(&mut eng)
                .expect("engines don't error");
            script
                .consensus_encode(&mut eng)
                .expect("engines don't error");
            let inner = sha256t::Hash::<TapTweakTag>::from_engine(eng);
            TapLeafHash::from_byte_array(inner.to_byte_array())
        }

        fn from_script2(script: &Script, ver: LeafVersion) -> TapLeafHash {
            let mut eng = sha256t::Hash::<TapLeafTag>::engine();
            ver.to_consensus()
                .consensus_encode(&mut eng)
                .expect("engines don't error");
            script
                .consensus_encode(&mut eng)
                .expect("engines don't error");
            // --------------------------------------- CHANGED HERE ----
            let inner = sha256t::Hash::<TapLeafTag>::from_engine(eng);
            TapLeafHash::from_byte_array(inner.to_byte_array())
        }

        let hash1 = from_script(script_hex!("5187"), LeafVersion::TapScript);
        let hash2 = from_script2(script_hex!("5187"), LeafVersion::TapScript);
        assert_eq!(hash1, hash2);
    }
}
