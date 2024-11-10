mod spend_p2wpkh;

use bitcoin::script::ScriptExt;
use bitcoin::{Amount, OutPoint, TxOut};
use bitcoin_demo::signing_helper::one_input_sign;
use bitcoin_demo::{
    broadcast_tx, confirm_to_broadcast, default_tx, parse_address, script_hex, TESTNET4,
};

const FEE: Amount = Amount::from_sat(300);

fn main() -> anyhow::Result<()> {
    let wif = "cVCag3xvtzb5KqYehrKwSWtfQbvX7cLifTfqGLDAwZkucMvRSE13";
    let outpoint = OutPoint {
        txid: "f3cb85076bc17986fd4abd7db6c3ef8c9c1c50fbd086c32d1c26ada04c26fc4b".parse()?,
        vout: 1,
    };
    let target = "tb1qsrd8xr452qye29aj0k22zpec3q5shrzms98rj8";

    let mut tx = default_tx();
    tx.input[0].previous_output = outpoint;
    tx.output = vec![TxOut {
        value: Amount::from_sat(401648) - FEE,
        script_pubkey: {
            let x = parse_address(target, TESTNET4)?.script_pubkey();
            assert!(x.is_witness_program());
            x
        },
    }];

    one_input_sign(
        wif,
        &mut tx,
        script_hex!("76a9141b7fcd43cdd8add98977bb8458448c7b04b9717f88ac"),
    )?;

    confirm_to_broadcast(&tx);
    Ok(())
}
