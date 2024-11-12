//! Make a transaction to store an AVIF image on the chain.
//!
//! Sadly, multi-op-return is rejected for propagation. Only miners can do this.
//!
//! This sample will fail to broadcast.

use bitcoin::{consensus, Amount, Network, OutPoint, TestnetVersion, TxOut};
use bitcoin_demo::signing_helper::one_input_sign;
use bitcoin_demo::{
    confirm_to_broadcast, default_tx, ideal_checked_op_return, parse_address, script_hex,
    ESTIMATED_SCRIPT_SIG_SIZE, OP_RETURN_IDEAL_MAX,
};

const FEE_RATE: f64 = 1.4;

fn main() -> anyhow::Result<()> {
    let data = include_bytes!("../res/a.avif");
    let mut tx = default_tx();
    let total_value = Amount::from_sat(453700);
    let network = Network::Testnet(TestnetVersion::V4);
    let wif = "cQ7WLKEA4s3DEEuv1yQ7saQZ8dD9vH47Ej8xecVfsTAiMRFEp31z";

    tx.input[0].previous_output = OutPoint {
        txid: "ac59228a274c628cb9142fb50f39df911ccecd3f71192dbb25730731b0846565".parse()?,
        vout: 1,
    };
    tx.output = Vec::new();

    // Outputs order in a transaction is retained.
    for chunk in data.chunks(OP_RETURN_IDEAL_MAX) {
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ideal_checked_op_return(chunk),
        });
    }
    // change
    tx.output.push(TxOut {
        value: Amount::ZERO, /* placeholder, because the fee is undetermined */
        script_pubkey: parse_address("mwmuZHTs9NWbiFbKKGBR29TjTKXoJq6AKZ", network)?
            .script_pubkey(),
    });

    // estimate the transaction size and fee
    let estimated_tx_size = consensus::serialize(&tx).len() + ESTIMATED_SCRIPT_SIG_SIZE;
    let fee = Amount::from_sat((estimated_tx_size as f64 * FEE_RATE) as u64);
    println!("Fee: {fee}");
    tx.output.last_mut().unwrap().value = total_value - fee;

    one_input_sign(
        wif,
        &mut tx,
        script_hex!("76a914b255f786aa697139fdcd7bd82eabfb0b74ee11ef88ac"),
    )?;

    confirm_to_broadcast(&tx);

    Ok(())
}
