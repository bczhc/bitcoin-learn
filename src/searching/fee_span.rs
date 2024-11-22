//! Get block fee span.
//!
//! Output (interrupted due to OOM): `output/fee-span.txt`.
//!
//! Notice the printed txid, those are transactions with zero fee.

use bitcoin::params::MAINNET;
use bitcoin_demo::{enable_logging, utxo_parser, UtxoBlockExt};
use num_traits::Zero;

fn main() -> anyhow::Result<()> {
    enable_logging();
    let iter = utxo_parser(MAINNET.network).skip(800000);
    for (height, block) in iter {
        let mut fee_rate_list = Vec::new();
        let regular_tx = block.transactions().skip(1);
        // skip empty blocks (only having the coinbase transaction)
        if block.block.txdata.len() == 1 {
            continue;
        }
        for (tx, txid) in regular_tx {
            let tx_fee = block.tx_fee(tx, txid);
            let vbytes = tx.weight().to_vbytes_ceil();
            let fee_rate = tx_fee.to_sat() as f64 / vbytes as f64;
            fee_rate_list.push(fee_rate);
            if fee_rate.is_zero() {
                println!("{}", tx.compute_txid());
            }
        }

        fee_rate_list.sort_by(|&a, &b| a.partial_cmp(&b).unwrap());

        println!(
            "Fee span of block {}: {:.2} - {:.2} sat/vB",
            height,
            fee_rate_list[0],
            fee_rate_list.last().unwrap()
        )
    }

    Ok(())
}
