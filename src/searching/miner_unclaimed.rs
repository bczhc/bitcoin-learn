//! When a block gets mined, the miner can claim **up to** a bitcoin value:
//! block reward + all transaction fees.
//!
//! By this, some miners may take less than that value. Thus, bitcoins are **destroyed** by them.
//!
//! This runs ~40 minutes and takes ~40 GiB of memory.
//!
//! Output: `miner-unclaimed.csv`

use bitcoin::Network;
use bitcoin_block_parser::blocks::Options;
use bitcoin_block_parser::utxos::{FilterParser, UtxoParser};
use bitcoin_block_parser::BlockParser;
use bitcoin_demo::{
    bitcoin_block_reward, bitcoin_old, parse_headers, set_up_logging, IntervalLogger,
};
use log::{debug, info, LevelFilter};
use rayon::prelude::*;
use std::fs::File;

fn main() -> anyhow::Result<()> {
    set_up_logging(LevelFilter::Info, None)?;
    let mut csv = csv::Writer::from_writer(File::create("../output/output.txt")?);
    csv.write_record([
        "Block Height",
        "Block ID",
        "Tx Fee",
        "Block Reward",
        "Miner Claimed",
        "Unclaimed",
    ])?;

    let mut interval_logger = IntervalLogger::new();

    let filter_parser = FilterParser::new();
    filter_parser.write("filter.bin")?;
    let utxo_parser = UtxoParser::new("filter.bin")?;

    let headers = parse_headers(Network::Bitcoin);
    let iter = utxo_parser
        .parse_with_opts(&headers, Options::default().order_output())
        .into_iter()
        .map(Result::unwrap);
    let iter = (0..(headers.len() as u32)).zip(iter);
    for (h, block) in iter {
        let mut txs = block.transactions();
        let coinbase_tx = txs.next().expect("No coinbase transaction").0;
        assert!(coinbase_tx.is_coinbase());

        let mut tx_fee = bitcoin_old::Amount::ZERO;
        for (tx, txid) in txs {
            // Here I used to call Bitcoin-core RPC `getrawtransaction` to fetch the total input
            // amount as the old implementation.
            // Indeed, it's unusable due to the very low performance.
            // Now, thanks to `UtxoParser` from `bitcoin_block_parser` crate!
            let inputs = block.input_amount(txid).iter().zip(tx.input.iter());
            let input_sum: bitcoin_old::Amount = inputs.map(|x| *x.0).sum();
            let output_sum: bitcoin_old::Amount = tx.output.iter().map(|x| x.value).sum();
            tx_fee += input_sum - output_sum;
        }

        let miner_claimed: bitcoin_old::Amount = coinbase_tx.output.iter().map(|x| x.value).sum();
        let block_reward = bitcoin_old::Amount::from_sat(bitcoin_block_reward(h));
        // In the coinbase transaction, miners are legal to claim less than the block reward.
        // So this indicates bitcoins the miners manually threw away/gave up to claim.
        let lost_bitcoin = block_reward + tx_fee - miner_claimed;

        interval_logger.log(|| info!("Block: #{h}"));
        debug!(
            "Block: #{}, fee: {}, coinbase_claimed: {}, erased_bitcoin: {}",
            h, tx_fee, miner_claimed, lost_bitcoin
        );

        if lost_bitcoin != bitcoin_old::Amount::ZERO {
            csv.write_record(&[
                format!("{h}"),
                format!("{}", block.block.block_hash()),
                format!("{}", tx_fee.to_sat()),
                format!("{}", block_reward.to_sat()),
                format!("{}", miner_claimed.to_sat()),
                format!("{}", lost_bitcoin.to_sat()),
            ])?;
        }
    }
    Ok(())
}
