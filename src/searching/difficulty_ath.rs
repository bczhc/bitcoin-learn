//! Bitcoin mining difficulty ATH
//!
//! Currently, this one:
//!
//! - <https://www.blockchain.com/explorer/blocks/btc/000000000000000000028ba1de91c9603b474a5e2ef6eea461afe847bd963626>

use bitcoin_block_parser::HeaderParser;
use std::cmp::Ordering;

fn main() {
    let blk_dir = "/mnt/nvme/bitcoin/bitcoind/blocks/blocks";
    let headers = HeaderParser::parse(blk_dir).unwrap();

    let max = headers.iter().max_by(|a, b| {
        a.inner
            .difficulty_float()
            .partial_cmp(&b.inner.difficulty_float())
            .unwrap_or(Ordering::Equal)
    });
    println!("{:?}", max);
}
