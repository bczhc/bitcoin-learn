//! Find large transactions (>3MB).
//!
//! Output: `large-tx.txt`.
//!
//! Some interesting transactions:
//!
//! - 0301e0480b374b32851a9462db29dc19fe830a7f7d7a88b81612b9d42099c0aei0
//!
//!    This large 4MB transaction has zero fee. The miner (pool) MUST have collaborated with this.
//!
//!    Source: https://www.reddit.com/r/Bitcoin/comments/10r6t1l/the_first_4_mb_block_in_bitcoin_history_mined_by

use bitcoin::params::MAINNET;
use bitcoin_demo::{block_parser_range, enable_logging};
use bytesize::{ByteSize, MB};

fn main() {
    enable_logging();
    let parser = block_parser_range(.., MAINNET.network);
    for (height, block) in parser {
        for tx in block.txdata {
            let size = tx.total_size();
            if size > 3 * MB as usize {
                println!(
                    "{} {} {}",
                    height,
                    tx.compute_txid(),
                    ByteSize(size as _).to_string_as(true)
                );
            }
        }
    }
}
