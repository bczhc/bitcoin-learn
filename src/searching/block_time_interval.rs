//! Find block time intervals less than 20 minutes.
//!
//! The testnet allows miners to mine a block with the minimum difficulty, but if
//! the block time interval is larger than 2 * 10 minutes.
//!
//! If not waiting for 20 minutes, you must mine a block with a higher difficulty it requires. This
//! program finds them.

use bitcoin_demo::{new_parser, TESTNET4};

fn main() -> anyhow::Result<()> {
    let parser = new_parser(TESTNET4);
    let mut iter = parser.into_iter().peekable();
    let first = iter.peek().unwrap();
    assert_eq!(first.0, 0);
    let mut prev_time = first.1.header.time;
    for (h, block) in iter {
        let time = block.header.time;
        if time - prev_time <= /* 20 min */ 20 * 60 {
            println!("Block #{h} time interval: {} min", (time - prev_time) / 60);
        }
        prev_time = time;
    }
    Ok(())
}
