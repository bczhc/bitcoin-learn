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
