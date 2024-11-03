use bitcoin_block_parser::blocks::Options;
use bitcoin_block_parser::HeaderParser;
use std::cmp::Ordering;

fn main() {
    let options = Options::default().order_output();
    let blk_dir = "/mnt/nvme/bitcoin/bitcoind/blocks/blocks";
    let mut headers = HeaderParser::parse(blk_dir).unwrap();

    let max = headers.iter().max_by(|a, b| {
        a.inner
            .difficulty_float()
            .partial_cmp(&b.inner.difficulty_float())
            .unwrap_or(Ordering::Equal)
    });
    println!("{:?}", max);
}
