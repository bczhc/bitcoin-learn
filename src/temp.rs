use bitcoin::{Address, KnownHrp, PrivateKey};
use bitcoin_demo::{block_parser_range, random_secret_key, TESTNET4};

fn main() {
    let parser = block_parser_range(.., TESTNET4);
    for (h, block) in parser {
        println!("{:?}", (h, block.block_hash()));
    }
}
