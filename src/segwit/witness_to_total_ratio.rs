//! Stub

use bitcoin::block::Header;
use bitcoin::params::MAINNET;
use bitcoin_demo::{bitcoin_old, block_parser_range};
use bitcoin_varint::VarInt;

fn main() {
    let parser = block_parser_range(870200.., MAINNET.network);
    for (_, block) in parser {
        let total_size = block.total_size();
        let witness_size = total_size - block.base_size();
        let ratio = witness_size as f64 / total_size as f64;
        println!("{}", ratio * 100.0);
    }
}

trait BlockExt {
    fn base_size(&self) -> usize;
}

impl BlockExt for bitcoin_old::Block {
    /// They don't make it `pub`. Don't know why.
    fn base_size(&self) -> usize {
        let mut size = Header::SIZE;

        // size += compact_size::encoded_size(self.txdata.len());
        size += VarInt::get_size(self.txdata.len() as _).unwrap() as usize;
        size += self.txdata.iter().map(|tx| tx.base_size()).sum::<usize>();

        size
    }
}
