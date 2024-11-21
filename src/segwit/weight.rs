//! Compute weight of transactions.
//!
//! References:
//!
//! - https://learnmeabitcoin.com/technical/transaction/#structure
//! - https://learnmeabitcoin.com/technical/transaction/size/#weight

use bitcoin::params::MAINNET;
use bitcoin_demo::{bitcoin_old, block_parser_range};
use bitcoin_varint::VarInt;

fn main() {
    let parser = block_parser_range(870200.., MAINNET.network);
    let block = parser.into_iter().next().unwrap().1;
    println!("Height: {}", block.bip34_block_height().unwrap());

    for tx in block.txdata {
        println!("{}", tx.compute_txid());
        println!("{:?}", (tx.total_size() - tx.base_size(), tx.base_size()));
        let weight = compute_weight(&tx);
        assert_eq!(weight as u64, tx.weight().to_wu());
    }
}

fn compute_weight(tx: &bitcoin_old::Transaction) -> usize {
    let tx_serialized = bitcoin_old::consensus::serialize(&tx);

    // tx structure: <version> [<marker>] [<flag>] <input-length>, ...
    // For non-segwit nodes, they will view this byte as "input length". The protocol enforces
    // input to be non-empty, in this case, if the byte is zero, the transaction is a segwit
    // transaction.
    let marker = tx_serialized[4];
    if marker != 0 {
        // legacy transaction. The weight is just its total size multiplied by 4.
        return tx_serialized.len() * 4;
    }

    let witness_raw_data_sum = tx
        .input
        .iter()
        .map(|x| x.witness.iter().map(|x| x.len()).sum::<usize>())
        .sum::<usize>();
    let witness_meta_len = tx
        .input
        .iter()
        .map(|x| {
            // witness field count
            VarInt::get_size(x.witness.len() as _).unwrap() as usize
                // witness data size for each field
                + x.witness.iter().map(|x| VarInt::get_size(x.len() as _).unwrap() as usize).sum::<usize>()
        })
        .sum::<usize>();
    // And don't forget tx marker and flag. These are also included for the segwit upgrade. And so,
    let witness_length = witness_raw_data_sum + witness_meta_len + 2;

    // and the tx size with witness stripped is apparently:
    let base_size = tx_serialized.len() - witness_length;

    println!("{:?}", (witness_length, base_size));

    base_size * 4 + witness_length
}
