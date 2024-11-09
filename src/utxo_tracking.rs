use bitcoin::Network;
use bitcoin_block_parser::blocks::Options;
use bitcoin_block_parser::utxos::{FilterParser, UtxoParser};
use bitcoin_block_parser::BlockParser;
use bitcoin_demo::{bitcoin_old, parse_headers};

fn main() -> anyhow::Result<()> {
    let filter_parser = FilterParser::new();
    filter_parser.write("filter.bin")?;
    let utxo_parser = UtxoParser::new("filter.bin")?;

    let headers = parse_headers(Network::Bitcoin);
    let iter = utxo_parser
        .parse_with_opts(&headers, Options::default().order_output())
        .into_iter()
        .map(Result::unwrap);
    for block in iter {
        for (tx, txid) in block.transactions() {
            let inputs = block.input_amount(txid).iter().zip(tx.input.iter());
            let total: bitcoin_old::Amount = inputs.map(|x| *x.0).sum();
            println!("{}", total);
        }
    }
    Ok(())
}
