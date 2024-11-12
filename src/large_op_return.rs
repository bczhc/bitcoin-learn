//! Search op-return data larger than [`THRESHOLD`] bytes.
//!
//! Output: `large-op-return.csv`.

use bitcoin::params::MAINNET;
use bitcoin::script::ScriptExt;
use bitcoin::Script;
use bitcoin_demo::{block_parser_range, extract_op_return, parse_timestamp, EncodeHex};
use std::fs::File;

const THRESHOLD: usize = 200;

fn main() -> anyhow::Result<()> {
    // let writer = stdout();
    // https://github.com/sumopool/bitcoin-block-parser/issues/5
    // let writer = writer.lock();
    let mut csv = csv::Writer::from_writer(File::create("../output/output.csv").unwrap());
    csv.write_record(&["Block Time", "Block Height", "Tx", "Data", "Lossy Text"])?;

    let parser = block_parser_range(.., MAINNET.network);
    for (h, block) in parser {
        for (idx, tx) in block.txdata.iter().enumerate() {
            for txo in &tx.output {
                let script = Script::from_bytes(txo.script_pubkey.as_bytes());
                if script.is_op_return() {
                    let Some(data) = extract_op_return(&script) else {
                        continue;
                    };

                    if data.len() > THRESHOLD {
                        csv.write_record(&[
                            parse_timestamp(block.header.time).to_string(),
                            h.to_string(),
                            format!("{}:{}", tx.compute_txid(), idx),
                            data.hex(),
                            String::from_utf8_lossy(data).to_string(),
                        ])?;
                    }
                }
            }
        }
    }
    Ok(())
}
