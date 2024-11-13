//! This finds inputs with small scriptSig.
//!
//! From this, some interesting/suspicious addresses can be found, such as:
//!
//! - 3Ppq6koGseiMyMiKVVKwBhqtHPRzVrCrob
//! - 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
//! - 1woukheyeacxfpxtpkxjqxureevdkbywj
//!
//! Output: `small-script-sig.csv`

#![feature(slice_split_once)]

use bitcoin::params::MAINNET;
use bitcoin_demo::{bitcoin_old, block_parser_range};
use std::collections::HashSet;
use std::fs::File;

fn main() -> anyhow::Result<()> {
    let range = ..;

    // used to ensure the same scriptSig can only be outputted once
    let mut script_set: HashSet<bitcoin_old::ScriptBuf> = HashSet::new();

    let mut csv = csv::Writer::from_writer(File::create("output.csv")?);
    csv.write_record(["Input (txid:index)", "ScriptSig ASM"])?;

    let parser = block_parser_range(range, MAINNET.network);
    for x in parser {
        for tx in x.1.txdata.iter().skip(1)
        /* skip the coinbase */
        {
            for (index, txi) in tx.input.iter().enumerate() {
                if
                /*set.contains(&(txi.previous_output.txid, txi.previous_output.vout as usize))
                && txi.witness.is_empty()*/
                true {
                    // this is spending a p2sh utxo
                    let script_sig = &txi.script_sig;
                    let length = script_sig.as_bytes().len();
                    if length < 20 && length > 1 && txi.witness.is_empty() {
                        let txid = tx.compute_txid();
                        let asm = script_sig.to_asm_string();
                        if !script_set.contains(script_sig) {
                            script_set.insert(script_sig.clone());
                            csv.write_record([format!("{}:{}", txid, index), asm])?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
