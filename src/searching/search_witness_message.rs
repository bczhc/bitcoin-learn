//! Try to extract some printable human-readable data hidden in witness data
//!
//! It's quite a bit difficult to tell if a byte stream contains
//! meaningful text produced by human.
//!
//! However, I still found some notable entries: `output/witness-text.txt`. Their witness-scripts
//! are formed like this:
//!
//! ```
//! OP_PUSHBYTES/OP_PUSHDATAN <data> OP_DROP OP_PUSHNUM_1
//! ```

#![feature(let_chains)]
#![feature(iter_map_windows)]

use bitcoin::params::MAINNET;
use bitcoin::script::ScriptExt;
use bitcoin::Script;
use bitcoin_demo::{block_parser_range, enable_logging};
use hex_literal::hex;

fn main() -> anyhow::Result<()> {
    enable_logging();

    let parser = block_parser_range(481824.., MAINNET.network);
    for (h, block) in parser {
        for tx in block.txdata {
            for txi in &tx.input {
                /*for w_item in txi.witness.iter() {
                    // let lossy_str = String::from_utf8_lossy(w_item);
                    // let mut han_consecutive = false;
                    // let _ = lossy_str.chars().map_windows::<_, _, 5>(|x| {
                    //     if x.iter().copied().all(han_char) {
                    //         han_consecutive = true;
                    //     }
                    // });
                    // if !han_consecutive {
                    //     continue;
                    // }

                    println!(
                        "{} {:?} {}",
                        parse_timestamp(block.header.time),
                        tx.compute_txid(),
                        ""
                    );
                }*/

                let Some(last) = txi.witness.last() else {
                    continue;
                };

                if last.len() > 2 && &last[(last.len() - 1 - 1)..] == &hex!("7551") {
                    let script = Script::from_bytes(last);
                    if script.to_asm_string().ends_with("OP_DROP OP_PUSHNUM_1") {
                        println!("{} {}", tx.compute_txid(), String::from_utf8_lossy(last));
                    }
                }
            }
        }
    }
    Ok(())
}
