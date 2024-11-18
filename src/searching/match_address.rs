//! Search specific TXO addresses.
//!
//! Notable forum posts:
//!
//! - https://bitcointalk.org/index.php?topic=90982.0
//! - (and all its reference URLs)
//!
//! Output: `special-non-segwit-addresses.txt`.

use bitcoin::params::MAINNET;
use bitcoin::script::ScriptExt;
use bitcoin::{Address, Script};
use bitcoin_demo::block_parser_range;
use std::collections::HashSet;
use std::fmt;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let mut set = HashSet::new();

    let parser = block_parser_range(.., MAINNET.network);
    let mut address_buf = String::with_capacity(30);
    for (_h, block) in parser {
        for tx in block.txdata {
            for txo in &tx.output {
                let script = Script::from_bytes(txo.script_pubkey.as_bytes());
                let Ok(address) = Address::from_script(&script, &MAINNET) else {
                    continue;
                };
                // skip segwit (bc1...) addresses
                if script.is_witness_program() {
                    continue;
                }
                use fmt::Write;
                address_buf.clear();
                write!(&mut address_buf, "{}", address)?;

                let mut print = |index: u32| {
                    if !set.contains(&address_buf) {
                        println!("{} {} {}", index, address_buf, tx.compute_txid());
                        set.insert(address_buf.clone());
                    }
                };

                match () {
                    _ if address_buf.starts_with("1Bitcoin") => print(0),
                    _ if address_buf.chars().all(|x| x.is_ascii_lowercase()) => print(1),
                    _ if address_buf.chars().all(|x| x.is_ascii_uppercase()) => print(2),
                    _ if address_buf
                        .chars()
                        .all(|x| x.is_ascii_digit() || x.is_ascii_lowercase()) =>
                    {
                        print(3)
                    }
                    _ if address_buf
                        .chars()
                        .all(|x| x.is_ascii_digit() || x.is_ascii_uppercase()) =>
                    {
                        print(4)
                    }
                    _ if address_buf.chars().all(|x| x.is_ascii_digit()) => print(5),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
