#![feature(slice_split_once)]

use bitcoin::{Network, ScriptBuf};
use bitcoin_demo::new_parser;
use std::collections::HashSet;

fn main() -> anyhow::Result<()> {
    let mut set = HashSet::new();

    let parser = new_parser(Network::Bitcoin).into_iter().take(10_000);
    for x in parser {
        for tx in x.1.txdata {
            for (index, txo) in tx.output.iter().enumerate() {
                if txo.script_pubkey.is_p2sh() {
                    set.insert((tx.compute_txid(), index));
                }
            }
        }
    }

    println!("{}", set.len());

    let parser = new_parser(Network::Bitcoin).into_iter().take(10_000);
    for x in parser {
        for tx in x.1.txdata {
            for txi in &tx.input {
                if set.contains(&(txi.previous_output.txid, txi.previous_output.vout as usize))
                    && txi.witness.is_empty()
                {
                    let txid = tx.compute_txid();
                    // this is spending a p2sh utxo
                    let asm = txi.script_sig.to_asm_string();
                    if let Some((_, hex_str)) = asm.as_bytes().rsplit_once(|&x| x == b' ') {
                        let hex_str = std::str::from_utf8(hex_str).expect("Invalid utf-8");
                        let redeem = ScriptBuf::from_bytes(hex::decode(hex_str)?);
                        println!("{} {}", txid, redeem);
                    }
                }
            }
        }
    }

    Ok(())
}
