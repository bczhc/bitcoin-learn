//! Search nonstandard and abnormal unspent Bitcoin UTXO in Blockchain
//!
//! Output: `non_standard_txo.txt`

use bitcoin::script::ScriptExt;
use bitcoin_block_parser::blocks::Options;
use bitcoin_block_parser::{BlockParser, DefaultParser, HeaderParser};
use bitcoin_demo::bitcoin_old;
use bitcoin_old::opcodes::all::OP_PUSHNUM_1;
use bitcoin_old::opcodes::OP_0;
use bitcoin_old::{Amount, Script, ScriptBuf, Txid};
use chrono::TimeZone;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fmt::{Debug, Formatter};

struct TrackedTxo {
    txid: Txid,
    index: usize,
    script: ScriptBuf,
    value: Amount,
}

impl Debug for TrackedTxo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.txid, self.value.to_sat(), self.script)
    }
}

fn main() -> anyhow::Result<()> {
    let mut tracked_txo_list = Vec::new();

    let options = Options::default().order_output();
    let blk_dir = "/mnt/nvme/bitcoin/bitcoind/blocks/blocks";
    let mut headers = HeaderParser::parse(blk_dir)?;
    headers.reverse();
    let parser = DefaultParser.parse_with_opts(&headers, options);

    let mut height = headers.len() - 1;
    for x in parser {
        let block = x?;
        eprintln!(
            "height={} txs={} time={:?}",
            height,
            block.txdata.len(),
            chrono::Local
                .timestamp_millis_opt(block.header.time as i64 * 1000)
                .unwrap()
                .to_rfc3339()
        );
        for tx in block.txdata.iter().skip(1)
        /* skip the block award transaction */
        {
            for (index, txo) in tx.output.iter().enumerate() {
                let script = txo.script_pubkey.clone();
                if txo.value.to_sat() != 0 && filter_script(&script) {
                    let txid = tx.compute_txid();
                    let tracked_txo = TrackedTxo {
                        txid,
                        index,
                        script,
                        value: txo.value,
                    };
                    println!("{:?}", tracked_txo);
                    tracked_txo_list.push(tracked_txo);
                }
            }
        }
        height -= 1;
    }

    // filter out TXOs that have been spent
    let mut txid_set = HashSet::new();
    tracked_txo_list.iter().for_each(|x| {
        txid_set.insert(x.txid);
    });
    let options = Options::default().order_output();
    let parser = DefaultParser.parse_with_opts(&headers, options);
    for (i, x) in parser.iter().enumerate() {
        let block = x?;
        eprintln!("Progress: {}/{}", i, headers.len());
        for tx in block.txdata {
            for txi in tx.input {
                let prev_output = &txi.previous_output;
                if !txid_set.contains(&prev_output.txid) {
                    continue;
                }
                let Some(index) = tracked_txo_list.iter().position(|x| {
                    x.txid == prev_output.txid && x.index == prev_output.vout as usize
                }) else {
                    continue;
                };
                eprintln!("{} has been spent", tracked_txo_list[index].txid);
                tracked_txo_list.remove(index);
            }
        }
    }

    println!("UNSPENT TRANSACTIONS");
    for x in tracked_txo_list {
        println!("{:?}", x);
    }

    Ok(())
}

fn filter_script(s: &Script) -> bool {
    !(s.is_p2pkh()
        || s.is_p2pk()
        || s.is_p2sh()
        || s.is_p2wpkh()
        || s.is_op_return()
        || s.first_opcode() == Some(OP_PUSHNUM_1)
        || s.first_opcode() == Some(OP_0)
        || s.is_multisig())
}
