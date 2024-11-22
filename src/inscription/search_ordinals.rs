#![feature(decl_macro)]
#![feature(array_windows)]
//! Search transactions made by the Ordinals project
//!
//! - https://github.com/ordinals/ord
//!
//! The input type is Pay-To-Taproot, with tapscript formed like this:
//!
//! ```text
//! OP_PUSHBYTES_32 <public-key> OP_CHECKSIG
//! OP_0
//! OP_IF
//! OP_PUSHBYTES_3 <ord-ascii>
//! OP_PUSHBYTES_1 01
//! OP_PUSHBYTES_xx <mime>
//! OP_0
//! OP_PUSHBYTES_xx/OP_PUSHDATA_xx <data>
//! OP_ENDIF
//! ```
//!
//! The witness of a p2tr input (script-path spend mode) is:
//!
//! ```text
//! <script-input>... <taproot-script> <control-block>
//! ```
//!
//! For Ordinals project, `<script-input>...` is just a signature. The witness length is 3.
//!
//! (Likely) Chinese message output: `output/ordinals-chinese.csv`.
//!
//! What I can only see is, that they put much, and much garbage on the chain. Nothing else basically.

use bitcoin::opcodes::all::*;
use bitcoin::opcodes::*;
use bitcoin::params::MAINNET;
use bitcoin::{Address, Script};
use bitcoin_demo::{
    bitcoin_old, block_parser_range, enable_logging, extract_push_data, TAPROOT_START,
};
use clap::Parser;
use log::info;
use rusqlite::{params, Connection};
use std::io::{Cursor, Read};
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    db: PathBuf,
}

fn main() -> anyhow::Result<()> {
    enable_logging();

    let args = Args::parse();

    let mut db = Connection::open(&args.db)?;
    db.execute(
        "CREATE TABLE ordinals
(
    mime     TEXT    NOT NULL,
    -- only store when mime is 'text/plain'
    plain_text_data     BLOB,
    input    TEXT    NOT NULL PRIMARY KEY,
    -- only present if there's only one output
    out_addr TEXT    NULL,
    size     INTEGER NOT NULL,
    block_time INTEGER NOT NULL,
    block    INTEGER NOT NULL
)",
        params![],
    )?;

    let transaction = db.transaction()?;
    let mut stmt = transaction.prepare("INSERT INTO ordinals VALUES (?, ?, ?, ?, ?, ?, ?)")?;
    let mut entries = 0_usize;

    let mut inscription_total = 0_usize;
    let parser = block_parser_range(TAPROOT_START.., MAINNET.network);
    for (height, block) in parser {
        for tx in block.txdata {
            for (in_idx, txi) in tx.input.iter().enumerate() {
                if !txi.script_sig.is_empty() || txi.witness.is_empty() {
                    continue;
                }

                let witness = &txi.witness;
                if witness.len() != 3 {
                    continue;
                }

                let tapscript = witness.second_to_last().unwrap();
                let tapscript = Script::from_bytes(tapscript);

                let Some(inscription) = resolve_tapscript(tapscript) else {
                    continue;
                };

                inscription_total += inscription.data.len();

                let plain_text = if inscription.mime.contains("text/plain") {
                    let text = String::from_utf8_lossy(inscription.data);
                    Some(text.to_string())
                } else {
                    None
                };

                // skip btc-20-like messages
                if inscription.data.array_windows::<3>().any(|x| x == b"\"p\"") {
                    continue;
                }

                let out_addr = if tx.output.len() == 1 {
                    let addr = bitcoin_old::Address::from_script(
                        &tx.output[0].script_pubkey,
                        &bitcoin_old::params::MAINNET,
                    )
                    .map(|x| x.to_string());
                    addr.ok()
                } else {
                    None
                };

                stmt.execute(params![
                    inscription.mime,
                    plain_text,
                    format!("{}:{}", tx.compute_txid(), in_idx),
                    out_addr,
                    inscription.data.len(),
                    block.header.time,
                    height
                ])?;
                if entries % 1000 == 0 {
                    info!("Entries: {}", entries);
                }
                entries += 1;
            }
        }
    }

    drop(stmt);
    transaction.commit()?;
    drop(db);

    Ok(())
}

#[derive(Debug)]
struct Ordinals<'a> {
    mime: &'a str,
    data: &'a [u8],
}

fn resolve_tapscript(script: &Script) -> Option<Ordinals> {
    let s = script.as_bytes();

    macro ne_return($value1:expr, $value2:expr) {
        if $value1 != $value2 {
            return None;
        }
    }

    let mut b = s.bytes().map(Result::unwrap);
    ne_return!(b.next()?, OP_PUSHBYTES_32.to_u8());
    let mut b = b.skip(32);
    ne_return!(b.next()?, OP_CHECKSIG.to_u8());
    ne_return!(b.next()?, OP_0.to_u8());
    ne_return!(b.next()?, OP_IF.to_u8());
    let &last = s.last()?;
    ne_return!(last, OP_ENDIF.to_u8());

    let if_body_start = 1 + 32 + 1 + 1 + 1;
    if s.len() <= if_body_start + 1 {
        return None;
    }

    let body = &s[if_body_start..(s.len() - 1)];

    let mut start = 0_usize;

    let (data, len) = extract_push_data(body)?;
    ne_return!(data, b"ord");
    start += len;

    body.get(start)?;
    let (data, len) = extract_push_data(&body[start..])?;
    ne_return!(data[0], 0x01);
    start += len;

    body.get(start)?;
    let (mime, len) = extract_push_data(&body[start..])?;
    start += len;

    ne_return!(*body.get(start)?, OP_0.to_u8());
    start += 1;
    let (inscription, len) = extract_push_data(&body[start..])?;

    let mime = std::str::from_utf8(mime).ok()?;

    Some(Ordinals {
        mime,
        data: inscription,
    })
}

#[cfg(test)]
mod test {
    use crate::resolve_tapscript;
    use bitcoin_demo::script_hex;

    #[test]
    fn test() {
        let script = script_hex!("202e821cbb64ff7b57064b5f1ab08049476064fe61397c0728185323962c8a847fac0063036f7264010118746578742f706c61696e3b636861727365743d7574662d38000568656c6c6f68 ");

        let resolved = resolve_tapscript(script).unwrap();
        assert_eq!(resolved.mime, "text/plain;charset=utf-8");
        let text = std::str::from_utf8(resolved.data).unwrap();
        assert_eq!(text, "hello");
    }
}
