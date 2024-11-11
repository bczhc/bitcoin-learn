//! Bitcoin OP_RETURN messages: write to SQLite database.
//!
//! Supports incremental database creation.
//!
//! Chinese messages: `output/op-return-chinese/<network>.txt`

use bitcoin::params::{MAINNET, TESTNET3, TESTNET4};
use bitcoin::{Network, OutPoint, Script};
use bitcoin_demo::{block_parser_range, extract_op_return, han_char, EncodeHex};
use chrono::TimeZone;
use rusqlite::{params, Connection};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    run("./op-return-messages-mainnet.db", MAINNET.network)?;
    run("./op-return-messages-testnet3.db", TESTNET3.network)?;
    run("./op-return-messages-testnet4.db", TESTNET4.network)?;
    Ok(())
}

fn run(db_file: impl AsRef<Path>, network: Network) -> anyhow::Result<()> {
    let mut db = Connection::open(db_file)?;
    db.execute(
        r#"create table if not exists op_return_msg
(
    data            blob    not null,
    hex             text    not null,
    text            text    not null,
    block_timestamp integer not null,
    block_height    integer not null,
    txo_txid        text    not null,
    txo_vout        integer not null
)"#,
        params![],
    )?;
    let height_start = db
        .query_row(
            "select max(block_height) from op_return_msg",
            params![],
            |r| r.get::<_, Option<u32>>(0),
        )?
        .unwrap_or(0);

    let db_transaction = db.transaction()?;
    let mut stmt = db_transaction.prepare(r#"insert into op_return_msg (data, hex, text, block_timestamp, block_height, txo_txid, txo_vout)
    values (?, ?, ?, ?, ?, ?, ?)"#)?;

    // let parser = block_parser_recent(10 * 30 * 24 * 60 / 10 /* 10 months */);
    // let parser = new_parser(Network::Testnet(TestnetVersion::V4));
    let parser = block_parser_range(height_start.., network);
    for (height, block) in parser {
        for tx in block.txdata {
            for (txo_idx, txo) in tx.output.iter().enumerate() {
                let script = &txo.script_pubkey;
                if script.is_op_return() {
                    let Some(data) = extract_op_return(Script::from_bytes(script.as_bytes()))
                    else {
                        continue;
                    };
                    // only accept data that is valid UTF-8
                    let Ok(text) = std::str::from_utf8(data) else {
                        continue;
                    };
                    // only accept printable data
                    if text.chars().any(|x| x.is_ascii_control()) {
                        continue;
                    }
                    // reject text with all asciis but without any space
                    if text.chars().all(|x| x.is_ascii()) && !text.contains(' ') {
                        continue;
                    }
                    let data = trim_null(data);
                    // validate_han(s) && !s.is_empty()
                    // !s.is_empty() && s.contains("bitcoin")
                    //     || s.contains("Bitcoin")
                    //     || s.contains("BITCOIN")
                    //     || s.contains("？")
                    // s.chars().any(han_char) && !s.as_bytes().starts_with(&hex!("146f6d6e69"))
                    let predicate = text.chars().any(han_char) /* contains Han characters*/
                        && data.len() >= 3 * 2 /* more than two Han characters */
                        && !text.starts_with("omni") /* filter out some specific string patterns */;
                    let predicate2 = text.contains("bitcoin")
                        || text.contains("BITCOIN")
                        || text.contains("Bitcoin");
                    if
                    /*predicate || predicate2*/
                    true {
                        // OP_RETURN has all Han characters
                        let block_time = chrono::Local
                            .timestamp_millis_opt(block.header.time as i64 * 1000)
                            .unwrap();
                        let txid_hex = tx.compute_txid().to_string();
                        println!(
                            "Block Time: {:?}, Height: {height}, txo: {}, data: {}",
                            block_time,
                            OutPoint {
                                txid: txid_hex.parse()?,
                                vout: txo_idx as u32,
                            },
                            text.replace("\n", " ")
                        );

                        // check row existence
                        let count = db_transaction.query_row("select count(*) from op_return_msg where txo_txid = ? and txo_vout = ?", params![
                            txid_hex, txo_idx as u32
                        ], |r| r.get::<_, u32>(0))?;
                        if count == 0 {
                            stmt.execute(params![
                                data,
                                data.hex(),
                                text,
                                block.header.time,
                                height,
                                txid_hex,
                                txo_idx as u32,
                            ])?;
                        }
                    }
                }
            }
        }
    }
    drop(stmt);
    db_transaction.commit()?;
    drop(db);
    Ok(())
}

fn trim_null(bytes: &[u8]) -> &[u8] {
    let Some(start) = bytes.iter().position(|&x| x != 0) else {
        return &[];
    };
    let Some(end) = bytes.iter().rposition(|&x| x != 0) else {
        return &[];
    };
    &bytes[start..=end]
}

fn validate_han(s: &str) -> bool {
    s.chars().all(han_char)
}
