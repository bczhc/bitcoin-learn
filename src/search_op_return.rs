use bitcoin::{Network, OutPoint, Script, TestnetVersion};
use bitcoin_demo::{extract_op_return, han_char, new_parser, EncodeHex};
use chrono::TimeZone;
use rusqlite::{params, Connection};

fn main() {
    let mut db = Connection::open("./op-return-messages.db").unwrap();
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
    )
    .unwrap();
    let db_transaction = db.transaction().unwrap();
    let mut stmt = db_transaction.prepare(r#"insert into op_return_msg (data, hex, text, block_timestamp, block_height, txo_txid, txo_vout)
    values (?, ?, ?, ?, ?, ?, ?)"#).unwrap();

    // let parser = block_parser_recent(10 * 30 * 24 * 60 / 10 /* 10 months */);
    let parser = new_parser(Network::Testnet(TestnetVersion::V4));
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
                                txid: txid_hex.parse().unwrap(),
                                vout: txo_idx as u32,
                            },
                            text.replace("\n", " ")
                        );
                        stmt.execute(params![
                            data,
                            data.hex(),
                            text,
                            block.header.time,
                            height,
                            txid_hex,
                            txo_idx as u32,
                        ])
                        .unwrap();
                    }
                }
            }
        }
    }
    drop(stmt);
    db_transaction.commit().unwrap();
    drop(db);
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
