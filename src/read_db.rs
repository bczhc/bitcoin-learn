use bczhc_lib::char::han_char_range;
use chrono::TimeZone;
use rusqlite::{params, Connection};
use std::io::stdout;

fn main() {
    struct Row {
        height: u32,
        time: String,
        text: String,
        txid: String,
        vout: u32,
    }

    let db = Connection::open(
        "/home/bczhc/Documents/bitcoin-op-return-msg/op-return-messages-mainnet.db",
    )
    .unwrap();
    let mut stmt = db
        .prepare("select * from op_return_msg order by block_timestamp")
        .unwrap();
    let rows = stmt
        .query_map(params![], |r| {
            let timestamp: u64 = r.get_unwrap("block_timestamp");
            Ok(Row {
                height: r.get_unwrap("block_height"),
                text: r.get_unwrap("text"),
                vout: r.get_unwrap("txo_vout"),
                txid: r.get_unwrap("txo_txid"),
                time: chrono::Local
                    .timestamp_millis_opt(timestamp as i64 * 1000)
                    .unwrap()
                    .to_string(),
            })
        })
        .unwrap();

    let mut csv = csv::Writer::from_writer(stdout());
    csv.write_record(&["Block Height", "Block Time", "Tx Output", "Text"])
        .unwrap();

    for x in rows {
        let row = x.unwrap();
        let text = &row.text;
        if text.chars().any(|x| han_char_range(x as u32)) && !text.chars().any(japanese_syllabary) {
            csv.write_record(&[
                row.height.to_string(),
                row.time,
                format!("{}:{}", row.txid, row.vout),
                text.into(),
            ])
            .unwrap()
        }
    }
}

fn japanese_syllabary(c: char) -> bool {
    matches!(c as u32, 0x3040..=0x309f | 0x30A0..=0x30ff)
}
