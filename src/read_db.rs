use bczhc_lib::char::han_char_range;
use chrono::TimeZone;
use rusqlite::{params, Connection};

fn main() {
    struct Row {
        time: String,
        text: String,
        txid: String,
        vout: u32,
    }

    let db = Connection::open("./op-return-messages-testnet4.db").unwrap();
    let mut stmt = db
        .prepare("select * from op_return_msg order by block_timestamp")
        .unwrap();
    let rows = stmt
        .query_map(params![], |r| {
            let timestamp: u64 = r.get_unwrap("block_timestamp");
            Ok(Row {
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
    for x in rows {
        let row = x.unwrap();
        let text = &row.text;
        if text.chars().any(|x| han_char_range(x as u32)) && !text.chars().any(japanese_syllabary) {
            println!("{} {}:{} {}", row.time, row.txid, row.vout, text);
        }
    }
}

fn japanese_syllabary(c: char) -> bool {
    matches!(c as u32, 0x3040..=0x309f | 0x30A0..=0x30ff)
}
