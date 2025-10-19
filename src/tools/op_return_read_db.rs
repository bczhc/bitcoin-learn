//! Filter (likely) Chinese messages from `search_op_return.rs`.

use bczhc_lib::char::han_char_range;
use chrono::TimeZone;
use clap::Parser;
use rusqlite::{params, Connection};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Args {
    db_path: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let db_path = args.db_path;

    let path1 = db_path.join("mainnet.db");
    if path1.exists() {
        run(
            path1,
            File::create("output/op-return-chinese/mainnet.csv")?,
        );
    }

    let path2 = db_path.join(Path::new("testnet3.db"));
    if path2.exists() {
        run(
            db_path.join("testnet3.db"),
            File::create("output/op-return-chinese/testnet3.csv")?,
        );
    }

    let path3 = db_path.join(Path::new("testnet4.db"));
    if path3.exists() {
        run(
            db_path.join("testnet4.db"),
            File::create("output/op-return-chinese/testnet4.csv")?,
        );
    }
    Ok(())
}

fn run(db_path: impl AsRef<Path>, writer: impl Write) {
    struct Row {
        height: u32,
        time: String,
        text: String,
        txid: String,
        vout: u32,
    }

    let db = Connection::open(db_path).unwrap();
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

    let mut csv = csv::Writer::from_writer(writer);
    csv.write_record(["Block Height", "Block Time", "Tx Output", "Text"])
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
    matches!(c as u32, 0x3040..=0x30ff)
}
