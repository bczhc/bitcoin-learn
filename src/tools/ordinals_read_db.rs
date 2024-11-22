//! Filter (likely) Chinese messages from `search_ordinals.rs`.

use bczhc_lib::char::han_char_range;
use bitcoin_demo::parse_block_time;
use clap::Parser;
use regex::Regex;
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

    run(db_path, File::create("output/ordinals-chinese.csv")?);
    Ok(())
}

fn run(db_path: impl AsRef<Path>, writer: impl Write) {
    let regex = Regex::new(r#"\.[a-zA-Z0-9]+\s*$"#).unwrap();

    struct Row {
        text: String,
        size: usize,
        input: String,
        time: String,
        height: u32,
    }

    let db = Connection::open(db_path).unwrap();
    let mut stmt = db
        .prepare("select * from ordinals where plain_text_data is not null order by block_time")
        .unwrap();
    let rows = stmt
        .query_map(params![], |r| {
            let timestamp: u32 = r.get_unwrap("block_time");
            Ok(Row {
                text: r.get_unwrap("plain_text_data"),
                size: r.get_unwrap("size"),
                input: r.get_unwrap("input"),
                height: r.get_unwrap("block"),
                time: parse_block_time(timestamp).unwrap().to_string(),
            })
        })
        .unwrap();

    let mut csv = csv::Writer::from_writer(writer);
    csv.write_record(["Block Height", "Block Time", "Input", "Text"])
        .unwrap();

    for x in rows {
        let row = x.unwrap();
        let text = &row.text;
        if text.chars().any(|x| han_char_range(x as u32))
            && !text.chars().any(japanese_syllabary)
            // filter out some NFT messages
            && !regex.is_match(text)
            // one character spams
            && text.trim().chars().count() > 1
            && !text.contains(char::REPLACEMENT_CHARACTER)
        {
            csv.write_record(&[
                row.height.to_string(),
                row.time,
                format!("{}", row.input),
                text.into(),
            ])
            .unwrap()
        }
    }
}

fn japanese_syllabary(c: char) -> bool {
    matches!(c as u32, 0x3040..=0x30ff)
}
