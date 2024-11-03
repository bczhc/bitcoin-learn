#![feature(try_blocks)]

use bitcoin::Address;
use electrum_client::ElectrumApi;
use std::io::{stdin, BufRead};
use std::str::FromStr;

fn main() {
    let lines = stdin().lock().lines();
    let client = electrum_client::Client::new("localhost:50001").unwrap();

    for x in lines {
        let line = x.unwrap();
        let result: anyhow::Result<()> = try {
            let address = Address::from_str(&line)?;
            let script = address.payload.script_pubkey();
            let balance = client.script_get_balance(&script)?;
            println!("{line} {:?}", (balance.confirmed, balance.unconfirmed));
        };
        if let Err(e) = result {
            eprintln!("Error: {line} {e}");
        }
    }
}
