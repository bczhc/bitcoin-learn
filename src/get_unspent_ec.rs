#![feature(try_blocks)]

use std::io::{stdin, BufRead};

use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use electrum_client::ElectrumApi;

use bitcoin_demo::{secret_to_pubkey, secret_to_pubkey_uncompressed};

fn main() {
    let lines = stdin().lock().lines();
    let client = electrum_client::Client::new("localhost:50001").unwrap();

    let k1 = Secp256k1::new();
    for x in lines {
        let line = x.unwrap();
        let result: anyhow::Result<()> = try {
            let mut ec = [0_u8; 32];
            hex::decode_to_slice(&line, &mut ec)?;
            let addr1 = Address::p2pkh(&secret_to_pubkey(&k1, &ec), Network::Bitcoin);
            let addr2 = Address::p2wpkh(&secret_to_pubkey(&k1, &ec), Network::Bitcoin).unwrap();
            let addr3 = Address::p2pkh(&secret_to_pubkey_uncompressed(&k1, &ec), Network::Bitcoin);
            let addrs = [&addr1, &addr2, &addr3];

            for address in addrs {
                let script = address.payload.script_pubkey();
                let balance = client.script_get_balance(&script)?;
                let history = client.script_get_history(&script)?;
                println!("{line} {address} {} {}", balance.confirmed, history.len());
            }
        };
        if let Err(e) = result {
            eprintln!("Error: {line} {e}");
        }
    }
}
