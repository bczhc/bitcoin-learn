#![feature(try_blocks)]

use std::env::args;
use std::io::{stdin, BufRead, BufReader};
use std::sync::mpsc::sync_channel;
use std::thread::spawn;

use bitcoin::key::Secp256k1;
use bitcoin::{Address, Network};
use electrum_client::ElectrumApi;
use num_bigint::BigUint;
use rayon::prelude::*;

use bitcoin_demo::{hash_iter, secret_to_pubkey, secret_to_pubkey_uncompressed, sha256_iter};

fn main() {
    let args = args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        println!(
            "Usage: 1|2|3 <iter_count>\n\
        1: unspent; 2: tx count; 3: both"
        );
        return;
    };

    let selection = args[0].parse::<u8>().unwrap();
    let iter_num = args[1].parse::<u64>().unwrap();

    let k1 = Secp256k1::new();

    let (sender, receiver) = sync_channel(10240);

    struct ChannelMsg {
        line: String,
        key: [u8; 32],
    }

    spawn(move || {
        let lines = BufReader::new(stdin()).lines();
        lines.par_bridge().for_each_with(sender, |s, x| {
            let line = x;
            if let Ok(line) = line {
                // let key = sha256_iter(line.as_bytes(), iter_num);
                let key = hash_iter::<blake3::Hasher>(line.as_bytes(), iter_num);

                // let uint = BigUint::from_bytes_be(&key);
                // let vec = (uint + BigUint::from(1_u8)).to_bytes_be();
                // let mut key = [0_u8; 32];
                // key[(32 - vec.len())..].copy_from_slice(&vec);

                // s.send(ChannelMsg { line, key }).unwrap();
                s.send(ChannelMsg { line, key }).unwrap();
            }
        });
    });

    let client = electrum_client::Client::new("localhost:50001").unwrap();
    receiver.into_iter().for_each(|x| {
        let line = x.line;
        let key = x.key;

        let key_hex = hex::encode(key);
        let addr1 = Address::p2pkh(&secret_to_pubkey(&k1, &key), Network::Bitcoin);
        let addr2 = Address::p2wpkh(&secret_to_pubkey(&k1, &key), Network::Bitcoin).unwrap();
        let addr3 = Address::p2pkh(&secret_to_pubkey_uncompressed(&k1, &key), Network::Bitcoin);
        let addrs = [&addr1, &addr2, &addr3];

        for addr in addrs {
            let result: anyhow::Result<()> = try {
                let script = addr.payload.script_pubkey();
                match selection {
                    1 => {
                        let result = client.script_get_balance(&script)?;
                        println!("{} {} {} {}", line, key_hex, addr, result.confirmed);
                    }
                    2 => {
                        let history = client.script_get_history(&script)?;
                        println!("{} {} {} {}", line, key_hex, addr, history.len());
                    }
                    3 => {
                        let result = client.script_get_balance(&script)?;
                        let history = client.script_get_history(&script)?;
                        println!(
                            "{} {} {} Unspent: {}, tx count {}",
                            line,
                            key_hex,
                            addr,
                            result.confirmed,
                            history.len()
                        );
                    }
                    _ => {}
                };
            };
            if let Err(e) = result {
                eprintln!("Error: {}", e);
            }
        }
    });
}
