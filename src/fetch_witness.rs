//! Fetch an image from witness data
//!
//! https://mempool.space/testnet4/tx/bbb38216aad6346f8deac68a7fcfc58c26e6069d32b10cf3d2207f6d82f76203?mode=details

use bitcoin::Txid;
use bitcoin_demo::{bitcoin_new_to_old, bitcoin_rpc_testnet4, hash160};
use bitcoincore_rpc::RpcApi;
use std::fs::File;
use std::io::Write;

fn main() -> anyhow::Result<()> {
    let txid: Txid = "bbb38216aad6346f8deac68a7fcfc58c26e6069d32b10cf3d2207f6d82f76203".parse()?;
    let rpc = bitcoin_rpc_testnet4()?;
    // `txindex=1` required
    let tx = rpc.get_raw_transaction(&bitcoin_new_to_old(&txid), None)?;
    let witness = &tx.input[0].witness;

    assert!(witness.len() > 2);

    let name = std::str::from_utf8(&witness[0])?;
    println!("{}", name);

    let data_iter = witness.iter().skip(1).take(witness.len() - 2);
    let mut data: Vec<u8> = Vec::new();
    for chunk in data_iter {
        data.write_all(chunk)?;
    }

    File::create("/tmp/img.avif")?.write_all(&data)?;

    Ok(())
}
