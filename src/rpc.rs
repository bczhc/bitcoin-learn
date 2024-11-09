use bitcoin::{consensus, Block, CompactTarget};
use bitcoin_demo::{bitcoin_new_to_old, bitcoin_old, bitcoin_rpc_testnet4, EncodeHex};
use bitcoincore_rpc::RpcApi;
use hex_literal::hex;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let rpc = bitcoin_rpc_testnet4().unwrap();
    let block: Block = consensus::deserialize(&hex!("00000020f90919d5f374b18748ae28536cd5dcb4335af5428e9e56b7a926240000000000a5ee8f2a75df1b725a5f29d43412b43e69fd7bb0d93625ac5b55ea17c466696b79c42f67ffff001dd053a64a0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff18034fd3004d696e65642062792062637a6863202d2d2d2030ffffffff0100f2052a010000001976a914f594ee0d16b9f74e42b1397959cf88abee3b3f9288ac00000000")).unwrap();
    println!("{:?}", block);
    loop {
        let result = rpc.submit_block(&bitcoin_new_to_old(&block));
        if result.is_ok() {
            println!("Done. Submit result: {:?}", result);
            break;
        }
    }
}
