//! Code trying to mine a block on testnet4
//!
//! However I tried, but my block won't be added on the `mempool.space` explorer...
//!
//! Testnet allows us to mine with the minimal difficulty (bit: 0x1d00ffff) if
//! the block time interval is more than 20 minutes.
//! https://github.com/bitcoin/bitcoin/blob/0903ce8dbc25d3823b03d52f6e6bff74d19e801e/src/pow.cpp#L27-L28
//!
//! This gets a bit tricky. If not setting the block time 20 minutes newer, we will get a required
//! difficulty (bits) for something like 420589345. That's a quite high difficulty, and it's hard
//! to meet the mining target.
//!
//! After setting the correct block timestamp, you can mine lots of blocks. However, a 20 minutes
//! still should be waited, or you'll get a `time-too-new` error when submitting the mined block.
//!
//! Lots of nodes may have mined lots of blocks, just waiting for the correct moment
//! to broadcast them. Thus, it turns to a time/network competition but not the computation
//! power competition. I got no luck to make my block shown on the explorer websites - so, how
//! can I ensure the block *I mined* can be the longest chain in the network?

use bitcoin::absolute::LockTime;
use bitcoin::block::Header;
use bitcoin::merkle_tree::MerkleNode;
use bitcoin::{
    block, consensus, transaction, Amount, Block, CompactTarget, ScriptBuf, Transaction, TxIn,
    TxMerkleNode, TxOut,
};
use bitcoin_demo::{
    bitcoin_new_to_old, bitcoin_old, bitcoin_old_to_new, bitcoin_rpc_testnet4, mining,
    parse_address, EncodeHex, TESTNET4,
};
use bitcoincore_rpc::RpcApi;
use byteorder::{WriteBytesExt, LE};
use chrono::{DateTime, Local};
use std::process::exit;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    let mut i = 0_u64;
    loop {
        let rpc = bitcoin_rpc_testnet4()?;
        println!("Difficulty from RPC: {}", rpc.get_difficulty()?);
        let last_block_num = /*rpc.get_block_count()?*/ 54094;
        // let last_block_hash = rpc.get_block_hash(last_block_num)?;
        // println!("Last block hash: {}", last_block_hash);
        let last_block_hash = bitcoin_old::BlockHash::from_str(
            "00000000002426a9b7569e8e42f55a33b4dcd56c5328ae4887b174f3d51909f9",
        )
        .unwrap();
        // let last_block = rpc.get_block(&last_block_hash)?;
        // let last_block_time = last_block.header.time;
        let last_block_time = "2024-11-10T04:02:16+08:00"
            .parse::<DateTime<Local>>()?
            .timestamp() as u32;

        let coinbase_text = format!("Mined by bczhc --- {i}");
        println!("Coinbase message: {coinbase_text}");
        let coinbase_tx = Transaction {
            version: transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![{
                let mut txi = TxIn::EMPTY_COINBASE;
                let mut msg_vec: Vec<u8> = vec![0x03];
                msg_vec.write_u24::<LE>(last_block_num as u32 + 1).unwrap();
                for &u8 in coinbase_text.as_bytes() {
                    msg_vec.push(u8);
                }
                txi.script_sig = ScriptBuf::from_bytes(msg_vec);
                txi
            }],
            output: vec![TxOut {
                value: Amount::from_int_btc(50),
                script_pubkey: parse_address("n3uUFt8okKcV8YUS3h8e7RELmmQh3ecdst", TESTNET4)?
                    .script_pubkey(),
            }],
        };

        let txs: Vec<Transaction> = vec![coinbase_tx];
        let merkle_root =
            TxMerkleNode::calculate_root(txs.iter().map(|x| x.compute_txid())).unwrap();
        let block_time = last_block_time + 20 * 60 + 1;
        let block = Block {
            header: Header {
                version: block::Version::from_consensus(0x20000000),
                time: block_time,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
                merkle_root,
                prev_blockhash: bitcoin_old_to_new(&last_block_hash),
            },
            txdata: txs,
        };
        println!("Bip34 block height: {:?}", block.bip34_block_height());

        println!("{:?}", block);
        mining::mine(
            block.clone(),
            Some(move |n| {
                let mut block = block.clone();
                block.header.nonce = n;
                println!("{}", block.block_hash());
                loop {
                    let result = rpc.submit_block(&bitcoin_new_to_old(&block));
                    println!("Submit block: {}", consensus::serialize(&block).hex());
                    format!("{:?}", result);
                    if result.is_ok() {
                        break;
                    }
                    sleep(Duration::from_secs(1));
                }
                exit(0);
            }),
        );
        i += 1;
    }
}
