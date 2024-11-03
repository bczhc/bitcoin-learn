#![feature(bigint_helper_methods)]

use bitcoin::{consensus, Block, Target};
use bitcoin_demo::EncodeHex;
use hex_literal::hex;
use std::process::exit;
use std::thread::spawn;

fn main() -> anyhow::Result<()> {
    let block = hex!("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
    let mut block: Block = consensus::deserialize(&block).expect("Deserialization failed");
    let bits = block.header.bits;
    let target = Target::from(bits);
    let target = target.to_be_bytes();
    println!("Target: {}", target.hex());

    fn uint256_ge(n1: &[u8; 32], n2: &[u8; 32]) -> bool {
        let mut c = *n2;
        for x in c.iter_mut() {
            *x = !*x;
        }
        // add one
        let mut carry = true;
        for x in c.iter_mut().rev() {
            (*x, carry) = x.carrying_add(0, carry);
        }
        let mut n1 = *n1;
        carry = false;
        for (i, x) in n1.iter_mut().enumerate().rev() {
            (*x, carry) = x.carrying_add(c[i], carry);
        }
        carry
    }

    #[inline(always)]
    fn check_target(block: &Block, target: &[u8; 32]) -> bool {
        let hash = block.header.block_hash();
        let mut hash = *hash.as_byte_array();
        hash.reverse();
        uint256_ge(&target, &hash)
    }

    let part = u32::MAX / 16;
    let mut join_handlers = Vec::new();
    for i in 0..16_u32 {
        let mut block = block.clone();
        let range = (part * i)..(part * (i + 1));
        let target = target.clone();
        let handler = spawn(move || {
            for nonce in range {
                block.header.nonce = nonce;
                if check_target(&block, &target) {
                    println!("Mined! {}, nonce {}", block.header.block_hash(), nonce);
                    exit(0);
                }
            }
        });
        join_handlers.push(handler);
    }

    join_handlers.into_iter().for_each(|x| x.join().unwrap());

    Ok(())
}
