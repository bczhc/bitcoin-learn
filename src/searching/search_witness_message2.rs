#![feature(try_blocks)]

//! Some other strategies trying to search meaningful text in witness data.
//!
//! See the filter functions: [`filter1`], [`filter2`], [`filter3`].
//!
//! Output: `witness-text2`.

use bitcoin::opcodes::all::*;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::params::MAINNET;
use bitcoin_demo::{bitcoin_old, block_parser_range, enable_logging, han_char, SEGWIT_START};
use std::fmt::Display;
use std::num::NonZeroUsize;
use utf8_iter::Utf8Chars;

fn main() {
    enable_logging();
    let parser = block_parser_range(SEGWIT_START.., MAINNET.network);
    // let rpc = bitcoin_rpc();

    for (_, block) in parser {
        for tx in block.txdata {
            for (i, txi) in tx.input.iter().enumerate() {
                // not a desired witness txi
                let witness = &txi.witness;
                if !txi.script_sig.is_empty() || witness.is_empty() || witness.len() < 3 {
                    continue;
                }

                filter1(witness, |s| {
                    output(1, String::from_utf8_lossy(s), tx.compute_txid(), i);
                });
                filter2(witness, |s| {
                    output(2, String::from_utf8_lossy(s), tx.compute_txid(), i);
                });
                filter3(witness, |s| {
                    output(3, String::from_utf8_lossy(s), tx.compute_txid(), i);
                });
            }
        }
    }
}

fn output(
    filter_n: impl Display,
    message: impl Display,
    txid: impl Display,
    input_idx: impl Display,
) {
    println!("filter{}: {} {}:{}", filter_n, message, txid, input_idx);
}

/// Search witness message where the \[witness|witness script\] is formed like:
///
/// (pattern 1)
///
/// ```text
/// [message, secret, script | OP_PUSHBYTESxx secret OP_EQUALVERIFY OP_DROP OP_TRUE]
/// ```
///
/// Or (pattern 2)
///
/// ```text
/// [message, secret, script | OP_SHA256/OP_HASH160/OP_HASH256/... OP_PUSHBYTESxx secret-hash OP_EQUALVERIFY OP_DROP OP_TRUE]
/// ```
///
/// To my surprise, the output has only one entry! Only the transaction I've made yesterday!
/// 只此一家，哈哈。
/// (as of 2024.11.22 11:13 UTC+8)
///
/// In the transaction: f04d93782a25d88f303631cd763a24dbfd08dc4ca5a0792d2f2075dec6ca1a4d.
fn filter1(witness: &bitcoin_old::Witness, print: impl FnOnce(&[u8])) {
    let Some(ws) = witness.last() else {
        return;
    };
    if filter1_ws(ws) {
        print(&witness[0]);
    }
}

fn filter1_ws(ws: &[u8]) -> bool {
    let hash_opcodes = [
        OP_SHA256.to_u8(),
        OP_HASH160.to_u8(),
        OP_HASH256.to_u8(),
        OP_RIPEMD160.to_u8(),
        OP_SHA1.to_u8(),
    ];
    let suffix = [OP_EQUALVERIFY.to_u8(), OP_DROP.to_u8(), OP_TRUE.to_u8()];

    // pattern 2
    let result1: Option<_> = try {
        let p1 = hash_opcodes.contains(ws.get(0)?);
        let size = opcode_check_pushbytes(*ws.get(1)?)?;
        NonZeroUsize::new(size)?;

        let p2 = [
            *ws.get(2 + size)?,
            *ws.get(2 + size + 1)?,
            *ws.get(2 + size + 2)?,
        ] == suffix
            && p1;
        p2
    };
    if result1 == Some(true) {
        return true;
    }

    // pattern 1
    let result2: Option<_> = try {
        let size = opcode_check_pushbytes(*ws.get(0)?)?;
        NonZeroUsize::new(size)?;
        [
            *ws.get(1 + size)?,
            *ws.get(1 + size + 1)?,
            *ws.get(1 + size + 2)?,
        ] == suffix
    };
    if result2 == Some(true) {
        return true;
    }

    false
}

/// Any witness field containing **only** han characters/punctuations.
///
/// As of 2024.11.22 12:08 UTC+8, only found transactions I made.
fn filter2(witness: &bitcoin_old::Witness, print: impl Fn(&[u8])) {
    for w in witness.iter().filter(|x| !x.is_empty()) {
        let mut chars = Utf8Chars::new(w);
        if chars.all(han_char) {
            print(w);
        }
    }
}

/// Any witness field containing English sentence.
fn filter3(witness: &bitcoin_old::Witness, print: impl Fn(&[u8])) {
    for w in witness.iter().filter(|x| !x.is_empty()) {
        if Utf8Chars::new(w).all(|x| x.is_ascii() && !x.is_ascii_control() && x != '{' && x != '}')
            && w.iter().any(|&x| x == b' ')
            && w.len() > 10
        {
            print(w);
        }
    }
}

fn opcode_check_pushbytes(c: u8) -> Option<usize> {
    if (OP_PUSHBYTES_0.to_u8()..=OP_PUSHBYTES_75.to_u8()).contains(&c) {
        return Some((c - OP_PUSHBYTES_0.to_u8()) as usize);
    }
    None
}

#[cfg(test)]
mod test {
    use crate::filter1_ws;
    use hex_literal::hex;
    use utf8_iter::Utf8Chars;

    #[test]
    fn test() {
        assert!(filter1_ws(&hex!("09e594a4e586ace585bd887551")));
    }

    #[test]
    fn utf8_iter() {
        let iter = Utf8Chars::new(&hex!("e4bda0e4bde5a5bd"));
        assert_eq!(
            iter.collect::<Vec<_>>(),
            ['你', char::REPLACEMENT_CHARACTER, '好']
        )
    }
}
