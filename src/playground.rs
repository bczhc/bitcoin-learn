use bitcoin::params::MAINNET;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin_demo::{bitcoin_old, block_parser_range, enable_logging, prompt_wait_new_line, sha256};
use fxhash::FxHashSet;
use num_bigint::BigUint;
use num_traits::{Euclid, One, ToPrimitive, Zero};
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::hint;
use std::sync::mpsc::{channel, sync_channel, Receiver};
use std::thread::spawn;

const CHARSET: &str = include_str!("../a.txt");

static CHARS: Lazy<Vec<char>> = Lazy::new(|| CHARSET.chars().collect());

fn main() {
    enable_logging();
    let mut utxo_set = FxHashSet::default();

    let (sender, rx) = sync_channel::<bitcoin_old::Transaction>(65536);
    spawn(move || {
        let parser = block_parser_range(.., MAINNET.network);

        for (_h, block) in parser {
            for tx in block.txdata {
                sender.send(tx).unwrap();
            }
        }
    });

    let tx_iter = rx.into_iter();
    let iter = with_txid_par_ordered(tx_iter, 65536);
    for (txid, tx) in iter {
        for txi in &tx.input {
            let out_point = txi.previous_output;
            let result = utxo_set.remove(&(out_point.txid, out_point.vout));
            if !tx.is_coinbase() {
                assert!(result);
            }
        }
        for (idx, _) in tx.output.iter().enumerate() {
            utxo_set.insert((txid, idx as u32));
        }
    }

    println!("Done");
    println!("{}", utxo_set.len());
    prompt_wait_new_line();
    return;
    let secp: Secp256k1<_> = Default::default();
    let keypair = Keypair::new(&secp, &mut OsRng);
    let message = "hello";
    let signature =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sha256(message.as_bytes())), &keypair);
    let signature = signature.serialize();
    let mut int = BigUint::from_bytes_be(&signature);
    let radix = BigUint::from(1000_u32);
    let one = BigUint::one();
    let mut radix_digits = Vec::new();
    loop {
        let (div, rem) = int.div_rem_euclid(&radix);
        int = div;
        radix_digits.push(rem.to_usize().unwrap());
        if int.is_zero() {
            break;
        }
    }
    radix_digits.reverse();

    let sig_string = radix_digits
        .iter()
        .map(|&x| (&*CHARS)[x])
        .collect::<String>();
    println!("{}", sig_string);
}

/// Compute TxIDs in batch.
fn with_txid_par_ordered(
    mut input: impl Iterator<Item = bitcoin_old::Transaction> + Send + 'static,
    batch_n: usize,
) -> Receiver<(bitcoin_old::Txid, bitcoin_old::Transaction)> {
    let (sender, rx) = channel();
    spawn(move || loop {
        let enumerate = input.by_ref().take(batch_n).enumerate();
        let mut batch = enumerate
            .par_bridge()
            .map(|(i, x)| (i, (x.compute_txid(), x)))
            .collect::<Vec<_>>();
        batch.sort_by_key(|x| x.0);
        if batch.is_empty() {
            break;
        }
        for (_i, x) in batch {
            sender.send(x).unwrap();
        }
    });

    rx
}
