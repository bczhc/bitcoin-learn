use std::env::args;

use bitcoin::key::Secp256k1;
use bitcoin::{Address, Network, PrivateKey};
use num_bigint::BigUint;

use bitcoin_demo::hash_iter;

fn main() {
    let s = Secp256k1::new();

    let ec = hash_iter::<blake3::Hasher>("a".as_bytes(), 1_0000_0000);
    let ec = ec_add_1(&ec);
    let private_key = PrivateKey::from_slice(&ec, Network::Bitcoin).unwrap();
    assert!(private_key.compressed);
    let address = Address::p2wpkh(&private_key.public_key(&s), Network::Bitcoin).unwrap();
    println!("{}", address);
}

fn ec_add_1(ec: &[u8]) -> [u8; 32] {
    let uint = BigUint::from_bytes_be(&ec);
    let vec = (uint + BigUint::from(1_u8)).to_bytes_be();
    vec.try_into().unwrap()
}
