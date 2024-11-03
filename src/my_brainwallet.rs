use std::io;
use std::io::{BufReader, Read};

use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::All;
use bitcoin::{Address, Network, PrivateKey};
use byteorder::ReadBytesExt;
use num_bigint::BigUint;

fn main() {
    let password = "好";
    let (addr, skip) = encode(password, "000");
    println!("{:?}", (addr, skip));
    println!("{:?}", decode(password, skip));
}

fn decode(password: &str, skip: u64) {
    let k1 = Secp256k1::new();
    let mut hasher = blake3::Hasher::new();
    hasher.update(password.as_bytes());
    let mut reader = hasher.finalize_xof();
    io::copy(&mut (&mut reader).take(skip), &mut io::sink()).unwrap();

    let mut hash = [0_u8; 32];
    reader.read_exact(&mut hash).unwrap();
    let uint = BigUint::from_bytes_be(&hash) + BigUint::from(skip);
    let new_ec = uint_to_bytes(uint);
    println!("{}", ec_to_address(&k1, &new_ec));
}

fn encode(password: &str, prefix: &str) -> (String, u64) {
    let prefix = format!("bc1q{prefix}");
    let mut hasher = blake3::Hasher::new();
    hasher.update(password.as_bytes());
    let reader = hasher.finalize_xof();
    let mut reader = BufReader::new(reader);

    let mut skip = 0_u64;
    let mut buf = [0_u8; 32];
    reader.read_exact(&mut buf).unwrap();

    let k1 = Secp256k1::new();
    loop {
        let uint = BigUint::from_bytes_be(&buf) + BigUint::from(skip);
        let new_ec = uint_to_bytes(uint);
        let private_key = PrivateKey::from_slice(&new_ec, Network::Bitcoin).unwrap();
        let public_key = private_key.public_key(&k1);
        let address = Address::p2wpkh(&public_key, Network::Bitcoin).unwrap();
        let address = address.to_string();
        if address.starts_with(&prefix) {
            return (address, skip);
        }

        let b = reader.read_u8().unwrap();
        buf.rotate_left(1);
        buf[31] = b;
        skip += 1;
    }
}

fn ec_to_address(k1: &Secp256k1<All>, ec: &[u8]) -> String {
    let private_key = PrivateKey::from_slice(ec, Network::Bitcoin).unwrap();
    let public_key = private_key.public_key(k1);
    let address = Address::p2wpkh(&public_key, Network::Bitcoin).unwrap();
    address.to_string()
}

fn uint_to_bytes(uint: BigUint) -> [u8; 32] {
    let be_bytes = uint.to_bytes_be();
    let mut bytes = [0_u8; 32];
    // leading padding
    bytes[(32 - be_bytes.len())..].copy_from_slice(&be_bytes);
    bytes
}
