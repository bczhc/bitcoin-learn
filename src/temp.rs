use bitcoin::{Address, KnownHrp, PrivateKey};
use bitcoin_demo::{random_secret_key, TESTNET4};

fn main() {
    let ec = random_secret_key();
    let prk = PrivateKey::new(ec, TESTNET4);
    let public_key = prk.public_key(&Default::default());
    println!("{}", public_key.pubkey_hash());
    println!("{}", public_key.wpubkey_hash().unwrap());
    let p2wpkh = Address::p2wpkh(public_key.try_into().unwrap(), KnownHrp::Testnets);
    println!("{}", prk.to_wif());
    println!("{}", p2wpkh);
}
