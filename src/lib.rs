#![allow(incomplete_features, const_evaluatable_unchecked)]
#![feature(generic_const_exprs)]

use std::env::args;
use std::io::{stdin, stdout, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::absolute::encode;
use bitcoin::key::Secp256k1;
use bitcoin::script::PushBytes;
use bitcoin::secp256k1::{All, Message, SecretKey};
use bitcoin::{Address, Amount, Network, PrivateKey, PublicKey, Transaction};
use bitcoin_block_parser::blocks::Options;
use bitcoin_block_parser::{BlockParser, DefaultParser, HeaderParser};
use bitcoincore_rpc::{Auth, RpcApi};
use digest::generic_array::GenericArray;
use digest::typenum::Unsigned;
use digest::{Digest, FixedOutput, OutputSizeUser};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

pub fn random_secret_key() -> SecretKey {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SecretKey::from_slice(&bytes).unwrap()
}

pub fn secret_to_pubkey(k1: &Secp256k1<All>, bytes: &[u8]) -> PublicKey {
    let secret = SecretKey::from_slice(bytes).unwrap();
    let pk = PrivateKey::new(secret, Network::Bitcoin);
    pk.public_key(k1)
}

pub fn secret_to_pubkey_uncompressed(k1: &Secp256k1<All>, bytes: &[u8]) -> PublicKey {
    let secret = SecretKey::from_slice(bytes).unwrap();
    let pk = PrivateKey::new_uncompressed(secret, Network::Bitcoin);
    pk.public_key(k1)
}

#[derive(Debug, Clone)]
pub struct EcDerived {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub p2pkh: Address,
    pub p2wpkh: Address,
}

pub fn ec_derive(ec: &[u8; 32]) -> EcDerived {
    // let s = Secp256k1::new();
    // let private_key = PrivateKey::from_slice(ec, Network::Bitcoin).unwrap();
    // let public_key = private_key.public_key(&s);
    // let p2wpkh = Address::p2wpkh(&public_key, Network::Bitcoin).unwrap();
    // EcDerived {
    //     private_key,
    //     public_key,
    //     p2wpkh,
    //     p2pkh: Address::p2pkh(&public_key, Network::Bitcoin),
    // }
    todo!()
}

#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    hash_iter::<Sha256>(data, 1)
}

#[inline]
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    hash_iter::<Sha256>(data, 2)
}

#[inline]
pub fn sha256_iter(data: &[u8], iter_num: u64) -> [u8; 32] {
    hash_iter::<Sha256>(data, iter_num)
}

#[inline]
pub fn blake3(data: &[u8]) -> [u8; 32] {
    hash_iter::<blake3::Hasher>(data, 1)
}

pub fn hash_iter<H>(data: &[u8], iter_num: u64) -> [u8; H::OutputSize::USIZE]
where
    H: Digest + FixedOutput + OutputSizeUser,
    [(); H::OutputSize::USIZE]:,
    GenericArray<u8, H::OutputSize>: From<[u8; H::OutputSize::USIZE]>,
    GenericArray<u8, H::OutputSize>: Into<[u8; H::OutputSize::USIZE]>,
{
    // initial hashing
    let mut hash = GenericArray::<u8, H::OutputSize>::from([0_u8; H::OutputSize::USIZE]);
    let mut hasher = H::new();
    Digest::update(&mut hasher, data);
    FixedOutput::finalize_into(hasher, &mut hash);

    // last iterations
    for _ in 1..iter_num {
        let mut hasher = H::new();
        Digest::update(&mut hasher, &*hash);
        FixedOutput::finalize_into(hasher, &mut hash);
    }

    hash.into()
}

#[macro_export]
macro_rules! hash {
    ($t:ty, $data:expr, $iter:expr) => {
        hash_iter::<$t>($data, $iter)
    };
    ($t:ty, $data:expr) => {
        hash!($t, $data, 1)
    };
}

pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn cli_args() -> Vec<String> {
    args().skip(1).collect()
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    hash!(ripemd::Ripemd160, &sha256(data), 1)
}

pub trait EncodeHex {
    fn hex(&self) -> String;
}

impl<A> EncodeHex for A
where
    A: AsRef<[u8]>,
{
    fn hex(&self) -> String {
        hex::encode(self)
    }
}

pub fn bitcoin_rpc() -> bitcoincore_rpc::Result<bitcoincore_rpc::Client> {
    bitcoincore_rpc::Client::new(
        "localhost:8332",
        Auth::UserPass(String::from("bitcoinrpc"), String::from("123")),
    )
}

pub fn bitcoin_rpc_testnet4() -> bitcoincore_rpc::Result<bitcoincore_rpc::Client> {
    bitcoincore_rpc::Client::new(
        "localhost:48332",
        Auth::UserPass(String::from("bitcoinrpc"), String::from("123")),
    )
}

pub fn new_parser() -> impl IntoIterator<Item = (usize, bitcoincore_rpc::bitcoin::Block)> {
    let options = Options::default().order_output();
    let blk_dir = "/mnt/nvme/bitcoin/bitcoind/blocks/blocks";
    let mut headers = HeaderParser::parse(blk_dir).unwrap();
    // headers.reverse();
    let parser = DefaultParser.parse_with_opts(&headers, options);

    let mut height = headers.len() - 1;
    (0..=height)
        .rev()
        .zip(parser.into_iter().map(Result::unwrap))
}

pub trait ScriptsBuilderExt
where
    Self: Sized,
{
    fn push_slice_try_from(self, slice: &[u8]) -> anyhow::Result<Self>;
}

impl ScriptsBuilderExt for bitcoin::script::Builder {
    fn push_slice_try_from(self, slice: &[u8]) -> anyhow::Result<Self> {
        Ok(self.push_slice(<&PushBytes>::try_from(slice)?))
    }
}

pub fn ecdsa_sign(
    private_key: &SecretKey,
    signing_hash: [u8; 32],
) -> bitcoin::secp256k1::ecdsa::Signature {
    Secp256k1::default().sign_ecdsa(&Message::from_digest(signing_hash), private_key)
}

pub fn confirm_to_broadcast_raw(raw_tx: &[u8]) {
    print!("Broadcast? [Enter]");
    stdout().flush().unwrap();
    stdin().read_line(&mut String::new()).unwrap();

    let rpc = bitcoin_rpc_testnet4().unwrap();
    let result = rpc.send_raw_transaction(raw_tx);
    println!("{:?}", result);
}

pub fn confirm_to_broadcast(tx: &Transaction) {
    let serialized = encode::serialize(tx);
    println!("Transaction: {}", serialized.hex());
    confirm_to_broadcast_raw(&serialized);
}

#[macro_export]
macro_rules! script_hex {
    ($x:literal) => {
        bitcoin::script::Script::from_bytes(&hex_literal::hex!($x))
    };
}

pub trait BitcoinAmountExt {
    const DUST_MIN: Amount = Amount::from_sat(999);
}

impl BitcoinAmountExt for Amount {}
