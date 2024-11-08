#![allow(incomplete_features, const_evaluatable_unchecked)]
#![feature(generic_const_exprs)]

use bczhc_lib::char::han_char_range;
use bitcoin::absolute::encode;
use bitcoin::key::Secp256k1;
use bitcoin::opcodes::all::{OP_PUSHBYTES_75, OP_PUSHDATA1};
use bitcoin::script::{PushBytes, ScriptExt};
use bitcoin::secp256k1::{All, Message, SecretKey};
use bitcoin::{Address, Amount, Network, PrivateKey, PublicKey, Script, Transaction};
use bitcoin_block_parser::blocks::Options;
use bitcoin_block_parser::headers::ParsedHeader;
use bitcoin_block_parser::{BlockParser, DefaultParser, HeaderParser};
use bitcoincore_rpc::bitcoin::opcodes::all::OP_PUSHBYTES_1;
use bitcoincore_rpc::{Auth, RpcApi};
use digest::generic_array::GenericArray;
use digest::typenum::Unsigned;
use digest::{Digest, FixedOutput, OutputSizeUser};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::env::args;
use std::io::{stdin, stdout, Write};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let blk_dir = "/mnt/nvme/bitcoin/bitcoind/blocks/testnet4/blocks";
    let mut headers = HeaderParser::parse(blk_dir).unwrap();
    println!("{}", headers.len());
    // headers.reverse();
    let parser = DefaultParser.parse_with_opts(&headers, options);

    let mut height = headers.len() - 1;
    (0..=height)
        // .rev()
        .zip(parser.into_iter().map(Result::unwrap))
}

pub fn new_parser_rev() -> impl IntoIterator<Item = (usize, bitcoincore_rpc::bitcoin::Block)> {
    let options = Options::default().order_output();
    let blk_dir = "/mnt/nvme/bitcoin/bitcoind/blocks/blocks";
    let mut headers = HeaderParser::parse(blk_dir).unwrap();
    headers.reverse();
    let parser = DefaultParser.parse_with_opts(&headers, options);

    let mut height = headers.len() - 1;
    (0..=height)
        .rev()
        .zip(parser.into_iter().map(Result::unwrap))
}

const BITCOIN_CORE_BLK_DIR: &str = "/mnt/nvme/bitcoin/bitcoind/blocks/blocks";

pub fn parse_headers() -> Vec<ParsedHeader> {
    HeaderParser::parse(BITCOIN_CORE_BLK_DIR).unwrap()
}

pub fn block_parser(
    headers: &[ParsedHeader],
) -> impl IntoIterator<Item = (usize, bitcoincore_rpc::bitcoin::Block)> {
    let options = Options::default().order_output();
    let parser = DefaultParser.parse_with_opts(headers, options);

    let mut height = headers.len() - 1;
    (0..=height).zip(parser.into_iter().map(Result::unwrap))
}

/// Only takes the recent `block_count` blocks.
pub fn block_parser_recent(
    block_count: usize,
) -> impl IntoIterator<Item = (usize, bitcoincore_rpc::bitcoin::Block)> {
    let headers = parse_headers();
    let start = headers.len() - block_count;
    let selected_headers = &headers[start..];
    let selected_height_start = headers.len() - block_count;

    let options = Options::default().order_output();
    let parser = DefaultParser.parse_with_opts(selected_headers, options);
    (selected_height_start..(selected_height_start + block_count))
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

pub fn extract_op_return(script: &Script) -> Option<&[u8]> {
    if !script.is_op_return() {
        return None;
    }

    let bytes = script.as_bytes();

    // merely OP_RETURN
    if bytes.len() == 1 {
        return None;
    }

    // OP_RETURN <OP_PUSHBYTES_1..=OP_PUSHBYTES_75> <data>
    if (OP_PUSHBYTES_1.to_u8()..=OP_PUSHBYTES_75.to_u8()).contains(&bytes[1]) {
        let pushed_len = (bytes[1] - OP_PUSHBYTES_1.to_u8() + 1) as usize;
        if bytes.len() - 2 < pushed_len {
            return None;
        }
        let data = &bytes[2..(2 + pushed_len)];
        return Some(data);
    }

    // OP_RETURN <OP_PUSHDATA1> <length> <data>
    if bytes[1] == OP_PUSHDATA1.to_u8() {
        let len = bytes[2] as usize;
        if bytes.len() - 3 < len {
            return None;
        }
        return Some(&bytes[3..(3 + len)]);
    }

    None
}

pub fn han_char(c: char) -> bool {
    if "，。《》？！【】〔〕「」·—：；“”‘’…"
        .chars()
        .any(|x| x == c)
    {
        return true;
    };

    han_char_range(c as u32)
}

/// This decodes `VarInt` (not `CompactInt`) referred to in Bitcoin-core.
///
/// See:
/// - https://github.com/bitcoin/bitcoin/blob/c9e67e214f03519da15d81bd7619879bd78dcfb9/src/serialize.h#L370
///
/// And the decoding algorithm used here is derived from:
///
/// https://github.com/in3rsha/bitcoin-chainstate-parser/blob/master/README.md?tab=readme-ov-file#varints
pub fn decode_bitcoin_core_var_int(bytes: &[u8]) -> (u64, usize) {
    const MAX_BYTES_LEN: usize = 4;
    let mut buf = [0_u8; MAX_BYTES_LEN];
    let mut len = 0_usize;
    for (i, &x) in bytes.iter().enumerate() {
        len += 1;
        buf[i] = x & 0b0111_1111;
        if x & 0b10000000 == 0b00000000 {
            break;
        }
        buf[i] += 1;
        assert_eq!(buf[0] & 0b10000000, 0b00000000);
    }

    match len {
        0 => (0, 0),
        1 => (buf[0] as u64, 1),
        2 => (((buf[0] as u64) << 7) | buf[1] as u64, 2),
        3 => (
            ((buf[0] as u64) << 14) | ((buf[1] as u64) << 7) | buf[2] as u64,
            3,
        ),
        4 => (
            ((buf[0] as u64) << 21)
                | ((buf[1] as u64) << 14)
                | ((buf[2] as u64) << 7)
                | buf[3] as u64,
            4,
        ),
        _ => {
            unimplemented!()
        }
    }
}

pub struct BitcoinCoreVarIntReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BitcoinCoreVarIntReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { pos: 0, data }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn read(&mut self) -> u64 {
        let (n, size) = decode_bitcoin_core_var_int(&self.data[self.pos..]);
        self.pos += size;
        n
    }
}

#[cfg(test)]
mod test {
    use crate::decode_bitcoin_core_var_int;
    use hex_literal::hex;

    #[test]
    fn bitcoin_core_var_int() {
        assert_eq!(decode_bitcoin_core_var_int(&hex!("")), (0, 0));
        assert_eq!(decode_bitcoin_core_var_int(&hex!("8eed3c")), (259900, 3));
        assert_eq!(decode_bitcoin_core_var_int(&hex!("df39")), (12345, 2));
    }
}
