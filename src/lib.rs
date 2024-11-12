#![allow(incomplete_features, const_evaluatable_unchecked)]
#![feature(generic_const_exprs)]
#![feature(inline_const_pat)]
#![feature(decl_macro)]
#![feature(bigint_helper_methods)]
// #![feature(type_alias_impl_trait)]

use crate::signing_helper::{one_input_sign, sign_sighash};
use bczhc_lib::char::han_char_range;
use bitcoin::absolute::{encode, LockTime};
use bitcoin::address::script_pubkey::BuilderExt;
use bitcoin::key::Secp256k1;
use bitcoin::opcodes::all::{OP_PUSHBYTES_75, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4};
use bitcoin::script::{PushBytes, ScriptBufExt, ScriptExt};
use bitcoin::secp256k1::{All, Message, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    consensus, Address, Amount, EcdsaSighashType, Network, OutPoint, PrivateKey, PublicKey, Script,
    ScriptBuf, Sequence, TestnetVersion, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_block_parser::blocks::Options;
use bitcoin_block_parser::headers::ParsedHeader;
use bitcoin_block_parser::{BlockParser, DefaultParser, HeaderParser};
pub use bitcoincore_rpc::bitcoin as bitcoin_old;
use bitcoincore_rpc::bitcoin::opcodes::all::OP_PUSHBYTES_1;
use bitcoincore_rpc::{Auth, RpcApi};
use chrono::{DateTime, Local, TimeZone};
use digest::generic_array::GenericArray;
use digest::typenum::Unsigned;
use digest::{Digest, FixedOutput, OutputSizeUser};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::Bound;
use std::env::args;
use std::io::{stdin, stdout, Read, Write};
use std::ops::{Index, RangeBounds};
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

/// Hash data one or multiple times.
///
/// # Exapmles
///
/// ```
/// use hex_literal::hex;
/// use bitcoin_demo::hash_iter;
///
/// let data = b"hello";
/// assert_eq!(hash_iter::<sha2::Sha256>(data, 2), hex!("9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"));
/// ```
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

pub fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
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

fn blocks_dir(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "/mnt/nvme/bitcoin/bitcoind/blocks/blocks",
        Network::Testnet(TestnetVersion::V3) => "/mnt/nvme/bitcoin/bitcoind/blocks/testnet3/blocks",
        Network::Testnet(TestnetVersion::V4) => "/mnt/nvme/bitcoin/bitcoind/blocks/testnet4/blocks",
        _ => unimplemented!(),
    }
}

pub fn new_parser(
    network: Network,
) -> impl IntoIterator<Item = (usize, bitcoincore_rpc::bitcoin::Block)> {
    let options = Options::default().order_output();
    let blk_dir = blocks_dir(network);
    let mut headers = HeaderParser::parse(blk_dir).unwrap();
    println!("{}", headers.len());
    // headers.reverse();
    let parser = DefaultParser.parse_with_opts(&headers, options);

    let mut height = headers.len() - 1;
    (0..=height)
        // .rev()
        .zip(parser.into_iter().map(Result::unwrap))
}

pub fn new_parser_rev(
    network: Network,
) -> impl IntoIterator<Item = (usize, bitcoincore_rpc::bitcoin::Block)> {
    let options = Options::default().order_output();
    let blk_dir = blocks_dir(network);
    let mut headers = HeaderParser::parse(blk_dir).unwrap();
    headers.reverse();
    let parser = DefaultParser.parse_with_opts(&headers, options);

    let mut height = headers.len() - 1;
    (0..=height)
        .rev()
        .zip(parser.into_iter().map(Result::unwrap))
}

pub fn parse_headers(network: Network) -> Vec<ParsedHeader> {
    HeaderParser::parse(blocks_dir(network)).unwrap()
}

pub fn block_parser(
    headers: &[ParsedHeader],
) -> impl IntoIterator<Item = (usize, bitcoincore_rpc::bitcoin::Block)> {
    let options = Options::default().order_output();
    let parser = DefaultParser.parse_with_opts(headers, options);

    let mut height = headers.len() - 1;
    (0..=height).zip(parser.into_iter().map(Result::unwrap))
}

macro block_iter_type() {
    impl IntoIterator<Item = (u32, bitcoincore_rpc::bitcoin::Block)>
}

/// Only takes the recent `block_count` blocks.
pub fn block_parser_recent(network: Network, block_count: usize) -> block_iter_type!() {
    let headers = parse_headers(network);
    let start = headers.len() - block_count;
    let selected_headers = &headers[start..];
    let selected_height_start = headers.len() - block_count;

    let options = Options::default().order_output();
    let parser = DefaultParser.parse_with_opts(selected_headers, options);
    (selected_height_start..(selected_height_start + block_count))
        .map(|x| x as u32)
        .zip(parser.into_iter().map(Result::unwrap))
}

pub fn block_parser_range(range: impl RangeBounds<u32>, network: Network) -> block_iter_type!() {
    let headers = parse_headers(network);
    let start = match range.start_bound() {
        Bound::Included(&x) => x,
        Bound::Excluded(_) => unimplemented!(),
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(&x) => x,
        Bound::Excluded(&x) => {
            if x == start {
                // return [].into_iter()
                panic!("Range is empty")
            } else {
                x - 1
            }
        }
        Bound::Unbounded => headers.len() as u32 - 1,
    };

    let range = &headers[start as usize..=end as usize];

    let options = Options::default().order_output();
    let parser = DefaultParser
        .parse_with_opts(range, options)
        .into_iter()
        .map(Result::unwrap);
    (start..=end).into_iter().zip(parser)
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

pub fn broadcast_tx(tx: &Transaction) -> anyhow::Result<Txid> {
    let rpc = bitcoin_rpc_testnet4()?;
    let raw_tx = consensus::serialize(tx);
    let txid = rpc.send_raw_transaction(&raw_tx)?;
    let txid: Txid = bitcoin_old_to_new(&txid);
    Ok(txid)
}

pub fn confirm_to_broadcast(tx: &Transaction) {
    let serialized = encode::serialize(tx);
    println!("Transaction: {}", serialized.hex());
    confirm_to_broadcast_raw(&serialized);
}

const FEE_RATE: f64 = 1.4;
pub fn estimate_fee(tx: &Transaction) -> Amount {
    let size = consensus::serialize(tx).len() + ESTIMATED_SCRIPT_SIG_SIZE * 1;
    Amount::from_sat((size as f64 * FEE_RATE) as u64)
}

pub const TESTNET4: Network = Network::Testnet(TestnetVersion::V4);

pub fn wait_new_line() {
    stdin().read_line(&mut String::new()).unwrap();
}

pub fn prompt_wait_new_line() {
    print!("Wait for enter key...");
    stdout().flush().unwrap();
    wait_new_line();
}

/// Limit every output to use up to 75 bytes. Because we have an opcode
/// [`OP_PUSHBYTES_75`] that pushes the most among `PUSHBYTES_*` group.
pub const OP_RETURN_IDEAL_MAX: usize = 75;

pub fn ideal_checked_op_return(data: &[u8]) -> ScriptBuf {
    assert!(data.len() <= OP_RETURN_IDEAL_MAX);
    ScriptBuf::new_op_return(<&PushBytes>::try_from(data).unwrap())
}

pub fn broadcast_tx_retry(tx: &Transaction) -> Txid {
    let new_txid = loop {
        let result = broadcast_tx(&tx);
        match result {
            Ok(x) => break x,
            Err(e) => {
                println!("Failed to broadcast. Press enter to retry. Error: {}", e);
                prompt_wait_new_line();
            }
        }
    };
    new_txid
}

pub fn generic_pay_to_one(
    network: Network,
    wif: &str,
    outpoint: &str,
    outpoint_script_pubkey: &Script,
    outpoint_amount: Amount,
    outpoint_is_p2wpkh: bool,
    to_address: &str,
    amount: Amount,
) -> anyhow::Result<Txid> {
    let outpoint: OutPoint = outpoint.parse()?;
    let address = parse_address(to_address, network)?;

    let mut tx = default_tx();
    tx.input[0].previous_output = outpoint;

    tx.output = vec![TxOut {
        value: amount,
        script_pubkey: address.script_pubkey(),
    }];

    // use p2wpkh signing or legacy signing according to the address type
    if outpoint_is_p2wpkh {
        let sighash_type = EcdsaSighashType::All;
        let mut cache = SighashCache::new(tx.clone());
        let sighash = cache.p2wpkh_signature_hash(
            0,
            outpoint_script_pubkey,
            outpoint_amount,
            sighash_type,
        )?;
        let private_key = PrivateKey::from_wif(wif)?;
        let signature = sign_sighash(sighash, &private_key.inner, sighash_type);
        let mut witness = Witness::new();
        witness.push(signature);
        witness.push(
            private_key
                .public_key(&Default::default())
                .inner
                .serialize(),
        );
        tx.input[0].witness = witness;
    } else {
        one_input_sign(wif, &mut tx, outpoint_script_pubkey)?;
    }

    Ok(broadcast_tx(&tx)?)
}

pub fn parse_timestamp(time: u32) -> DateTime<Local> {
    Local.timestamp_millis_opt(time as i64 * 1000).unwrap()
}

#[inline]
pub fn guess_meaningful_text(text: &str) -> bool {
    if text.len() < 10 && text.len() > 4 && text.chars().all(|x| !x.is_ascii_control()) {
        // maybe single words
        return true;
    }

    // only accept printable data
    if text.chars().any(|x| x.is_ascii_control()) {
        return false;
    }
    // reject text with all asciis but without any space
    if text.chars().all(|x| x.is_ascii()) && !text.contains(' ') {
        return false;
    }

    true
}

#[macro_export]
macro_rules! script_hex {
    ($x:literal) => {
        bitcoin::script::Script::from_bytes(&hex_literal::hex!($x))
    };
}

pub trait BitcoinAmountExt {
    const DUST_MIN: Amount = Amount::from_sat(1000);
}

impl BitcoinAmountExt for Amount {}

/// Extract the data from an `OP_RETURN` script.
///
/// # Examples
///
/// ```
/// use bitcoin::script::ScriptBufExt;
/// use bitcoin::ScriptBuf;
/// use bitcoin_demo::extract_op_return;
///
/// let script = ScriptBuf::new_op_return(b"hello");
/// let extracted = extract_op_return(&script);
/// assert_eq!(extracted, Some(&b"hello"[..]));
/// ```
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
    if bytes.get(1).is_none() {
        return None;
    }
    if (OP_PUSHBYTES_1.to_u8()..=OP_PUSHBYTES_75.to_u8()).contains(&bytes[1]) {
        let pushed_len = (bytes[1] - OP_PUSHBYTES_1.to_u8() + 1) as usize;
        if bytes.len() - 2 < pushed_len {
            return None;
        }
        let data = &bytes[2..(2 + pushed_len)];
        return Some(data);
    }

    // OP_RETURN <OP_PUSHDATAx> <length> <data>
    match bytes.get(1) {
        Some(&x) if x == OP_PUSHDATA1.to_u8() => {
            // OP_PUSHDATA1
            let Some(&length) = bytes.get(2) else {
                return None;
            };
            let length = length as usize;
            if bytes.len() - 3 < length {
                return None;
            }
            return Some(&bytes[3..(3 + length)]);
        }
        Some(&x) if x == OP_PUSHDATA2.to_u8() => {
            // OP_PUSHDATA2
            let (Some(&len_low), Some(&len_high)) = (bytes.get(2), bytes.get(3)) else {
                return None;
            };
            let length = u16::from_le_bytes([len_low, len_high]) as usize;
            if bytes.len() - 4 < length {
                return None;
            }
            return Some(&bytes[4..(4 + length)]);
        }
        Some(&x) if x == OP_PUSHDATA4.to_u8() => {
            // OP_PUSHDATA4
            let (Some(&len1), Some(&len2), Some(&len3), Some(&len4)) =
                (bytes.get(2), bytes.get(3), bytes.get(4), bytes.get(5))
            else {
                return None;
            };
            let length = u32::from_le_bytes([len1, len2, len3, len4]) as usize;
            if bytes.len() - 6 < length {
                return None;
            }
            return Some(&bytes[6..(6 + length)]);
        }
        _ => {}
    }

    None
}

/// Han characters with punctuations.
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

/// Such things are caused by inconsistent `bitcoin` versions used by this crate
/// and `bitcoincore_rpc`
///
/// # Examples
///
/// ```rust
/// use bitcoincore_rpc::bitcoin as old;
/// use bitcoin_demo::bitcoin_old_to_new;
///
/// let old_amount = old::Amount::from_sat(1000);
/// let new_amount: bitcoin::Amount = bitcoin_old_to_new(&old_amount);
/// assert_eq!(old_amount.to_sat(), new_amount.to_sat());
/// ```
pub fn bitcoin_old_to_new<
    Src: bitcoincore_rpc::bitcoin::consensus::Encodable + ?Sized,
    Dst: bitcoin::consensus::Decodable + ?Sized,
>(
    src: &Src,
) -> Dst {
    let data = bitcoincore_rpc::bitcoin::consensus::serialize(src);
    bitcoin::consensus::deserialize(&data).unwrap()
}

pub fn bitcoin_new_to_old<
    Src: bitcoin::consensus::Encodable + ?Sized,
    Dst: bitcoincore_rpc::bitcoin::consensus::Decodable + ?Sized,
>(
    src: &Src,
) -> Dst {
    let data = consensus::serialize(src);
    bitcoin_old::consensus::deserialize(&data).unwrap()
}

/// Circularly take values.
///
/// # Examples
///
/// ```
/// use bitcoin_demo::Circular;
///
/// let data = [1_u8, 2];
/// let mut c = Circular::new(data);
/// assert_eq!(c.next(), 1_u8);
/// assert_eq!(c.next(), 2_u8);
/// assert_eq!(c.next(), 1_u8);
/// assert_eq!(c.next(), 2_u8);
/// ```
pub struct Circular {
    vec: Vec<u8>,
    counter: usize,
}

impl Circular {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            vec: bytes.into(),
            counter: 0,
        }
    }

    #[inline]
    pub fn next(&mut self) -> u8 {
        let x = self.vec[self.counter % self.vec.len()];
        self.counter += 1;
        x
    }

    pub fn skip(&mut self, size: usize) {
        self.counter += size;
    }
}

pub struct XorReader<R: Read> {
    inner: R,
    xor: Circular,
}

impl<R: Read> XorReader<R> {
    pub fn new(reader: R, xor_bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: reader,
            xor: Circular::new(xor_bytes),
        }
    }

    pub fn xor_skip(&mut self, size: usize) {
        self.xor.skip(size);
    }
}

impl<R: Read> Read for XorReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.inner.read(buf)?;
        for x in &mut buf[..size] {
            *x ^= self.xor.next();
        }
        Ok(size)
    }
}

const INITIAL_BLOCK_REWARD: u64 = 50_0000_0000 /* 50 BTC */;

/// Block reward by height
///
/// # Examples
///
/// ```rust
/// use bitcoin_demo::bitcoin_block_reward;
///
/// assert_eq!(bitcoin_block_reward(839999), 6_25000000);
/// assert_eq!(bitcoin_block_reward(840000), 3_12500000);
/// ```
pub fn bitcoin_block_reward(height: u32) -> u64 {
    const INTERVAL: u32 = 210_000;
    match height {
        const { INTERVAL * 0 }..const { INTERVAL * 1 } => INITIAL_BLOCK_REWARD / 1,
        const { INTERVAL * 1 }..const { INTERVAL * 2 } => INITIAL_BLOCK_REWARD / 2,
        const { INTERVAL * 2 }..const { INTERVAL * 3 } => INITIAL_BLOCK_REWARD / 4,
        const { INTERVAL * 3 }..const { INTERVAL * 4 } => INITIAL_BLOCK_REWARD / 8,
        const { INTERVAL * 4 }..const { INTERVAL * 5 } => INITIAL_BLOCK_REWARD / 16,
        const { INTERVAL * 5 }..const { INTERVAL * 6 } => INITIAL_BLOCK_REWARD / 32,
        _ => unimplemented!(),
    }
}

pub fn set_up_logging(level: log::LevelFilter, file: Option<&str>) -> anyhow::Result<()> {
    let mut dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                humantime::format_rfc3339(std::time::SystemTime::now()),
                record.level(),
                record.target(),
                message
            ))
        })
        .level(level)
        .chain(stdout());
    if let Some(f) = file {
        dispatch = dispatch.chain(fern::log_file(f)?);
    }
    dispatch.apply()?;
    Ok(())
}

pub struct IntervalLogger {
    start: u64,
}

impl IntervalLogger {
    pub fn new() -> Self {
        Self { start: timestamp() }
    }

    pub fn log(&mut self, f: impl FnOnce()) {
        let timestamp_ms = timestamp_ms();
        if timestamp_ms / 1000 == self.start {
            // this is called within one second, ignored
        } else {
            f();
            // reset the start time
            self.start = timestamp_ms / 1000;
        }
    }
}

/// Builds a concrete transaction for most common/trivial uses, with one dummy input and no output.
pub fn default_tx() -> Transaction {
    Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::COINBASE_PREVOUT,
            sequence: Sequence::FINAL,
            witness: Default::default(),
            script_sig: Default::default(),
        }],
        output: vec![],
    }
}

pub fn parse_address(addr: &str, network: Network) -> anyhow::Result<Address> {
    Ok(addr.parse::<Address<_>>()?.require_network(network)?)
}

pub fn wif_to_secret(wif: &str) -> anyhow::Result<SecretKey> {
    Ok(PrivateKey::from_wif(wif)?.inner)
}

pub fn wif_to_pubkey(wif: &str) -> anyhow::Result<PublicKey> {
    Ok(PrivateKey::from_wif(wif)?.public_key(&Default::default()))
}

pub trait ScriptBufExt2 {
    fn p2pkh_script_sig(
        signature: impl AsRef<[u8]>,
        pubkey: impl Into<PublicKey>,
    ) -> anyhow::Result<ScriptBuf> {
        Ok(ScriptBuf::builder()
            .push_slice_try_from(signature.as_ref())?
            .push_key(pubkey.into())
            .into_script())
    }
}

impl ScriptBufExt2 for ScriptBuf {}

/// https://bitcoin.stackexchange.com/a/77192/159523
pub const MAX_SIGNATURE_LENGTH: usize = 73;
pub const COMPRESSED_PUBKEY_LENGTH: usize = 1 /* prefix */
    + 32 /* an ECDSA point */;

pub const UNCOMPRESSED_PUBKEY_LENGTH: usize = COMPRESSED_PUBKEY_LENGTH + 32 /* another ECDSA point */;
pub const ESTIMATED_SCRIPT_SIG_SIZE: usize = 1 /* PUSHBYTES_XX */
    + MAX_SIGNATURE_LENGTH /* signature */
    + 1 /* PUSHBYTES_XX */
    + COMPRESSED_PUBKEY_LENGTH /* public key (compressed) */;

pub mod signing_helper {
    use crate::{wif_to_pubkey, wif_to_secret, ScriptBufExt2};
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    use bitcoin::sighash::SighashCache;
    use bitcoin::{EcdsaSighashType, Script, ScriptBuf, Transaction};

    pub fn one_input_sign(
        wif: &str,
        tx: &mut Transaction,
        script_pubkey: impl AsRef<Script>,
    ) -> anyhow::Result<()> {
        let signature = one_input_signature(wif, tx, script_pubkey)?;
        tx.input[0].script_sig = ScriptBuf::p2pkh_script_sig(signature, wif_to_pubkey(wif)?)?;
        Ok(())
    }

    pub fn one_input_signature(
        wif: &str,
        tx: &Transaction,
        script_pubkey: impl AsRef<Script>,
    ) -> anyhow::Result<Vec<u8>> {
        let cache = SighashCache::new(tx.clone());
        let hash =
            cache.legacy_signature_hash(0, script_pubkey.as_ref(), EcdsaSighashType::All as u32)?;
        let signature = sign_sighash(hash, &wif_to_secret(wif)?, EcdsaSighashType::All);
        Ok(signature)
    }

    /// Returns the bitcoin signature: `(<ecdsa-signature> <sighash-flag>)`
    pub fn sign_sighash(
        sighash: impl AsRef<[u8]>,
        secret: &SecretKey,
        sighash_flag: EcdsaSighashType,
    ) -> Vec<u8> {
        let message = Message::from_digest(sighash.as_ref().try_into().expect("Length must be 32"));
        let mut signature = Secp256k1::default()
            .sign_ecdsa(&message, secret)
            .serialize_der()
            .to_vec();
        signature.push(sighash_flag as u8);
        signature
    }
}

pub mod mining {
    use crate::EncodeHex;
    use bitcoin::{consensus, Block, Target};
    use hex_literal::hex;
    use std::cmp::Ordering;
    use std::fmt;
    use std::fmt::{Display, Formatter};
    use std::ops::Add;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::{channel, Sender};
    use std::sync::{atomic, Arc};
    use std::thread::spawn;

    #[derive(Clone)]
    pub struct RawBlockHeader([u8; 80]);

    impl RawBlockHeader {
        fn change_nonce(&mut self, n: u32) {
            unsafe {
                *(&mut self.0[80 - 4] as *mut u8 as *mut [u8; 4]) = n.to_le_bytes();
            }
        }

        fn block_hash(&self) -> [u8; 32] {
            crate::sha256d(&self.0)
        }

        fn block_hash_display(&self) -> String {
            let mut hash = self.block_hash();
            hash.reverse();
            hash.hex()
        }
    }

    impl From<&Block> for RawBlockHeader {
        fn from(value: &Block) -> Self {
            let vec = consensus::encode::serialize(&value.header);
            Self(vec.try_into().expect("Block header must be 80-byte length"))
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    struct Uint256 {
        lo: u128,
        hi: u128,
    }

    impl Display for Uint256 {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            use fmt::Write;
            write!(
                f,
                "lo: {}, hi: {}",
                self.lo.to_ne_bytes().hex(),
                self.hi.to_ne_bytes().hex()
            )
        }
    }

    impl Uint256 {
        fn from_bytes_le(bytes: [u8; 256 / 8]) -> Self {
            unsafe {
                let lo = *(bytes.as_ptr() as *const u128);
                let hi = *(bytes.as_ptr().offset(16) as *const u128);
                Self { lo, hi }
            }
        }

        fn from_bytes_be(bytes: [u8; 256 / 8]) -> Self {
            unsafe {
                let mut lo_part = *(&bytes[16] as *const u8 as *const [u8; 16]);
                lo_part.reverse();
                let mut hi_part = *(&bytes[0] as *const u8 as *const [u8; 16]);
                hi_part.reverse();
                Self {
                    lo: u128::from_le_bytes(lo_part),
                    hi: u128::from_le_bytes(hi_part),
                }
            }
        }

        fn to_bytes_le(self) -> [u8; 256 / 8] {
            let mut b = [0_u8; 256 / 8];
            b[..16].copy_from_slice(&self.lo.to_le_bytes());
            b[16..].copy_from_slice(&self.hi.to_le_bytes());
            b
        }

        fn to_bytes_be(self) -> [u8; 256 / 8] {
            let mut b = [0_u8; 256 / 8];
            b[..16].copy_from_slice(&self.hi.to_be_bytes());
            b[16..].copy_from_slice(&self.lo.to_be_bytes());
            b
        }
    }

    impl Add for Uint256 {
        type Output = Uint256;

        fn add(self, rhs: Self) -> Self::Output {
            // TODO: carrying maybe not work
            let (lo, carry) = self.lo.carrying_add(rhs.lo, false);
            let hi = self.hi.carrying_add(self.hi, carry).0;
            Self { lo, hi }
        }
    }

    impl PartialOrd for Uint256 {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            if self == other {
                return Some(Ordering::Equal);
            }

            if self.hi != other.hi {
                return Some(self.hi.cmp(&other.hi));
            }

            // only compare the low part
            Some(self.lo.cmp(&other.lo))
        }
    }

    pub fn assert_little_endianness() {
        let num = 0x1122334455667788_9900000000000000_u128;
        assert_eq!(num.to_ne_bytes(), hex!("0000000000000099 8877665544332211"));
    }

    pub fn mine(block: Block) -> Option<u32> {
        assert_little_endianness();

        let threads = num_cpus::get() as u32;
        println!("use threads: {threads}");
        assert_eq!((u32::MAX as u64 + 1) % threads as u64, 0);

        let bits = block.header.bits;
        println!("Bits: {}", bits.to_consensus());
        let target = Target::from(bits);
        let target_le = target.to_le_bytes();
        // let target_le = {
        //     let mut x = hex!("0000000000ffff00000000000000000000000000000000000000000000000000");
        //     x.reverse();
        //     x
        // };
        let target = Uint256::from_bytes_le(target_le);
        println!("Target: {}", target.to_bytes_be().hex());

        #[inline(always)]
        fn check_target(header: &RawBlockHeader, target: &Uint256) -> bool {
            let hash = header.block_hash();
            let hash_num = Uint256::from_bytes_le(hash);
            hash_num.le(target)
        }

        let part = ((u32::MAX as u64 + 1) / threads as u64) as u32;
        let mut join_handlers = Vec::new();
        let result_channel = channel();
        struct Context {
            result_sender: Sender<u32>,
            stop: AtomicBool,
            target: Uint256,
        }
        let context = Arc::new(Context {
            stop: AtomicBool::new(false),
            result_sender: result_channel.0,
            target,
        });
        for i in 0..threads {
            let mut raw_header = RawBlockHeader::from(&block);
            let range = (part * i)..=(part * i + (part - 1));
            let context = Arc::clone(&context);
            let handler = spawn(move || {
                let target = context.target;
                for nonce in range {
                    if context.stop.load(atomic::Ordering::SeqCst) {
                        break;
                    }

                    raw_header.change_nonce(nonce);
                    if check_target(&raw_header, &target) {
                        println!(
                            "Mined! {}, nonce {}",
                            raw_header.block_hash_display(),
                            nonce
                        );
                        context.result_sender.send(nonce).unwrap();
                        context.stop.store(true, atomic::Ordering::SeqCst);
                    }
                }
            });
            join_handlers.push(handler);
        }

        join_handlers.into_iter().for_each(|x| x.join().unwrap());

        result_channel.1.try_recv().ok()
    }

    #[cfg(test)]
    mod test {
        use crate::mining::assert_little_endianness;
        use crate::mining::Uint256;
        use hex_literal::hex;

        #[test]
        fn test() {
            assert_little_endianness();

            macro from_be($b:expr) {
                Uint256::from_bytes_be(hex!($b))
            }
            let n1 = from_be!("0000ffffffff0000000000000000000000000000000000000000000000000000");
            let n2 = from_be!("0000ffffffff0000000000000000000000000000000000000000000000000000");
            assert_eq!(n1, n2);
            let n3 = from_be!("0000ffffffff0000000000000000000000000000000000000000000000000001");
            assert!(n2 < n3);
            let n4 = from_be!("000000ffffff0000000000000000000000000000000000000000000000000000");
            assert!(n3 > n4);
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{decode_bitcoin_core_var_int, extract_op_return, guess_meaningful_text, XorReader};
    use hex_literal::hex;
    use std::io::{Cursor, Read};

    #[test]
    fn bitcoin_core_var_int() {
        assert_eq!(decode_bitcoin_core_var_int(&hex!("")), (0, 0));
        assert_eq!(decode_bitcoin_core_var_int(&hex!("12")), (0x12, 1));
        assert_eq!(decode_bitcoin_core_var_int(&hex!("df39")), (12345, 2));
        assert_eq!(decode_bitcoin_core_var_int(&hex!("8eed3c")), (259900, 3));
    }

    #[test]
    fn xor() {
        let data = Cursor::new(hex!("8e ed 3c df 39").to_vec());
        let mut xor = XorReader::new(data, hex!("aabb"));
        let mut out = Vec::new();
        xor.read_to_end(&mut out).unwrap();

        assert_eq!(
            &out,
            &[
                0x8e ^ 0xaa,
                0xed ^ 0xbb,
                0x3c ^ 0xaa,
                0xdf ^ 0xbb,
                0x39 ^ 0xaa,
            ]
        );
    }

    #[test]
    fn meaningful_text() {
        assert!(!guess_meaningful_text("\x02DS"));
    }

    #[test]
    fn op_return() {
        assert_eq!(extract_op_return(script_hex!("")), None);
        assert_eq!(extract_op_return(script_hex!("6a")), None);
        // OP_PUSHBYTES*
        assert_eq!(extract_op_return(script_hex!("6a05")), None);
        assert_eq!(
            extract_op_return(script_hex!("6a056162636465")),
            Some(&b"abcde"[..])
        );
        // OP_PUSHDATA1
        assert_eq!(extract_op_return(script_hex!("6a4c")), None);
        assert_eq!(extract_op_return(script_hex!("6a4c03")), None);
        assert_eq!(extract_op_return(script_hex!("6a4c036162")), None);
        assert_eq!(
            extract_op_return(script_hex!("6a4c03616263")),
            Some(&b"abc"[..])
        );
        assert_eq!(
            extract_op_return(script_hex!("6a4c0361626364")),
            Some(&b"abc"[..])
        );
        // OP_PUSHDATA2
        assert_eq!(extract_op_return(script_hex!("6a4d")), None);
        assert_eq!(extract_op_return(script_hex!("6a4d04")), None);
        assert_eq!(extract_op_return(script_hex!("6a4d0400")), None);
        assert_eq!(extract_op_return(script_hex!("6a4d0400616263")), None);
        assert_eq!(
            extract_op_return(script_hex!("6a4d040061626364")),
            Some(&b"abcd"[..])
        );
        assert_eq!(
            extract_op_return(script_hex!("6a4d04006162636465")),
            Some(&b"abcd"[..])
        );
        // OP_PUSHDATA4
        assert_eq!(extract_op_return(script_hex!("6a4e")), None);
        assert_eq!(extract_op_return(script_hex!("6a4e06")), None);
        assert_eq!(extract_op_return(script_hex!("6a4e0600")), None);
        assert_eq!(extract_op_return(script_hex!("6a4e06000000")), None);
        assert_eq!(extract_op_return(script_hex!("6a4e0600000061")), None);
        assert_eq!(
            extract_op_return(script_hex!("6a4e060000006162636465")),
            None
        );
        assert_eq!(
            extract_op_return(script_hex!("6a4e06000000616263646566")),
            Some(&b"abcdef"[..])
        );
        assert_eq!(
            extract_op_return(script_hex!("6a4e0600000061626364656667")),
            Some(&b"abcdef"[..])
        );
    }
}
