#![allow(incomplete_features, const_evaluatable_unchecked)]
#![feature(generic_const_exprs)]
#![feature(inline_const_pat)]

use bczhc_lib::char::han_char_range;
use bitcoin::absolute::{encode, LockTime};
use bitcoin::address::script_pubkey::BuilderExt;
use bitcoin::key::Secp256k1;
use bitcoin::opcodes::all::{OP_PUSHBYTES_75, OP_PUSHDATA1};
use bitcoin::script::{PushBytes, ScriptBufExt, ScriptExt};
use bitcoin::secp256k1::{All, Message, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{
    consensus, Address, Amount, Network, OutPoint, PrivateKey, PublicKey, Script, ScriptBuf,
    Sequence, TestnetVersion, Transaction, TxIn, Txid,
};
use bitcoin_block_parser::blocks::Options;
use bitcoin_block_parser::headers::ParsedHeader;
use bitcoin_block_parser::{BlockParser, DefaultParser, HeaderParser};
pub use bitcoincore_rpc::bitcoin as bitcoin_old;
use bitcoincore_rpc::bitcoin::opcodes::all::OP_PUSHBYTES_1;
use bitcoincore_rpc::{Auth, RpcApi};
use digest::generic_array::GenericArray;
use digest::typenum::Unsigned;
use digest::{Digest, FixedOutput, OutputSizeUser};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::env::args;
use std::io::{stdin, stdout, Read, Write};
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

/// Only takes the recent `block_count` blocks.
pub fn block_parser_recent(
    network: Network,
    block_count: usize,
) -> impl IntoIterator<Item = (usize, bitcoincore_rpc::bitcoin::Block)> {
    let headers = parse_headers(network);
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
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::sighash::SighashCache;
    use bitcoin::{EcdsaSighashType, Script, ScriptBuf, Transaction};

    pub fn one_input_sign(
        wif: &str,
        tx: &mut Transaction,
        script_pubkey: impl AsRef<Script>,
    ) -> anyhow::Result<()> {
        let cache = SighashCache::new(tx.clone());
        let hash =
            cache.legacy_signature_hash(0, script_pubkey.as_ref(), EcdsaSighashType::All as u32)?;
        let message = Message::from_digest(hash.to_byte_array());
        let mut signature = Secp256k1::default()
            .sign_ecdsa(&message, &wif_to_secret(wif)?)
            .serialize_der()
            .to_vec();
        signature.push(EcdsaSighashType::All as u8);

        tx.input[0].script_sig = ScriptBuf::p2pkh_script_sig(signature, wif_to_pubkey(wif)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{decode_bitcoin_core_var_int, XorReader};
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
}
