use bitcoin::consensus::Decodable;
use bitcoin::{Block, BlockHash};
use bitcoin_demo::{BitcoinCoreVarIntReader, EncodeHex, XorReader};
use bitflags::bitflags;
use leveldb::database::Database;
use leveldb::kv::KV;
use leveldb::options::{Options, ReadOptions};
use std::fs::File;
use std::io;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
struct BytesKey<'a>(&'a [u8]);

#[derive(Debug, Clone)]
struct OwnedBytesKey(Vec<u8>);

impl db_key::Key for OwnedBytesKey {
    fn from_u8(key: &[u8]) -> Self {
        Self(key.into())
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(&self.0)
    }
}

impl<'a> db_key::Key for BytesKey<'a> {
    fn from_u8(_key: &[u8]) -> Self {
        unimplemented!()
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(self.0)
    }
}

type DbKeyBytes = [u8; 33];

trait DbKey {
    fn as_key(&self) -> DbKeyBytes;
}

impl DbKey for BlockHash {
    fn as_key(&self) -> DbKeyBytes {
        let mut key = [0_u8; size_of::<DbKeyBytes>()];
        key[0] = b'b' /* block hash */;
        key[1..].clone_from_slice(self.as_byte_array());
        key
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
struct KeyWrapper<T: DbKey>(T);

impl<T: DbKey> db_key::Key for KeyWrapper<T> {
    fn from_u8(key: &[u8]) -> Self {
        unimplemented!()
    }

    fn as_slice<U, F: Fn(&[u8]) -> U>(&self, f: F) -> U {
        f(&self.0.as_key())
    }
}

fn main() -> anyhow::Result<()> {
    let list = [
        "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043", /* #0 */
        "0000000012982b6d5f621229286b880e909984df669c2afabb102ce311b13f28", /* #1 */
        "00000000e2c8c94ba126169a88997233f07a9769e2b009fb10cad0e893eff2cb", /* #50000 */
    ];
    for b in list {
        let block = get_block(b.parse()?)?;
        println!("{}", block.block_hash());
    }
    Ok(())
}

fn get_block(block_hash: BlockHash) -> anyhow::Result<Block> {
    let options = Options::new();
    let db = Database::open(
        Path::new("/mnt/nvme/bitcoin/bitcoind/data/testnet4/blocks/index"),
        options,
    )
    .unwrap();
    let ro = ReadOptions::<KeyWrapper<BlockHash>>::new();

    let value = db
        .get(ro, KeyWrapper(block_hash))?
        .expect("No record found");
    println!("Value: {}", value.hex());

    let mut int_reader = BitcoinCoreVarIntReader::new(&value);
    let client_version = int_reader.read();
    let block_height = int_reader.read();
    let block_status = int_reader.read();
    let tx_number = int_reader.read();
    println!("{}", client_version);
    println!("{}", block_height);
    println!("{}", block_status);
    println!("{}", tx_number);

    let block_status =
        BlockStatus::from_bits_truncate(block_status.try_into().expect("u8 expected"));
    assert!(block_status.contains(BlockStatus::BLOCK_HAVE_DATA));
    let blk_file = int_reader.read();
    let blk_start = int_reader.read();
    if block_status.contains(BlockStatus::BLOCK_HAVE_UNDO) {
        let _rev_start = int_reader.read();
    }

    println!("blk_file {}", blk_file);
    println!("blk_start {}", blk_start);

    let mut file = File::open(
        Path::new("/mnt/nvme/bitcoin/bitcoind/blocks/testnet4/blocks").join(blk_filename(blk_file)),
    )?;
    let mut xor_file = File::open("/mnt/nvme/bitcoin/bitcoind/blocks/testnet4/blocks/xor.dat")?;
    let mut xor_data = [0_u8; 8];
    xor_file.read_exact(&mut xor_data)?;

    file.seek(SeekFrom::Start(blk_start))?;
    let mut reader = XorReader::new(file, xor_data);
    reader.xor_skip(blk_start as usize);

    let mut reader = BufReader::new(reader);

    let block = Block::consensus_decode_from_finite_reader(&mut reader).unwrap();
    Ok(block)
}

fn blk_filename(number: u64) -> String {
    format!("blk{:05}.dat", number)
}

bitflags! {
    pub struct BlockStatus: u8 {
        const BLOCK_HAVE_DATA = 8;
        const BLOCK_HAVE_UNDO = 16;
    }
}
