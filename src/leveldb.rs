use bitcoin::consensus::Decodable;
use bitcoin::{Block, BlockHash};
use bitcoin_demo::{BitcoinCoreVarIntReader, EncodeHex};
use bitflags::bitflags;
use leveldb::database::Database;
use leveldb::kv::KV;
use leveldb::options::{Options, ReadOptions};
use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};
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
    let options = Options::new();
    let db = Database::open(
        Path::new("/mnt/nvme/bitcoin/bitcoind/data/testnet4/blocks/index"),
        options,
    )
    .unwrap();
    let ro = ReadOptions::<KeyWrapper<BlockHash>>::new();
    let bloch_hash =
        "00000000000bf65febda12ae5dfd009acff48227b9533acffd84deea44d21bba" /* height: 12345 */
            .parse::<BlockHash>()?;

    let value = db
        .get(ro, KeyWrapper(bloch_hash))?
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
    assert!(block_status.contains(BlockStatus::BLOCK_HAVE_UNDO));
    let blk_file = int_reader.read();
    let blk_start = int_reader.read();
    let _rev_start = int_reader.read();

    println!("{}", blk_file);
    println!("{}", blk_start);

    let mut file = File::open(
        Path::new("/mnt/nvme/bitcoin/bitcoind/blocks/testnet4/blocks").join(blk_filename(blk_file)),
    )?;
    file.seek(SeekFrom::Start(blk_start))?;
    let mut reader = BufReader::new(file);
    let block = Block::consensus_decode_from_finite_reader(&mut reader).unwrap();
    println!("{:?}", block.compute_merkle_root());
    println!("{}", block.block_hash());
    println!("{:?}", block);

    Ok(())
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
