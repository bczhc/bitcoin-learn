//! Parse blk*.dat files.

use bitcoin::consensus::Decodable;
use bitcoin::Block;
use byteorder::{ReadBytesExt, LE};
use hex_literal::hex;
use std::fs::File;
use std::io::{BufReader, ErrorKind, Read};
use std::path::Path;

const MAGIC: [u8; 4] = hex!("f9 be b4 d9");

fn main() {
    let blk_dir = "/mnt/nvme/bitcoin/bitcoind/blocks/testnet3/blocks";
    let file = File::open(Path::new(blk_dir).join("blk00000.dat")).unwrap();

    // let mut block_header = [0_u8; Header::SIZE];
    // file.read_exact(&mut block_header).unwrap();
    // let block_header: Header = consensus::deserialize(&block_header).unwrap();
    // println!("{}", block_header.block_hash());
    // let mut reader = BufReader::new(file);
    // let tx = Transaction::consensus_decode_from_finite_reader(&mut reader).unwrap();
    // println!("{:?}", tx);

    let mut reader = BufReader::new(file);
    loop {
        let mut magic = [0_u8; 4];
        let result = reader.read_exact(&mut magic);
        if result
            .as_ref()
            .is_err_and(|x| x.kind() == ErrorKind::UnexpectedEof)
        {
            break;
        }
        result.unwrap();
        assert_eq!(magic, MAGIC);
        let size = reader.read_u32::<LE>().unwrap();
        let block =
            Block::consensus_decode_from_finite_reader(&mut (&mut reader).take(size as u64))
                .unwrap();
        println!("{:?}", block.compute_merkle_root());
    }
}
