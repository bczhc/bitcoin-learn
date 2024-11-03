use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Txid};
use bitcoin_demo::bitcoin_rpc;
use bitcoincore_rpc::RpcApi;
use hex_literal::hex;
use std::str::FromStr;

fn main() -> anyhow::Result<()> {
    let rpc = bitcoin_rpc()?;
    // let mut height = 820000_u64;
    // loop {
    //     println!("{}", height);
    //     let hash = rpc.get_block_hash(height)?;
    //     let block = rpc.get_block(&hash)?;
    //     if block.txdata.len() == 1 {
    //         // only contains the coinbase transaction
    //         println!("Found: {}", height);
    //     }
    //     // let coinbase_in = &block.txdata[0].input[0];
    //     // let coinbase_data = coinbase_in.script_sig.as_bytes();
    //     // let data = coinbase_data[5..]
    //     //     .iter()
    //     //     .filter(|x| char::from(**x).is_ascii())
    //     //     .copied()
    //     //     .map(|x| if x == b'\n' || x == b'\r' { b' ' } else { x })
    //     //     .collect::<Vec<_>>();
    //     // println!(
    //     //     "Height: {height}; coinbase data: {}",
    //     //     String::from_utf8_lossy(&data)
    //     // );
    //     height += 1;
    // }

    let block = rpc.get_block(&BlockHash::from_str(
        "000000000000000000025d155f4144abbd90fd86f4ac69627470734a79ab2054",
    )?)?;
    let tx = Txid::from_str("6d1041c33738aec56f7301aa9d9a3596c7b57f53be8d60ef6f924d34ca91792a")?;
    for x in block.txdata {
        if x.compute_txid() == tx {
            println!("{:?}", x);
        }
    }

    Ok(())
}
