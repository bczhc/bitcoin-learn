use bitcoin::{CompactTarget, Target};
use bitcoin_demo::bitcoin_rpc_testnet4;
use bitcoincore_rpc::RpcApi;

fn main() -> anyhow::Result<()> {
    let rpc = bitcoin_rpc_testnet4()?;
    println!("{}", rpc.get_difficulty()?);

    Ok(())
}
