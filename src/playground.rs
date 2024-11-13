use bitcoin_demo::{bitcoin_rpc_testnet4, EncodeHex, WITNESS_ITEM_MAX};
use bitcoincore_rpc::RpcApi;

fn main() -> anyhow::Result<()> {
    let rpc = bitcoin_rpc_testnet4()?;
    println!(
        "{:?}",
        rpc.get_block(&"0000000000333b2b4760e67fe7f428036709c0d8f332517d678857167dd6ceaa".parse()?)
    );
    Ok(())
}
