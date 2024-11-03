use bitcoin::consensus::Decodable;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Block, Network};
use bitcoin_demo::{secret_to_pubkey, secret_to_pubkey_uncompressed, sha256, sha256d};
use bitcoincore_rpc::{Auth, RpcApi};
use electrum_client::ElectrumApi;

fn main() {
    let client = electrum_client::Client::new("localhost:50001").unwrap();
    let bc_client = bitcoincore_rpc::Client::new(
        "localhost:8332",
        Auth::UserPass(String::from("bitcoinrpc"), String::from("123")),
    )
    .unwrap();

    for h in (0..=816275) {
        let block_header = client.block_header(h).unwrap();
        let block_hash = block_header.block_hash();
        let block = bc_client.get_block(&block_hash).unwrap();
        for tx in block.txdata {
            let txid = tx.txid();
            println!("{}", txid);
            let mut x: [u8; 32] = *txid.as_ref();
            x.reverse();
            println!("{}", hex::encode(x));
            println!("{}", hex::encode(sha256(txid.as_ref())));
            println!("{}", hex::encode(sha256d(txid.as_ref())));
        }
    }
}
