use bitcoin::Txid;
use bitcoin_demo::EncodeHex;

fn main() {
    let txid: Txid = "f21c7462e56fef1a212ac4aa214a3b99c919f7f7a1bb7000ea0c591be5aa0720"
        .parse()
        .unwrap();
    println!("{}", txid.hex());
}
