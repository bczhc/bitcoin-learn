use bitcoin::address::script_pubkey::ScriptBufExt;
use bitcoin::{Amount, PublicKey, ScriptBuf};
use bitcoin_demo::{new_parser, EncodeHex};
use hex_literal::hex;

fn main() -> anyhow::Result<()> {
    let uc_pubkey = hex!("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");
    let pubkey = PublicKey::from_slice(&uc_pubkey)?;
    assert!(!pubkey.compressed);
    let p2pk_script = ScriptBuf::new_p2pk(pubkey);
    let p2pkh_script = ScriptBuf::new_p2pkh(pubkey.pubkey_hash());

    let mut p2pk_txo_count = 0_u64;
    let mut p2pkh_txo_count = 0_u64;
    let mut p2pkh_amount = 0_u64;

    let parser = new_parser();
    for (_h, block) in parser {
        for tx in block.txdata {
            for (index, txo) in tx.output.iter().enumerate() {
                if txo.script_pubkey.as_bytes() == p2pk_script.as_bytes() {
                    p2pk_txo_count += 1;
                    // println!("1 {}:{index}", tx.compute_txid());
                }
                if txo.script_pubkey.as_bytes() == p2pkh_script.as_bytes() {
                    p2pkh_txo_count += 1;
                    p2pkh_amount += txo.value.to_sat();
                    // println!("2 {}:{index}", tx.compute_txid());
                    println!("p2pkh: {} BTC", Amount::from_sat(p2pkh_amount).to_btc());
                }
            }
        }
    }
    Ok(())
}
