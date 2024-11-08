use bitcoin::address::script_pubkey::ScriptBufExt;
use bitcoin::{PublicKey, ScriptBuf};
use bitcoin_demo::new_parser;
use hex_literal::hex;

fn main() -> anyhow::Result<()> {
    let parser = new_parser();
    let satoshi_pubkey = hex!("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");
    let output_script = ScriptBuf::new_p2pk(PublicKey::from_slice(&satoshi_pubkey)?);
    for (h, block) in parser {
        let satoshi_mined = block.txdata[0]
            .output
            .iter()
            .any(|x| x.script_pubkey.as_bytes() == output_script.as_bytes());
        if satoshi_mined {
            println!("{} {}", h, block.block_hash());
        }
    }
    Ok(())
}
