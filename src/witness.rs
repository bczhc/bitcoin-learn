use bitcoin::secp256k1::SecretKey;
use bitcoin_demo::EncodeHex;
use hex_literal::hex;

fn main() -> anyhow::Result<()> {
    let ec = hex!("e62481eb7691c58d9a9793afe00d0e4c7a8d3c71a11a9137ec1f3a2aff1f440a");
    let secret = SecretKey::from_slice(&ec)?;
    Ok(())
}
