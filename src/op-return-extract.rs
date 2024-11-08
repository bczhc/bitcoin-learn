use bitcoin::ScriptBuf;
use bitcoin_demo::extract_op_return;
use hex_literal::hex;

fn main() {
    let script = ScriptBuf::from_bytes(hex!("6a0ce4bc9ae8b5a2e59097efbc9f").to_vec());
    println!("{:?}", extract_op_return(&script));
}
