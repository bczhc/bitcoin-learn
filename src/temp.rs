use bitcoin::opcodes::all::OP_EQUAL;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::script::ScriptBufExt;
use bitcoin::{Address, KnownHrp, ScriptBuf};

fn main() -> anyhow::Result<()> {
    // let mut witness = Witness::new();
    // // args for redeem-script
    // witness.push()

    let ws = ScriptBuf::builder().push_opcode(OP_EQUAL).into_script();
    let address = Address::p2wsh(&ws, KnownHrp::Mainnet)?;
    println!("{}", address);
    Ok(())
}
