//! A kind of brain wallet address is in the p2sh form. The redeem script is like the following:
//!
//! `OP_HASH160 OP_PUSHBYTES_N xxx OP_EQUAL`
//!
//! Transactions involving these address have happened a lot on the blockchain. Some examples:
//!
//! - <https://mempool.space/tx/6291d99a36997b1a4aa14f9b83cbce237626c03d14303aa270bbc1acad761f06>

use bitcoin::opcodes::all::{OP_EQUAL, OP_HASH160};
use bitcoin::script::ScriptBufExt;
use bitcoin::{Address, NetworkKind, ScriptBuf};
use bitcoin_demo::{hash160, ScriptsBuilderExt};

fn main() -> anyhow::Result<()> {
    let password = "hello";
    // hash160
    let hash = hash160(password.as_bytes());
    let redeem = ScriptBuf::builder()
        .push_opcode(OP_HASH160)
        .push_slice(hash)
        .push_opcode(OP_EQUAL)
        .into_script();

    let address = Address::p2sh(&redeem, NetworkKind::Main)?;
    // If the address exists in the UTXO set, we can spend it.
    // The scriptSig to unlock it is shown below.
    let _script_sig = ScriptBuf::builder()
        .push_slice_try_from(password.as_bytes())?
        .push_slice_try_from(redeem.as_bytes())?
        .into_script();

    // TODO: search it using Electrum server
    Ok(())
}
