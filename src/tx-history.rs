use bitcoin::script::ScriptExt;
use bitcoin_demo::new_parser;
use bitcoincore_rpc::bitcoin::opcodes::all::{OP_PUSHBYTES_33, OP_PUSHBYTES_72};
use rayon::prelude::*;
use std::fmt::Debug;

fn main() -> anyhow::Result<()> {
    const SIG_LEN: usize = 72;
    const PUBKEY_LEN: usize = 33;

    let receiver = new_parser();
    for (height, block) in receiver {
        for x in block.txdata {
            for (i, txi) in x.input.iter().enumerate() {
                let sig = &txi.script_sig;
                if sig.first_opcode() == Some(OP_PUSHBYTES_72)
                    && sig.as_bytes().get(1 + 72) == Some(&OP_PUSHBYTES_33.to_u8())
                    && sig.as_bytes().get(72) == Some(&0x02 /* SIGHASH_NONE */)
                {
                    println!("{}:{}", x.compute_txid(), i);
                }
            }
        }
    }

    Ok(())
}
