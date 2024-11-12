use bitcoin::script::ScriptBufExt;
use bitcoin::{Script, ScriptBuf};
use bitcoin_demo::hash160;
use num_bigint::BigUint;
use num_traits::{One, Zero};

fn main() {
    println!("{}", ScriptBuf::builder().push_int(-256).unwrap());

    return;
    let mut int = BigUint::zero();
    let mut b58_input = [0_u8; 160 / 8 + 1];
    b58_input[0] = 0x05 /* version prefix */;
    loop {
        let be_bytes = int.to_bytes_be();
        let script_hash = hash160(&be_bytes);
        b58_input[1..].copy_from_slice(&script_hash);
        let p2sh = bitcoin::base58::encode_check(&b58_input);
        println!("{} {}", p2sh, Script::from_bytes(&be_bytes));
        /* TODO: check UTXO */
        int += BigUint::one();
    }
}
