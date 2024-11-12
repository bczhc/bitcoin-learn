//! <https://mempool.space/testnet4/tx/0fd7658a90b3d86051d4656d15ca11d5f548c40ab8b50bf486c7dedfcdd70986>

use bitcoin::opcodes::all::{OP_ADD, OP_EQUAL};
use bitcoin::script::ScriptBufExt;
use bitcoin::{Amount, ScriptBuf};
use bitcoin_demo::{generic_pay_to_one, script_hex, TESTNET4};

fn main() -> anyhow::Result<()> {
    let txid = generic_pay_to_one(
        TESTNET4,
        "cSDuf6wbKeTnnJJiiqp5ZSku3pV2UZ9Snpz9FpZGaakVKyba8Z7W",
        "cc146d76e5792205eab2d49b22a1ea57b195bb715cefeccf3220f4efdefe77c2:0",
        script_hex!("001480da730eb450099517b27d94a1073888290b8c5b"),
        Amount::from_sat(401048),
        true,
        "tb1qeptvfh9d232z7d8s3zdqcy4v72237vgyep2qnk9hqwrmhvhf2fsscys5s8",
        Amount::from_sat(401048 - 300),
    )?;
    println!("{}", txid);
    Ok(())
}

fn redeem_script() -> ScriptBuf {
    // the full unlocking script: 1 1 <ADD 2 EQUAL>

    ScriptBuf::builder()
        .push_opcode(OP_ADD)
        .push_int(2)
        .unwrap()
        .push_opcode(OP_EQUAL)
        .into_script()
}

#[cfg(test)]
mod test {
    use crate::redeem_script;
    use bitcoin::{Address, KnownHrp, WitnessProgram};
    use bitcoin_demo::{sha256, EncodeHex};

    #[test]
    fn test() {
        let redeem = redeem_script();
        let redeem_hash = sha256(redeem.as_bytes());
        let program = WitnessProgram::p2wsh(&redeem).unwrap();
        assert_eq!(program.program().as_bytes(), redeem_hash);

        let redeem = redeem_script();
        let p2wsh = Address::p2wsh(&redeem, KnownHrp::Testnets).unwrap();
        assert_eq!(
            p2wsh.to_string(),
            "tb1qeptvfh9d232z7d8s3zdqcy4v72237vgyep2qnk9hqwrmhvhf2fsscys5s8"
        );

        assert_eq!(redeem.hex(), "935287");
    }
}
