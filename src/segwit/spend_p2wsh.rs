//! <https://mempool.space/testnet4/tx/7501e19cc1c97e4a7f41bf5b7a9364d45a08353de543de5c9f8d5c19d27237b3>

use bitcoin::{Amount, TxOut, Witness};
use bitcoin_demo::{broadcast_tx, default_tx, ideal_checked_op_return, parse_address, TESTNET4};
use hex_literal::hex;

fn main() -> anyhow::Result<()> {
    let outpoint = "0fd7658a90b3d86051d4656d15ca11d5f548c40ab8b50bf486c7dedfcdd70986:0";

    let mut tx = default_tx();
    tx.input[0].previous_output = outpoint.parse()?;
    tx.output = vec![
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ideal_checked_op_return("花费P2WSH测试 bczhc".as_bytes()),
        },
        TxOut {
            value: Amount::from_sat(400748 - 300),
            script_pubkey: parse_address("tb1qsrd8xr452qye29aj0k22zpec3q5shrzms98rj8", TESTNET4)?
                .script_pubkey(),
        },
    ];

    let mut witness = Witness::new();
    // witness.push(ScriptBuf::builder().push_int(1)?.push_int(1)?.as_bytes());
    witness.push(&[0x01]);
    witness.push(&[0x01]);
    let redeem_bytes = hex!("935287") /* ADD 2 EQUAL */;
    witness.push(redeem_bytes);

    tx.input[0].witness = witness;

    println!("{:?}", broadcast_tx(&tx));

    Ok(())
}
