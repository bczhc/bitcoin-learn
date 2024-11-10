use bitcoin::address::script_pubkey::ScriptBufExt;
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use bitcoin_demo::{default_tx, EncodeHex};

const FEE: Amount = Amount::from_sat(300);

fn main() -> anyhow::Result<()> {
    let wif = "";
    let outpoint = OutPoint {
        txid: "f3cb85076bc17986fd4abd7db6c3ef8c9c1c50fbd086c32d1c26ada04c26fc4b".parse()?,
        vout: 1,
    };

    let tx = default_tx();
    tx.input[0].previous_output = outpoint;
    tx.output = vec![TxOut {
        value: Amount::from_sat(401648) - FEE,
        script_pubkey: ScriptBuf::new_p2wpkh(),
    }];
    Ok(())
}
