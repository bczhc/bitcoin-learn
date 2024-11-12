use bitcoin::opcodes::all::{OP_CLTV, OP_DROP};
use bitcoin::opcodes::OP_TRUE;
use bitcoin::script::ScriptBufExt;
use bitcoin::transaction::Version;
use bitcoin::{
    absolute, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TestnetVersion, Transaction,
    TxIn, TxOut, Witness,
};
use bitcoin_demo::{confirm_to_broadcast, BitcoinAmountExt, ScriptsBuilderExt};

fn main() -> anyhow::Result<()> {
    let timestamp = "2024-10-21T17:00:00+08:00"
        .parse::<chrono::DateTime<chrono::Utc>>()?
        .timestamp() as u32;
    let lock_time = absolute::LockTime::Seconds(absolute::Time::from_consensus(timestamp)?);
    let redeem = ScriptBuf::builder()
        .push_lock_time(lock_time)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_opcode(OP_TRUE)
        .into_script();

    let outpoint = OutPoint {
        txid: "c3a5d5bbf463a62d2c6fe89fd49c121f858bbb75682f8dddac4e7a6c5ad1cff3".parse()?,
        vout: 0,
    };
    let tx = Transaction {
        version: Version::ONE,
        lock_time,
        input: vec![TxIn {
            previous_output: outpoint,
            witness: Witness::default(),
            sequence: Sequence::ENABLE_LOCKTIME_AND_RBF,
            script_sig: ScriptBuf::builder()
                .push_slice_try_from(redeem.as_bytes())?
                .into_script(),
        }],
        output: vec![TxOut {
            value: Amount::DUST_MIN,
            script_pubkey: "mqM4hh3AcH5CGwpqNo5Cs9h2GqUpTyPXb5"
                .parse::<Address<_>>()?
                .require_network(Network::Testnet(TestnetVersion::V4))?
                .script_pubkey(),
        }],
    };

    confirm_to_broadcast(&tx);
    Ok(())
}
