//! This creates the transaction: <https://mempool.space/testnet4/tx/ac59228a274c628cb9142fb50f39df911ccecd3f71192dbb25730731b0846565>

use bitcoin::absolute::LockTime;
use bitcoin::address::script_pubkey::BuilderExt;
use bitcoin::address::{script_pubkey, ParseError};
use bitcoin::opcodes::OP_FALSE;
use bitcoin::script::{PushBytes, ScriptBufExt, ScriptExt};
use bitcoin::secp256k1::Message;
use bitcoin::transaction::Version;
use bitcoin::{
    consensus, Address, Amount, EcdsaSighashType, Network, NetworkKind, OutPoint, PrivateKey,
    ScriptBuf, Sequence, TestnetVersion, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_demo::{confirm_to_broadcast, script_hex, sha256d, BitcoinAmountExt};
use byteorder::{WriteBytesExt, LE};

const FEE: Amount = Amount::from_sat(300);

fn main() -> anyhow::Result<()> {
    /* ========== INPUTS ========== */
    let sender_wif = "cQ7WLKEA4s3DEEuv1yQ7saQZ8dD9vH47Ej8xecVfsTAiMRFEp31z";
    let input_outpoint_txid = "861d27b5493061a6fb12c19b94d18cdb1c5048e2f4e36c1b93106eaf96fa0da6";
    let input_outpoint_index = 1;
    let input_utxo_total_amount = Amount::from_sat(455000);
    let receiver_amount = Amount::DUST_MIN;
    /* ============================= */

    let network = Network::Testnet(TestnetVersion::V4);
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let sender_prk = PrivateKey::from_wif(sender_wif)?;
    assert_eq!(sender_prk.network, NetworkKind::Test);

    let sender_address = Address::p2pkh(sender_prk.public_key(&secp), network);

    let mut tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::from_consensus(0),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: input_outpoint_txid.parse()?,
                vout: input_outpoint_index,
            },
            script_sig: ScriptBuf::new(), /* placeholder */
            sequence: Sequence::FINAL,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: receiver_amount,
                script_pubkey: script_pubkey::ScriptBufExt::new_p2sh(
                    ScriptBuf::builder()
                        .push_opcode(OP_FALSE)
                        .into_script()
                        .script_hash()?, /* some random unspendable outputs */
                ),
            },
            // and, don't forget the change!! Or you'll pay all the rest as fee to miners.
            TxOut {
                value: input_utxo_total_amount - receiver_amount - FEE,
                script_pubkey: sender_address.script_pubkey(),
            },
        ],
    };

    // We only have one input, so no need to truncate other inputs.
    // Before signing. The input scriptSig should be set to the outpoint scriptPubKey.
    // I just copy & paste it from the blockchain explorer.
    tx.input[0].script_sig =
        script_hex!("76a914b255f786aa697139fdcd7bd82eabfb0b74ee11ef88ac").into();
    let mut serialized = consensus::serialize(&tx);
    // append the sighash flag as a u32-le to the signing message
    serialized.write_u32::<LE>(EcdsaSighashType::All as u32)?;
    let message = sha256d(&serialized);
    let message = Message::from_digest(message);
    let sender_puk = sender_prk.public_key(&secp);
    let signature = secp.sign_ecdsa(&message, &sender_prk.inner);

    let mut tx_sig = signature.serialize_der().to_vec();
    // Append the sighash flag again to the DER sequence. Since then, it becomes
    // the signature in Bitcoin's format (<DER> <SIGHASH_FLAG>).
    tx_sig.push(EcdsaSighashType::All as u8);

    // The unlocking script. Format: <signature> <sender-pubkey>
    let script_sig = ScriptBuf::builder()
        .push_slice(<&PushBytes as TryFrom<&[u8]>>::try_from(&tx_sig)?)
        .push_key(sender_puk)
        .into_script();
    // Put the signature back to script_sig,
    // then we can broadcast it now!
    tx.input[0].script_sig = script_sig;

    confirm_to_broadcast(&tx);
    Ok(())
}

fn parse_address(address: &str) -> Result<Address, ParseError> {
    address
        .parse::<Address<_>>()?
        .require_network(Network::Testnet(TestnetVersion::V4))
}

fn op_return_script(msg: &[u8]) -> anyhow::Result<ScriptBuf> {
    Ok(ScriptBuf::new_op_return(<&PushBytes>::try_from(msg)?))
}
