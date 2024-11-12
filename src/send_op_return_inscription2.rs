#![feature(decl_macro)]

//! This sample tried to put an AVIF image on the chain by sending multiple transactions
//! with OP_RETURN data.
//!
//! Diagram:
//!
//! ```text
//!      │
//!      │
//!      │
//! ┌────┼┐       ┌───────────┐
//! │ TxO│├──────►│    Tx1    ├───►OP_RETURN
//! └────┼┘       │           ├──┐   ┌───────────┐
//!      │        └───────────┘  └──►│    Tx2    ├───►OP_RETURN
//!      │                           │           ├──┐  ┌───────────┐
//!      │                           └───────────┘  └─►│    Tx3    ├───►OP_RETURN
//!      │                                             │           ├───┐
//!      │                                             └───────────┘   │
//!      │                                                             ▼(change)
//!      │                                                            UTXO
//!      │
//! ```
//!
//! Get the data by joining Tx1:0, Tx2:0, Tx3:0 and so on.
//!
//! This will work. But when flushing so many chained transactions to the network,
//! a new error will encounter:
//!
//! `too-long-mempool-chain, too many unconfirmed ancestors [limit: 25]`
//!
//! Though chained transactions are ordered, I still write the order message for intuition when
//! looked up in a blockchain explorer (the flat displaying style).
//!
//! This is similar to
//! <https://mempool.space/address/bc1q3ez0mu6q3y59emtl2nweeevnhu7ualvu3ylapp>.
//!
//! Also see notes: `fetch-op-return-image.md`.
//!
//! Ehh. However, the extra message is too long to be fitted in a single OP_RETURN data. So split
//! them more using [`split_message`].
//!
//! <https://mempool.space/testnet4/tx/6a2998062461aed0c273966b3869404418f5cd399d3ba56748a156c169a9381b>

use bitcoin::script::{PushBytes, ScriptBufExt};
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut};
use bitcoin_demo::{
    broadcast_tx_retry, default_tx, estimate_fee, parse_address, signing_helper, EncodeHex,
    OP_RETURN_IDEAL_MAX, TESTNET4,
};

const OUTPUT_OP_RETURN_LIMIT: usize = 75;
const NETWORK: Network = TESTNET4;

fn main() -> anyhow::Result<()> {
    let data = include_bytes!("../res/a.avif");
    let extra_data = split_message(
        &format!(
            r#"按Order拼接得a.avif({}B) Order: {}."#,
            data.len(),
            prefix_order_list(data)
        ),
        OP_RETURN_IDEAL_MAX,
    )
    .into_iter()
    .map(Vec::from);
    let chunks = data.chunks(OUTPUT_OP_RETURN_LIMIT).map(|x| x.to_vec());

    let wif = "cVCag3xvtzb5KqYehrKwSWtfQbvX7cLifTfqGLDAwZkucMvRSE13";
    let address = "mi2Me4PgHjeJqEuuAv7veiQG7YJkrGSfj5";
    let mut outpoint = OutPoint {
        txid: "cb43d297090352ea906a0e9c2ed0ea316ef5c7a3bc8e786fe269a312282a0d83".parse()?,
        vout: 0,
    };
    let mut amount = Amount::from_sat(443650);

    for data in extra_data.chain(chunks) {
        assert!(data.len() <= OP_RETURN_IDEAL_MAX);
        let mut tx = default_tx();

        tx.input[0].previous_output = outpoint;
        tx.output = vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return(<&PushBytes>::try_from(data.as_slice())?),
            },
            // change
            TxOut {
                value: Amount::ZERO, /* placeholder */
                script_pubkey: parse_address(address, TESTNET4)?.script_pubkey(),
            },
        ];
        let fee = estimate_fee(&tx);
        tx.output[1].value = amount - fee;
        amount = tx.output[1].value;

        signing_helper::one_input_sign(
            wif,
            &mut tx,
            parse_address(address, NETWORK)?.script_pubkey(),
        )?;

        let new_txid = broadcast_tx_retry(&tx);
        println!("Sent: {}", new_txid);
        outpoint.txid = new_txid;
        outpoint.vout = 1;
    }
    Ok(())
}

fn prefix_list(data: &[u8]) -> Vec<String> {
    let chunks = data.chunks(OP_RETURN_IDEAL_MAX).collect::<Vec<_>>();
    let mut prefix_list = Vec::new();
    let hex_list = chunks.iter().map(|x| x.hex()).collect::<Vec<_>>();

    for hex in &hex_list {
        for len in 1..=hex.len() {
            let test_prefix = &hex[..len];
            let prefix_match_count = hex_list
                .iter()
                .filter(|x| x.starts_with(test_prefix))
                .count();
            if prefix_match_count == 1 {
                prefix_list.push(test_prefix.into());
                break;
            }
        }
    }

    prefix_list
}

fn prefix_order_list(data: &[u8]) -> String {
    prefix_list(data).join("-")
}

pub fn split_message(text: &str, max_len: usize) -> Vec<String> {
    if text.is_empty() {
        return vec!["M0 ".into()];
    }
    // to be UTF8-aware
    let mut chars = text.chars().peekable();
    let mut i = 0;
    let mut message = String::new();
    let mut message_list = Vec::new();
    loop {
        let prefix = format!("M{i} ");
        message.push_str(&prefix);
        loop {
            let Some(&c) = chars.peek() else { break };
            if message.len() + c.len_utf8() > max_len {
                break;
            }
            message.push(chars.next().unwrap() /* we already peeked it */);
        }
        // message is filled full this time
        if message.strip_prefix(&prefix).unwrap().is_empty() {
            // But, if the message still doesn't add anything, this function call is impossible.
            // Here's an example:
            // text: "你", max_len: 5
            // The character "你" (takes 3 bytes in UTF-8) can't be fitted in the template
            // "M0 {}" where the total size is constrained to 5 bytes. The minimal string that
            // can be constructed is "M0 你" which takes 6 bytes.
            panic!("max_len is unexpectedly too small")
        }
        message_list.push(message);
        message = String::new();
        i += 1;
        // to the text end
        if chars.peek().is_none() {
            return message_list;
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn split_message() {
        assert_eq!(super::split_message("", 5), vec!["M0 "]);
        assert_eq!(super::split_message("h", 5), vec!["M0 h"]);
        assert_eq!(super::split_message("he", 5), vec!["M0 he"]);
        assert_eq!(super::split_message("hel", 5), vec!["M0 he", "M1 l"]);
        assert_eq!(super::split_message("hell", 5), vec!["M0 he", "M1 ll"]);
        assert_eq!(
            super::split_message("hello", 5),
            vec!["M0 he", "M1 ll", "M2 o"]
        );
        assert_eq!(super::split_message("你", 6), vec!["M0 你"]);
        assert_eq!(super::split_message("a你", 6), vec!["M0 a", "M1 你"])
    }

    #[test]
    #[should_panic]
    fn split_message_panic() {
        super::split_message("你", 5);
    }
}
