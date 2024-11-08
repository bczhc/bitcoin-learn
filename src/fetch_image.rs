use bitcoin::{Network, Script};
use bitcoin_demo::{block_parser_recent, extract_op_return};
use bitcoincore_rpc::bitcoin as old_bitcoin;
use pretty_hex::PrettyHex;
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;

fn main() -> anyhow::Result<()> {
    let parser = block_parser_recent(1 * 30 * 24 * 60 / 10 /* 1 month */);
    let address = "bc1q3ez0mu6q3y59emtl2nweeevnhu7ualvu3ylapp";
    let address_spk = address
        .parse::<bitcoin::Address<_>>()?
        .require_network(Network::Bitcoin)?
        .script_pubkey();
    let mut tx_set: HashSet<bitcoincore_rpc::bitcoin::OutPoint> = HashSet::new();
    for (_h, block) in parser {
        for tx in block.txdata {
            for (i, txo) in tx.output.iter().enumerate() {
                if txo.script_pubkey.as_bytes() == address_spk.as_bytes() {
                    tx_set.insert(old_bitcoin::OutPoint {
                        txid: tx.compute_txid(),
                        vout: i as u32,
                    });
                }
            }
        }
    }

    let mut tx_vec = Vec::new();

    let parser = block_parser_recent(1 * 30 * 24 * 60 / 10 /* 1 month */);
    for (_h, block) in parser {
        for tx in block.txdata.into_iter().filter(|x| {
            x.input.len() == 1
                && tx_set.contains(&x.input[0].previous_output)
                && x.output
                    .iter()
                    .filter(|x| x.script_pubkey.is_op_return())
                    .count()
                    == 1
        }) {
            tx_vec.push(tx);
        }
    }

    assert_eq!(tx_vec.len(), 25);
    let parsed_op_return = tx_vec
        .into_iter()
        .map(|tx| {
            let script_pubkey = &tx
                .output
                .iter()
                .find(|txo| txo.script_pubkey.is_op_return())
                .unwrap()
                .script_pubkey;
            let extracted =
                extract_op_return(Script::from_bytes(script_pubkey.as_bytes())).unwrap();
            match std::str::from_utf8(extracted) {
                Ok(s) => OpReturnData::Printable(s.into()),
                Err(_) => OpReturnData::Binary(extracted.into()),
            }
        })
        .collect::<Vec<_>>();

    let mut binary_vec = Vec::new();
    let mut order = Vec::default();
    for x in &parsed_op_return {
        match x {
            OpReturnData::Printable(s) => {
                println!("Message: {s}");
                if s.starts_with("Order") {
                    let split = s.strip_prefix("Order").unwrap().split('-');
                    order = split.collect::<Vec<_>>();
                }
            }
            OpReturnData::Binary(b) => {
                binary_vec.push(b.as_slice());
            }
        }
    }

    println!("Order: {:?}", order);

    let mut joined_binary = Vec::new();
    for hex_start in order {
        let mut filter = binary_vec
            .iter()
            .filter(|&&x| hex::encode_upper(x).starts_with(hex_start));
        let found = filter.next().unwrap();
        assert!(
            filter.next().is_none(),
            "Only one hex array is expected to be matched"
        );
        found.iter().for_each(|&x| joined_binary.push(x));
    }

    println!("{:?}", joined_binary.hex_dump());

    let mut out = File::create("/tmp/image.avif")?;
    out.write_all(&joined_binary)?;

    Ok(())
}

enum OpReturnData {
    Printable(String),
    Binary(Vec<u8>),
}
