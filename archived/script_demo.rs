use bitcoin::opcodes::all::{OP_DROP, OP_SWAP};
use bitcoin::opcodes::OP_FALSE;
use bitcoin::script::{ScriptBufExt, ScriptExt};
use bitcoin::{Address, Network, ScriptBuf};
use bitcoin_demo::{bitcoin_rpc, EncodeHex};
use bitcoincore_rpc::RpcApi;
use hex_literal::hex;

fn main() -> anyhow::Result<()> {
    // let pkh = hex!("00 ab68025513c3dbd2f7b92a94e0581f5d50f654e7");
    // println!("{}", bitcoin::base58::encode_check(&pkh));
    //
    // let pkh: [u8; 20] = pkh[1..21].try_into().unwrap();
    // let script = ScriptBuf::builder()
    //     .push_opcode(OP_DUP)
    //     .push_opcode(OP_HASH160)
    //     .push_slice(pkh)
    //     .push_opcode(OP_EQUALVERIFY)
    //     .push_opcode(OP_CHECKSIG)
    //     .into_script();
    // println!("{}", script);
    //
    // println!("{:?}", Address::from_script(&script, Network::Bitcoin));
    // println!("{:?}", Address::p2sh(&script, Network::Bitcoin));
    //
    // // OP_DUP OP_HASH160 OP_PUSHBYTES_20 dbd0788d294dd15704d232053790c555d1cb3378 OP_EQUALVERIFY OP_CHECKSIG
    //
    // let script = ScriptBuf::builder().push_opcode(OP_TRUE).into_script();
    // println!("{:?}", Address::from_script(&script, Network::Bitcoin));
    // println!("{:?}", Address::p2sh(&script, Network::Bitcoin));
    //
    // let script = ScriptBuf::builder().push_opcode(OP_EQUAL).into_script();
    // println!("{:?}", Address::p2sh(&script, Network::Bitcoin));
    //
    // let script = ScriptBuf::builder().push_opcode(OP_OR).into_script();
    // println!("{:?}", Address::p2sh(&script, Network::Bitcoin));
    //
    // let mut vec = hex::decode("51510187").unwrap();
    // println!("{}", ScriptBuf::from_bytes(vec));
    //
    // let asm = hex!("483045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e381301410484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf76a9147f9b1a7fb68d60c536c2fd8aeaa53a8f3cc025a888ac");
    // // println!("{:?}", ScriptBuf::consensus_decode(&mut Cursor::new(asm)));
    //
    // let mut x = hex!("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000");
    // x.reverse();
    // println!("{}", hex::encode(x));
    //
    // println!(
    //     "{}",
    //     hash160(&hex!("0484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf")).hex()
    // );
    //
    // println!(
    //     "{}",
    //     BigUint::from_bytes_be(&hex!(
    //         "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    //     ))
    // );
    //
    // let script = ScriptBuf::builder().push_opcode(OP_RETURN).into_script();
    // dbg!(script);
    //
    // let mut vec = hex::decode("6e879169a87ca8878787").unwrap();
    // let script = ScriptBuf::from_bytes(vec);
    // println!("{}", script);
    // println!("{:?}", Address::p2sh(&script, Network::Bitcoin));
    //
    // println!("--------------------------");
    //
    // // OP_SHA256 OP_PUSHDATA1 32 0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 OP_EQUAL
    // let script = ScriptBuf::builder()
    //     .push_opcode(OP_SHA256)
    //     .push_opcode(OP_PUSHBYTES_1)
    //     .push_int(32)
    //     .push_slice(hex!(
    //         "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    //     ))
    //     .push_opcode(OP_EQUAL)
    //     .into_script();
    // println!("{}", script);
    // println!("{:?}", Address::p2sh(&script, Network::Bitcoin));
    // println!("{:?}", Address::p2sh(&script, Network::Testnet));
    //
    // let a = hash160(&hex!("0484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf"));
    // println!("{}", a.len());
    // println!("{}", hex::encode(a));
    //
    // println!(
    //     "{}",
    //     ScriptBuf::from_bytes(
    //         hex!("5120e1444f1f99f715d53bb5ba5a2703fa09a3601b2144ed3f1f902fcf54e3f8ded8").to_vec()
    //     )
    // );
    //
    // let buf = ScriptBuf::builder().push_opcode(OP_TRUE).into_script();
    // println!("{}", buf);
    // println!("{:?}", Address::p2sh(&buf, Network::Bitcoin));
    //
    // let buf = ScriptBuf::builder()
    //     .push_slice(b"hello")
    //     .push_opcode(OP_EQUAL)
    //     .into_script();
    // println!("{}", buf);
    // println!("{}", buf.script_hash());
    // println!("{:?}", Address::p2sh(&buf, Network::Bitcoin));
    //
    // // p2sh:
    // // <unlock-script> <redeem-script> <sh> HASH160 EQUALVERIFY
    //
    // let transaction = Transaction {
    //     lock_time: LockTime::Blocks(Height::MIN),
    //     version: Version::TWO,
    //     input: vec![],
    //     output: vec![],
    // };
    // println!("{:?}", transaction);

    let client = bitcoin_rpc()?;
    println!("{:?}", client.get_block_count());

    let script_buf = ScriptBuf::builder().push_opcode(OP_SWAP).into_script();
    println!("{}", script_buf.script_hash().as_ref()?.hex());
    println!("{:?}", Address::p2sh(&script_buf, Network::Bitcoin));

    println!(
        "{}",
        ScriptBuf::from(hex!("a914726ba1c09c5a72a64a64c42ae2160d4c201398d887").to_vec())
            .to_asm_string()
    );

    Ok(())
}
