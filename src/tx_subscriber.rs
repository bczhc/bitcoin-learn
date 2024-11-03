use bitcoin::consensus::deserialize;
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::opcodes::OP_0;
use bitcoin::script::ScriptExt;
use bitcoin::{Script, Transaction};
use zmq::SocketType;

fn main() -> anyhow::Result<()> {
    let zmq = zmq::Context::new();
    let socket = zmq.socket(SocketType::SUB)?;
    socket.connect("tcp://127.0.0.1:28332")?;
    socket.set_subscribe(b"rawtx")?;
    loop {
        let msg = socket.recv_msg(0)?;
        let bytes = msg.as_ref();
        let Ok(tx) = deserialize::<Transaction>(bytes) else {
            continue;
        };
        let txid = tx.compute_txid();
        for x in tx.output {
            let s = x.script_pubkey;
            if s.is_op_return() {
                let vec = s
                    .as_bytes()
                    .iter()
                    .filter(|&&x| x.is_ascii() && !x.is_ascii_control() && x != b'\n' && x != b'\r')
                    .copied()
                    .collect::<Vec<_>>();
                let str = std::str::from_utf8(&vec).unwrap();
                println!("{txid} {}", str);
            }
        }
    }
    Ok(())
}

fn filter_script(s: &Script) -> bool {
    !(s.is_p2pkh()
        || s.is_p2sh()
        || s.is_p2wpkh()
        || s.is_op_return()
        || s.first_opcode() == Some(OP_PUSHNUM_1)
        || s.first_opcode() == Some(OP_0))
}
