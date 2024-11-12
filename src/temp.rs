use bitcoin::opcodes::all::OP_EQUAL;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::script::ScriptBufExt;
use bitcoin::{Address, KnownHrp, ScriptBuf};
use std::io::stdout;

fn main() -> anyhow::Result<()> {
    let writer = stdout();
    let writer = writer.lock();
    let mut csv = csv::Writer::from_writer(writer);
    csv.write_record(&["Header"]).unwrap();

    loop {
        csv.write_record(&["1"])?;
    }
    Ok(())
}
