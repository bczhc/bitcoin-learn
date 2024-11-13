use bitcoin_demo::{EncodeHex, WITNESS_ITEM_MAX};

fn main() -> anyhow::Result<()> {
    let data = include_bytes!("../res/a.avif");
    println!(
        "{}",
        data.chunks(WITNESS_ITEM_MAX)
            .map(|x| x.hex())
            .collect::<Vec<_>>()
            .join(",")
    );
    Ok(())
}
