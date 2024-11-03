use bitcoin_demo::confirm_to_broadcast_raw;
use std::env::args;

fn main() {
    let args = args().skip(1).collect::<Vec<_>>();
    let hex = &args[0];

    confirm_to_broadcast_raw(&hex::decode(hex).expect("Invalid Hex"));
}
