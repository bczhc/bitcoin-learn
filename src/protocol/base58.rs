//! Generate p2pkh vanity addresses.

use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, NetworkKind, PrivateKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt;
use std::thread::scope;

fn main() {
    scope(|s| {
        for _ in 0..num_cpus::get() {
            s.spawn(move || {
                let mut rng = OsRng;
                let mut ec = [0_u8; 256 / 8];
                let secp: Secp256k1<_> = Default::default();
                let mut address_string = String::with_capacity(30);
                loop {
                    rng.fill_bytes(&mut ec);
                    let Ok(key) = PrivateKey::from_slice(&ec, NetworkKind::Main) else {
                        continue;
                    };
                    let address = Address::p2pkh(key.public_key(&secp), NetworkKind::Main);
                    use fmt::Write;
                    address_string.clear();
                    write!(&mut address_string, "{}", address).unwrap();
                    let predicate = address_string
                        .as_bytes()
                        .iter()
                        .all(|&x| char::from(x).is_ascii_lowercase());
                    // let predicate = address_string.starts_with("1Archive");
                    // let predicate = address_string.starts_with("1Ninj");
                    if predicate {
                        println!("{} {}", address, key.to_wif());
                    }
                }
            });
        }
    });
}
