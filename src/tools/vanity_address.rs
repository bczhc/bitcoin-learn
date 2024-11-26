use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, NetworkKind, PrivateKey, PubkeyHash};
use rand::rngs::OsRng;
use rand::RngCore;
use std::thread::scope;
use std::{fmt, mem};

type Key = (u128, u128);

fn as_key_array(key: &mut Key) -> &mut [u8; 32] {
    unsafe { mem::transmute(key) }
}

fn main() {
    assert_eq!(size_of::<Key>(), 256 / 8);

    let jobs = num_cpus::get();
    let start = "1Cafe";
    scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| {
                let mut initial = (0_u128, 0_u128);
                OsRng.fill_bytes(as_key_array(&mut initial));
                let secp: Secp256k1<_> = Default::default();
                let mut addr_buf = String::with_capacity(50);
                loop {
                    // TODO: use uncheck
                    unsafe {
                        let pk =
                            PrivateKey::from_slice(as_key_array(&mut initial), NetworkKind::Main)
                                .unwrap_unchecked();
                        let addr = Address::p2pkh(pk.public_key(&secp), NetworkKind::Main);
                        use fmt::Write;
                        unsafe {
                            addr_buf.clear();
                            write!(&mut addr_buf, "{}", addr).unwrap_unchecked();
                            if addr_buf.starts_with(start) {
                                println!("{} {}", addr_buf, pk.to_wif())
                            }
                        }
                        initial.0 += 1;
                    }
                }
            });
        }
    });
}
