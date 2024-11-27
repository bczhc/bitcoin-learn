use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, NetworkKind, PrivateKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::alloc::Layout;
use std::thread::scope;
use std::{fmt, mem};

type Key = (u128, u128);

#[inline(always)]
fn increase_sk(secret_key: &mut SecretKey) {
    unsafe {
        let num: &mut (u128, u128) = mem::transmute(secret_key);
        num.0 += 1;
    }
}

fn main() {
    assert_eq!(size_of::<Key>(), 256 / 8);
    assert_eq!(Layout::new::<SecretKey>(), Layout::new::<[u8; 256 / 8]>());

    let jobs = num_cpus::get();
    let start = "1Arch";
    scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| unsafe {
                let mut initial = [0_u8; 32];
                OsRng.fill_bytes(&mut initial);
                let sk: SecretKey = mem::transmute_copy(&initial);
                let mut prk = PrivateKey {
                    compressed: true,
                    network: NetworkKind::Main,
                    inner: sk,
                };
                let secp: Secp256k1<_> = Default::default();
                let mut addr_buf = String::with_capacity(50);
                loop {
                    let addr = Address::p2pkh(prk.public_key(&secp), NetworkKind::Main);
                    use fmt::Write;
                    addr_buf.clear();
                    write!(&mut addr_buf, "{}", addr).unwrap_unchecked();
                    if addr_buf.starts_with(start) {
                        // validate secret key
                        SecretKey::from_slice(prk.inner.as_ref()).unwrap();
                        let address = addr.to_string();
                        println!("{} {}", address, prk.to_wif())
                    }
                    increase_sk(&mut prk.inner);
                }
            });
        }
    });
}
