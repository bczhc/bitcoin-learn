use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1;
use bitcoin_demo::EncodeHex;
use num_bigint::BigUint;

fn main() {
    // the order value of secp256k1: p=2^256-2^32-977
    let p = {
        let p = BigUint::from(2_u8);
        p.pow(256) - p.pow(32) - BigUint::from(977_u32)
    };

    println!("Bisecting...");
    let mut left = BigUint::from(1_u8);
    let mut right = p.clone();
    let two = BigUint::from(2_u8);
    let one = BigUint::from(1_u8);
    let mut mid = left.clone();
    while left <= right {
        mid = (&left + &right) / &two;
        let result = secret_from_num(&mid).is_ok();
        if result {
            left = &mid + &one;
        } else {
            right = &mid - &one;
        }
    }
    let invalid = mid.clone();
    // 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    println!("{}", padded_bytes_from_bigint_be::<32>(&invalid).as_hex());
    let valid = &mid - &one;
    // 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
    println!("{}", padded_bytes_from_bigint_be::<32>(&valid).as_hex());

    assert!(!secret_from_num(&invalid).is_ok());
    assert!(secret_from_num(&valid).is_ok());
}

fn padded_bytes_from_bigint_be<const SIZE: usize>(n: &BigUint) -> [u8; SIZE] {
    let be = n.to_bytes_be();
    let mut data = [0_u8; SIZE];
    data[(SIZE - be.len())..].copy_from_slice(&be);
    data
}

fn secret_from_num(n: &BigUint) -> anyhow::Result<secp256k1::SecretKey> {
    let data = padded_bytes_from_bigint_be::<32>(n);
    Ok(secp256k1::SecretKey::from_slice(&data)?)
}
