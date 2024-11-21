#![feature(decl_macro)]
extern crate core;

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::PrivateKey;
use hex_literal::hex;
use num_bigint::BigUint;
use num_traits::Num;

/// Elliptic curve function: y^2==x^3+7 (mod p)
fn verify_point(x: &BigUint, y: &BigUint, p: &BigUint) -> bool {
    let lhs = (x.pow(3) + BigUint::from(7_u8)).modpow(&BigUint::from(1_u8), p);
    let rhs = y.modpow(&2_u8.into(), p);
    lhs == rhs
}

fn main() -> anyhow::Result<()> {
    macro hex_num($x:literal) {
        BigUint::from_str_radix($x, 16)?
    }
    let gx = hex_num!("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let gy = hex_num!("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    let p = hex_num!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    let secret = hex_num!("5436a60b428ddc101497d6231c8c13926f44ab8c9d42d1b2d7ef38673cc7e170");
    // K = k.G

    assert!(verify_point(&gx, &gy, &p));

    let secret = hex!("0000000000110011000000000000110000001100000110001111110000000011");
    let secret = SecretKey::from_slice(&secret)?;
    let secp = Secp256k1::default();

    let signature = bitcoin::sign_message::sign(&secp, b"hello", secret);
    println!("{}", signature);

    Ok(())
}

// fn main() -> anyhow::Result<()> {
//     // let secret = random_secret_key();
//     // let public_key = secret.public_key(&Default::default());
//     // let bytes = public_key.serialize();
//     // println!("{} {}", bytes[0..1].as_hex(), bytes[1..(1 + 32)].as_hex(),);
//     // let bytes = public_key.serialize_uncompressed();
//     // println!(
//     //     "{} {} {}",
//     //     bytes[0..1].as_hex(),
//     //     bytes[1..(1 + 32)].as_hex(),
//     //     bytes[33..(33 + 32)].as_hex()
//     // );
//
//     // let x_point = hex!("a53eef437db4ad9bc02ac62d81f318bfc3a60587afdb5e171defce18fd6bc1d6");
//     // let prefix = 0x03_u8;
//     // let mut serialized = vec![0_u8; x_point.len() + 1];
//     // serialized[0] = prefix;
//     // serialized[1..].copy_from_slice(&x_point);
//     // let pk = secp256k1::PublicKey::from_slice(&serialized)?;
//     // println!("{}", pk.serialize_uncompressed()[33..].as_hex());
//
//     // let secp: Secp256k1<_> = Default::default();
//     // loop {
//     //     let secret = random_secret_key();
//     //     let message = Message::from_digest(sha256(secret.as_ref()));
//     //     let signature = secp.sign_ecdsa(&message, &secret);
//     //     println!("{}", signature.serialize_der().hex().len() / 2);
//     // }
//     // let secret = SecretKey::from_slice(&hex!(
//     //     "0000000000110011000000000000110000001100000110001111110000000011"
//     // ))
//     // .unwrap();
//     // let secp: Secp256k1<_> = Default::default();
//     // let public_key = secret.public_key(&secp);
//     //
//     // let message = "a";
//     // let signing_message = Message::from_digest(sha256d(message.as_bytes()));
//     // let signature = secp.sign_ecdsa(&signing_message, &secret);
//     // let der = signature.serialize_der().hex();
//     // let public_hex = public_key.serialize().hex();
//     // println!("Signature (DER): {der}");
//     // println!("PublicKey: {public_hex}");
//     //
//     // println!("----------- VERIFY ----------");
//     // let signature = Signature::from_der(&hex::decode(der).unwrap()).unwrap();
//     // let public_key = PublicKey::from_slice(&hex::decode(public_hex).unwrap()).unwrap();
//     // let result = secp.verify_ecdsa(&signing_message, &signature, &public_key);
//     // println!("{:?}", result);
//
//     // 3044
//     // 0220
//     // 2a0e77d63e56168565419cc4bc2d4b8ac6a69ad6e5a5281afb808c83ce049654 - R
//     // 0220
//     // 2d15c440340389af6f7e8f8d23e280cd2e1a57033dc651c9fb073c1adbdab30d - S
//     // SIG_HASH
//     // 6 + 32 + 32 + 1 = 71
//
//     // let signature = base64::decode(
//     //     "HzJGfhWMs7sGgDNszYhpSsbYVk7V3MYwsJokFok2gEn7a6PnJ1xTsCM6dnedYKSEfldu23O1FoNQw/FG5aA1Jfc=",
//     // )?;
//     // println!("{}", signature.hex());
//     // 1f32467e158cb3bb0680336ccd88694ac6d8564ed5dcc630b09a241689368049fb6ba3e7275c53b0233a76779d60a4847e576edb73b5168350c3f146e5a03525f7
//     Ok(())
// }
