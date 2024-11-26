use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin_demo::sha256;
use num_bigint::BigUint;
use num_traits::{Euclid, Num, One, ToPrimitive, Zero};
use once_cell::sync::Lazy;
use rand::rngs::OsRng;

const CHARSET: &str = include_str!("../a.txt");

static CHARS: Lazy<Vec<char>> = Lazy::new(|| CHARSET.chars().collect());

fn main() {
    let secp: Secp256k1<_> = Default::default();
    let keypair = Keypair::new(&secp, &mut OsRng);
    let message = "hello";
    let signature =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sha256(message.as_bytes())), &keypair);
    let signature = signature.serialize();
    let mut int = BigUint::from_bytes_be(&signature);
    let radix = BigUint::from(1000_u32);
    let one = BigUint::one();
    let mut radix_digits = Vec::new();
    loop {
        let (div, rem) = int.div_rem_euclid(&radix);
        int = div;
        radix_digits.push(rem.to_usize().unwrap());
        if int.is_zero() {
            break;
        }
    }
    radix_digits.reverse();

    let sig_string = radix_digits
        .iter()
        .map(|&x| (&*CHARS)[x])
        .collect::<String>();
    println!("{}", sig_string);
}
