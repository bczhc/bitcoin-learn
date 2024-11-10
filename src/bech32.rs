//! - https://en.bitcoin.it/wiki/BIP_0173

use bech32::primitives::checksum;
use bech32::primitives::encode::Encoder;
use bech32::primitives::iter::Checksummed;
use bech32::{Bech32, ByteIterExt, Fe32, Hrp, NoChecksum};
use bitcoin::opcodes::OP_0;
use bitcoin::script::ScriptBufExt;
use bitcoin::{Address, Params, PublicKey, ScriptBuf};
use bitcoin_demo::{hash160, parse_address, EncodeHex, TESTNET4};
use hex_literal::hex;
use num_bigint::BigUint;
use once_cell::sync::Lazy;

const BECH32_TABLE: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const WITNESS_VERSION: u8 = 0x00;

static TEST_PUBLIC_KEY: Lazy<PublicKey> = Lazy::new(|| {
    PublicKey::from_slice(&hex!(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    ))
    .unwrap()
});

fn main() {
    let bech32 = bech32::encode::<Bech32>(Hrp::parse("prefix-").unwrap(), b"hello").unwrap();
    println!("{:?}", bech32);

    let address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let decoded = bech32::decode(address).unwrap();
    println!("decoded.0: {}", decoded.0);
    println!("decoded.1: {}", decoded.1.hex());

    let puk = PublicKey::from_slice(&hex!(
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    ))
    .unwrap();
    println!(
        "hash160 of public key: {}",
        hash160(&puk.inner.serialize()).hex()
    );

    let parsed_address = parse_address(address, TESTNET4).unwrap();
    assert!(parsed_address.is_related_to_pubkey(puk));
    println!("{:?}", parsed_address.address_type());

    let witness_program = hex!("751e76e8199196d454941c45d1b3a323f1433bd6");
    let script_pubkey = ScriptBuf::builder()
        .push_opcode(OP_0 /* witness version */)
        .push_slice(&witness_program)
        .into_script();
    println!("{}", script_pubkey);

    let address = Address::from_script(&script_pubkey, Params::TESTNET4).unwrap();
    println!("Address from script: {}", address);

    let versioned_fe32_iter = || {
        [Fe32::try_from(WITNESS_VERSION).unwrap()]
            .into_iter()
            .chain(
                base32(&witness_program)
                    .into_iter()
                    .map(|x| Fe32::try_from(x).unwrap()),
            )
    };

    let hrp = Hrp::parse("tb").unwrap();
    let encoder = Encoder::<_, Bech32>::new(versioned_fe32_iter(), &hrp);
    let encoded = encoder.chars().collect::<String>();
    println!("Encoded: {}", encoded);

    let checksum = Checksummed::<_, Bech32>::new_hrp(hrp, versioned_fe32_iter());
    println!(
        "GE(32) mapping with checksum: {}",
        checksum.map(|x| x.to_char()).collect::<String>()
    );

    let mut engine = checksum::Engine::<Bech32>::new();
    engine.input_hrp(hrp);
    for x in versioned_fe32_iter() {
        engine.input_fe(x);
    }
    println!("{}", engine.residue());

    // example from https://en.bitcoin.it/wiki/Bech32#Creating_a_Bech32_address
    println!(
        "create_p2wpkh_bech32_no_checksum: {}",
        create_p2wpkh_bech32_no_checksum(*TEST_PUBLIC_KEY, "tb")
    );
}

fn base32(data: &[u8]) -> Vec<u8> {
    // naive method to convert it to base-32
    let n = BigUint::from_bytes_be(data);
    n.to_radix_be(32)
}

fn map_bech32(fe32: &[u8]) -> String {
    fe32.iter()
        .map(|&x| {
            assert!(x < 0b000_11111);
            char::from(BECH32_TABLE[x as usize])
        })
        .collect::<String>()
}

/// Creates P2WPKH Bech32 address from PublicKey, but without the trailing checksum because
/// I know nothing about its checksumming.
///
/// Note: When encoding a segwit address, it doesn't work with [`bech32::encode_lower`]. This
/// function does the following:
///
/// data -> base32 -> map-to-string (see [`map_bech32`]).
///
/// Instead, [`Encoder`] is desired. For a segwit address, a witness version is prepended to the data that is **after** a base32
/// transformation. That's, we have no way to achieve this via [`bech32::encode_lower`]. Prepending
/// a `0x00` to the `data` parameter of [`bech32::encode_lower`] is invalid. Correct flow is
/// shown below:
///
/// data -> base32 -> prepend `0x00` -> map to string
///
/// Compared to the wrong way:
///
/// data -> prepend `0x00` -> base32 -> map to string
///
/// [`create_p2wpkh_bech32_no_checksum_lib_way`] is
/// an implementation with no checksum using [`bech32`] crate.
fn create_p2wpkh_bech32_no_checksum(public: PublicKey, hrp: &str) -> String {
    let witness_version: u8 = WITNESS_VERSION;
    let separator = '1';

    // the standard only accepts compressed public keys
    assert!(public.compressed);
    let bytes = public.inner.serialize();
    assert!(bytes[0] == 0x02 || bytes[1] == 0x03);

    let witness_program = hash160(&bytes);
    let witness_program_base32 = base32(&witness_program);
    let mut data = vec![0_u8; witness_program_base32.len() + 1];
    data[0] = witness_version;
    data[1..].copy_from_slice(&witness_program_base32);
    for &x in &data {
        assert!(x < 0b00011111);
    }

    format!("{hrp}{separator}{}", map_bech32(&data))
}

fn create_p2wpkh_bech32_no_checksum_lib_way(public: PublicKey, hrp: &str) -> String {
    assert!(public.compressed);
    let pubkey_hash = public.pubkey_hash();
    let bytes = *pubkey_hash.as_byte_array();

    let bytes_fe_list = bytes.into_iter().bytes_to_fes();
    let versioned_fe_list = [Fe32::try_from(WITNESS_VERSION).unwrap()]
        .into_iter()
        .chain(bytes_fe_list);
    let hrp = Hrp::parse(hrp).unwrap();
    Encoder::<_, NoChecksum>::new(versioned_fe_list, &hrp)
        .chars()
        .collect::<String>()
}

#[cfg(test)]
mod test {
    use crate::{
        create_p2wpkh_bech32_no_checksum, create_p2wpkh_bech32_no_checksum_lib_way, TEST_PUBLIC_KEY,
    };

    #[test]
    fn test() {
        let hrp = "tb";
        let bech32_1 = create_p2wpkh_bech32_no_checksum(*TEST_PUBLIC_KEY, hrp);
        let bech32_2 = create_p2wpkh_bech32_no_checksum_lib_way(*TEST_PUBLIC_KEY, hrp);
        assert_eq!(bech32_1, bech32_2);
    }
}
