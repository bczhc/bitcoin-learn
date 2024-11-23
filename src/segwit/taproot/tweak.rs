//! Play around with p2tr key tweaking, script tree and address generation etc.

use bitcoin::opcodes::all::{OP_EQUAL, OP_PUSHNUM_1, OP_PUSHNUM_2};
use bitcoin::params::TESTNET4;
use bitcoin::script::ScriptBufExt;
use bitcoin::secp256k1::Scalar;
use bitcoin::{consensus, Address, KnownHrp, Script, ScriptBuf, TapNodeHash};
use bitcoin_demo::bitcoin_old::secp256k1::PublicKey;
use bitcoin_demo::mining::Uint256;
use bitcoin_demo::secp256k1::PublicKeyExt;
use bitcoin_demo::{sha256, EncodeHex, Hash256, Hash512, Key256, PointHex};
use digest::Digest;
use hex_literal::hex;
use std::cmp::Ordering;

fn main() {
    use bitcoin::secp256k1 as secp;

    let secret = secp::SecretKey::from_slice(&hex!(
        "584e5e6909b27b2444c263975758220891495105804cf62397f148f2396cc3b4"
    ))
    .unwrap();
    let pk = secret.public_key(&Default::default());
    let coord = pk.coordinates();
    println!("Pubkey: {}", PointHex(coord));

    // Compute the tweaked pubkey, with no tapscript.
    let (tweak_scalar, tweaked_pubkey) = compute_tweaked_pubkey(pk, None);

    let tweaked_secret = secret.add_tweak(&tweak_scalar).unwrap();
    let derived_pk = tweaked_secret.public_key(&Default::default());

    // This checks:
    // > Thanks to the mathematics of elliptic curves, this tweaked private key will actually correspond to the tweaked public key.
    // from https://learnmeabitcoin.com/technical/upgrades/taproot
    assert_eq!(derived_pk, tweaked_pubkey);

    println!();
    // Do the same thing, but with two tapscripts added:
    // - 1: OP_EQUAL
    // - 2: OP_2 OP_EQUAL
    let script1 = ScriptBuf::builder().push_opcode(OP_EQUAL).into_script();
    let script2 = ScriptBuf::builder()
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_EQUAL)
        .into_script();
    let script1_hash = leaf_hash(&script1);
    let script2_hash = leaf_hash(&script2);
    let script_root = branch_hash(script1_hash, script2_hash);
    println!("Script merkle root: {}", script_root.hex());
    let (_, tweaked_pubkey) = compute_tweaked_pubkey(pk, Some(script_root));
    println!("Tweaked pubkey with two tapscripts: {}", tweaked_pubkey);
}

fn compute_tweaked_pubkey(pk: PublicKey, script_root: Option<Hash256>) -> (Scalar, PublicKey) {
    let taproot_pk = pk.serialize();
    let taproot_pk: [u8; 32] = (&taproot_pk[1..]).try_into().unwrap();
    let tweak = tweak(taproot_pk, script_root);
    println!("Tweak: {}", tweak.hex());

    let tweak_scalar = Scalar::from_be_bytes(tweak).unwrap();

    let tweaked_pubkey = pk
        .add_exp_tweak(&Default::default(), &tweak_scalar)
        .unwrap();
    let (x, y) = tweaked_pubkey.coordinates();
    println!("Tweaked pubkey: {}", PointHex((x, y)));
    // only takes the x coordinate
    println!("Taproot: {}", x.hex());

    let script = ScriptBuf::builder()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(x /* p2tr witness program */)
        .into_script();
    let address = Address::from_script(&script, &TESTNET4).unwrap();
    // here we created a p2tr address, with public key (034ba21a14c30a9efa5792b20b801a51612989ca6f20ee3ef80a13c0a64748f36e)
    // and no alternative scripts at all (empty script tree)
    println!("Address: {}", address);

    let root = script_root.map(|x| TapNodeHash::from_byte_array(x));
    let lib_address = Address::p2tr(&Default::default(), pk.into(), root, KnownHrp::Testnets);
    // compare with the address generated using the lib
    assert_eq!(address, lib_address);
    (tweak_scalar, tweaked_pubkey)
}

fn tag_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut prefix = [0_u8; 64];
    prefix[..32].copy_from_slice(&tag_hash);
    prefix[32..].copy_from_slice(&tag_hash);
    let mut hash = sha2::Sha256::default();
    hash.update(&prefix);
    hash.update(data);
    hash.finalize().into()
}

fn combine_two_hash(a: Hash256, b: Hash256) -> Hash512 {
    let mut data = [0_u8; 64];
    data[..32].copy_from_slice(&a);
    data[32..].copy_from_slice(&b);
    data
}

fn leaf_hash(leaf_script: &Script) -> [u8; 32] {
    let leaf_version = 0xc0;
    let script = consensus::serialize(leaf_script);
    let mut data = vec![0_u8; script.len() + 1];
    data[0] = leaf_version;
    data[1..].copy_from_slice(&script);

    tag_hash("TapLeaf", &data)
}

fn branch_hash(p1: Hash256, p2: Hash256) -> Hash256 {
    let p1num = Uint256::from_bytes_be(p1);
    let p2num = Uint256::from_bytes_be(p2);
    let tuple = match p1num.partial_cmp(&p2num).unwrap() {
        Ordering::Less => (p1, p2),
        Ordering::Equal => (p1, p2),
        Ordering::Greater => (p2, p1),
    };

    tag_hash("TapBranch", &combine_two_hash(tuple.0, tuple.1))
}

fn tweak(pubkey: Key256, merkle_root: Option<Hash256>) -> Hash256 {
    const TAG: &str = "TapTweak";
    match merkle_root {
        None => tag_hash(TAG, &pubkey),
        Some(m) => tag_hash(TAG, &combine_two_hash(pubkey, m)),
    }
}

#[cfg(test)]
mod test {
    use bitcoin::secp256k1::Scalar;
    use bitcoin::taproot::{LeafNode, LeafNodes, LeafVersion, TaprootMerkleBranch};
    use bitcoin::{consensus, secp256k1, ScriptBuf, TapNodeHash};
    use bitcoin_demo::secp256k1::PublicKeyExt;
    use bitcoin_demo::{script_hex, script_hex_owned, EncodeHex, Key256};
    use hex_literal::hex;
    use num_bigint::BigUint;

    fn decimal_to_hex(decimal: &str) -> Key256 {
        let int: BigUint = decimal.parse().unwrap();
        let vec = int.to_bytes_be();
        let mut key = [0_u8; 32];
        let padding = 32_usize.checked_sub(vec.len()).unwrap();
        key[padding..].copy_from_slice(&vec);
        key
    }

    #[test]
    fn public_key_from_coordinates() {
        let x = decimal_to_hex(
            "55066263022277343669578718895168534326250603453777594175500187360389116729240",
        );
        let y = decimal_to_hex(
            "32670510020758816978083085130507043184471273380659243275938904335757337482424",
        );
        let pk = secp256k1::PublicKey::from_coordinates(x, y).unwrap();
        let pk2 = secp256k1::PublicKey::from_coordinate_x(x, secp256k1::Parity::Even).unwrap();
        let (x2, y2) = pk.coordinates();
        let (x3, y3) = pk2.coordinates();
        assert_eq!((x, y), (x2, y2));
        assert_eq!((x, y), (x3, y3));
    }

    /// Really thanks to
    /// https://learnmeabitcoin.com/technical/upgrades/taproot/#example-4-script-path-spend-tree.
    /// for the test data.
    #[test]
    fn tweak_key() {
        let x = decimal_to_hex(
            "55066263022277343669578718895168534326250603453777594175500187360389116729240",
        );
        let y = decimal_to_hex(
            "32670510020758816978083085130507043184471273380659243275938904335757337482424",
        );
        let pk = secp256k1::PublicKey::from_coordinates(x, y).unwrap();

        let tweak1 = pk
            .mul_tweak(
                &Default::default(),
                &Scalar::from_be_bytes(decimal_to_hex("10")).unwrap(),
            )
            .unwrap();
        let (x, y) = tweak1.coordinates();

        assert_eq!(
            x,
            decimal_to_hex(
                "72488970228380509287422715226575535698893157273063074627791787432852706183111"
            )
        );
        assert_eq!(
            y,
            decimal_to_hex(
                "62070622898698443831883535403436258712770888294397026493185421712108624767191"
            )
        );
    }

    #[test]
    fn tag_hash() {
        // <leaf-version> OP_EQUAL
        let data = hex!("c087");
        let hash = super::tag_hash("TapLeaf", &data);
        assert_eq!(
            hash,
            hex!("7beb14f2a06c7c9b4dfe992e338ed13f7f34ea97cabd481a5e1e4f8a6e75980c")
        );
    }

    #[test]
    fn leaf_hash() {
        let leaf_hash = super::leaf_hash(script_hex!("5187"));
        assert_eq!(
            leaf_hash,
            hex!("6b13becdaf0eee497e2f304adcfa1c0c9e84561c9989b7f2b5fc39f5f90a60f6")
        );

        assert_ne!(consensus::serialize(script_hex!("5187")), hex!("5187"));

        // using lib
        let leaf_node = LeafNode::new_script(script_hex_owned!("5187"), LeafVersion::TapScript);
        let lib_leaf_hash = leaf_node.leaf_hash().unwrap();
        assert_eq!(lib_leaf_hash.as_byte_array(), &leaf_hash);
    }

    #[test]
    fn branch_hash() {
        let leaf1 = hex!("6b13becdaf0eee497e2f304adcfa1c0c9e84561c9989b7f2b5fc39f5f90a60f6");
        let leaf2 = hex!("ed5af8352e2a54cce8d3ea326beb7907efa850bdfe3711cef9060c7bb5bcf59e");

        let hash = super::branch_hash(leaf1, leaf2);
        assert_eq!(
            hash,
            hex!("1324300a84045033ec539f60c70d582c48b9acf04150da091694d83171b44ec9")
        );

        let lib_hash = TapNodeHash::from_node_hashes(
            TapNodeHash::from_byte_array(leaf1),
            TapNodeHash::from_byte_array(leaf2),
        );
        assert_eq!(hash, lib_hash.to_byte_array());
    }

    #[test]
    fn tweak() {
        let pubkey = hex!("924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329");
        let merkle_root = hex!("b5b72eea07b3e338962944a752a98772bbe1f1b6550e6fb6ab8c6e6adb152e7c");
        let tweak = super::tweak(pubkey, Some(merkle_root));
        assert_eq!(
            tweak,
            hex!("28dcaf275e25b339c2b8362dd0db3347fc7336602b2b52d95ffae0149038776c")
        );
    }
}
