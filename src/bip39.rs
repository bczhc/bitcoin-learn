use bip39::{Language, Mnemonic};
use bitcoin::consensus::Decodable;
use bitcoin::{PrivateKey, Transaction};
use hex_literal::hex;
use rand::rngs::OsRng;

fn main() {
    // let mut res = [0_u8; 512 / 8];
    // let mnemonic = "army van defense carry jealous true garbage claim echo media make crunch";
    // pbkdf2::pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), b"mnemonic", 2048, &mut res);
    // println!("{}", hex::encode(res));

    // let mut hmac = SimpleHmac::<blake3::Hasher>::new_from_slice(b"secret").unwrap();
    // hmac.update(b"content");
    // let output = hmac.finalize().into_bytes();
    // let output = output.as_slice();
    // println!("{}", hex::encode(output));
    // println!("{}", output.len());

    //
    // let ec = sha256(&entropy);
    // println!("{:?}", ec_derive(&ec).p2wpkh);
    //
    // let mnemonic = Mnemonic::from_phrase(
    //     "empower pride flavor bounce giraffe affair case where major situate shaft joke",
    //     Language::English,
    // )
    // .unwrap();
    // println!("{}", hex::encode(mnemonic.entropy()));
    // mnemonic;

    let private =
        PrivateKey::from_wif("KwDiBf89Rpdb8DxqowiAp5eTGDMyYCiYKVN1NrkvCYizWr7mwxnK").unwrap();
    let mnemonic = Mnemonic::from_entropy(&private.to_bytes(), Language::English)
        .unwrap()
        .to_string();
    println!("{}", mnemonic);
}
