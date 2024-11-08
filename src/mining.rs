#![feature(bigint_helper_methods)]
#![feature(decl_macro)]

use bitcoin::{consensus, Block, Target};
use bitcoin_demo::{sha256d, EncodeHex};
use hex_literal::hex;
use num_traits::ToBytes;
use std::cmp::Ordering;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Add;
use std::process::exit;
use std::thread::spawn;

fn main() -> anyhow::Result<()> {
    assert_little_endianness();

    let threads = num_cpus::get() as u32;
    println!("use threads: {threads}");
    assert_eq!((u32::MAX as u64 + 1) % threads as u64, 0);

    let block = hex!("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
    let mut block: Block = consensus::deserialize(&block).expect("Deserialization failed");
    let bits = block.header.bits;
    let target = Target::from(bits);
    let target_le = target.to_le_bytes();
    // let target_le = {
    //     let mut x = hex!("000000ffffff0000000000000000000000000000000000000000000000000000");
    //     x.reverse();
    //     x
    // };
    let target = Uint256::from_bytes_le(target_le);
    println!("Target: {}", target.to_bytes_be().hex());

    #[inline(always)]
    fn check_target(header: &RawBlockHeader, target: &Uint256) -> bool {
        let hash = header.block_hash();
        let hash_num = Uint256::from_bytes_le(hash);
        hash_num.le(target)
    }

    let part = ((u32::MAX as u64 + 1) / threads as u64) as u32;
    let mut join_handlers = Vec::new();
    for i in 0..threads {
        let mut raw_header = RawBlockHeader::from(&block);
        let range = (part * i)..=(part * i + (part - 1));
        let target = target.clone();
        let handler = spawn(move || {
            for nonce in range {
                raw_header.change_nonce(nonce);
                if check_target(&raw_header, &target) {
                    println!(
                        "Mined! {}, nonce {}",
                        raw_header.block_hash_display(),
                        nonce
                    );
                    exit(0);
                }
            }
        });
        join_handlers.push(handler);
    }

    join_handlers.into_iter().for_each(|x| x.join().unwrap());

    Ok(())
}

#[derive(Clone)]
struct RawBlockHeader([u8; 80]);

impl RawBlockHeader {
    fn change_nonce(&mut self, n: u32) {
        unsafe {
            *(&mut self.0[80 - 4] as *mut u8 as *mut [u8; 4]) = n.to_le_bytes();
        }
    }

    fn block_hash(&self) -> [u8; 32] {
        sha256d(&self.0)
    }

    fn block_hash_display(&self) -> String {
        let mut hash = self.block_hash();
        hash.reverse();
        hash.hex()
    }
}

impl From<&Block> for RawBlockHeader {
    fn from(value: &Block) -> Self {
        let vec = consensus::encode::serialize(&value.header);
        Self(vec.try_into().expect("Block header must be 80-byte length"))
    }
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
struct Uint256 {
    lo: u128,
    hi: u128,
}

impl Display for Uint256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use fmt::Write;
        write!(
            f,
            "lo: {}, hi: {}",
            self.lo.to_ne_bytes().hex(),
            self.hi.to_ne_bytes().hex()
        )
    }
}

impl Uint256 {
    fn from_bytes_le(bytes: [u8; 256 / 8]) -> Self {
        unsafe {
            let lo = *(bytes.as_ptr() as *const u128);
            let hi = *(bytes.as_ptr().offset(16) as *const u128);
            Self { lo, hi }
        }
    }

    fn from_bytes_be(bytes: [u8; 256 / 8]) -> Self {
        unsafe {
            let mut lo_part = *(&bytes[16] as *const u8 as *const [u8; 16]);
            lo_part.reverse();
            let mut hi_part = *(&bytes[0] as *const u8 as *const [u8; 16]);
            hi_part.reverse();
            Self {
                lo: u128::from_le_bytes(lo_part),
                hi: u128::from_le_bytes(hi_part),
            }
        }
    }

    fn to_bytes_le(self) -> [u8; 256 / 8] {
        let mut b = [0_u8; 256 / 8];
        b[..16].copy_from_slice(&self.lo.to_le_bytes());
        b[16..].copy_from_slice(&self.hi.to_le_bytes());
        b
    }

    fn to_bytes_be(self) -> [u8; 256 / 8] {
        let mut b = [0_u8; 256 / 8];
        b[..16].copy_from_slice(&self.hi.to_be_bytes());
        b[16..].copy_from_slice(&self.lo.to_be_bytes());
        b
    }
}

impl Add for Uint256 {
    type Output = Uint256;

    fn add(self, rhs: Self) -> Self::Output {
        // TODO: carrying maybe not work
        let (lo, carry) = self.lo.carrying_add(rhs.lo, false);
        let hi = self.hi.carrying_add(self.hi, carry).0;
        Self { lo, hi }
    }
}

impl PartialOrd for Uint256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self == other {
            return Some(Ordering::Equal);
        }

        if self.hi != other.hi {
            return Some(self.hi.cmp(&other.hi));
        }

        // only compare the low part
        Some(self.lo.cmp(&other.lo))
    }
}

fn assert_little_endianness() {
    let num = 0x1122334455667788_9900000000000000_u128;
    assert_eq!(num.to_ne_bytes(), hex!("0000000000000099 8877665544332211"));
}

#[cfg(test)]
mod test {
    use crate::{assert_little_endianness, Uint256};
    use bitcoin_demo::EncodeHex;
    use hex_literal::hex;

    #[test]
    fn test() {
        assert_little_endianness();

        macro from_be($b:expr) {
            Uint256::from_bytes_be(hex!($b))
        }
        let n1 = from_be!("0000ffffffff0000000000000000000000000000000000000000000000000000");
        let n2 = from_be!("0000ffffffff0000000000000000000000000000000000000000000000000000");
        assert_eq!(n1, n2);
        let n3 = from_be!("0000ffffffff0000000000000000000000000000000000000000000000000001");
        assert!(n2 < n3);
        let n4 = from_be!("000000ffffff0000000000000000000000000000000000000000000000000000");
        assert!(n3 > n4);
    }
}
