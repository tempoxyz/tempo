//! TIP-1094 FF1 (NIST SP 800-38G) over 48 binary digits with AES-256.
//!
//! The parameters are fixed by the TIP: radix 2, numeral-string length 48 (6 bytes, most
//! significant bit first), so both halves are 24-bit integers and every round fits in a [`u64`].

use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use tempo_contracts::zones::{ZVDA_DECRYPT_GAS, zvda_tweak};
use tempo_precompiles::storage::StorageCtx;

const HALF_BITS: u32 = 24;
const HALF_MASK: u64 = (1 << HALF_BITS) - 1;
/// `b` from SP 800-38G for radix 2 and `v = 24`.
const B: usize = 3;
const ROUNDS: u8 = 10;

/// Charge the fixed TIP-1094 decryption tariff.
pub(crate) fn charge_gas() -> tempo_precompiles::Result<()> {
    StorageCtx::default().deduct_gas(ZVDA_DECRYPT_GAS)
}

/// Encrypt a 6-byte `masterId || userTag` under the key for `version` in zone `zone_id`.
pub fn encrypt(key: &[u8; 32], version: u8, zone_id: u32, plaintext: [u8; 6]) -> [u8; 6] {
    let ff1 = Ff1::new(key, version, zone_id);
    let (mut a, mut b) = split(plaintext);
    for i in 0..ROUNDS {
        let c = (a + ff1.round(i, b)) & HALF_MASK;
        a = b;
        b = c;
    }
    join(a, b)
}

/// Decrypt a 6-byte ciphertext under the key for `version` in zone `zone_id`.
pub fn decrypt(key: &[u8; 32], version: u8, zone_id: u32, ciphertext: [u8; 6]) -> [u8; 6] {
    let ff1 = Ff1::new(key, version, zone_id);
    let (mut a, mut b) = split(ciphertext);
    for i in (0..ROUNDS).rev() {
        let c = b.wrapping_sub(ff1.round(i, a)) & HALF_MASK;
        b = a;
        a = c;
    }
    join(a, b)
}

struct Ff1 {
    cipher: Aes256,
    /// `P` followed by the zero-padded tweak, up to the round byte.
    prefix: [u8; 48],
    prefix_len: usize,
}

impl Ff1 {
    fn new(key: &[u8; 32], version: u8, zone_id: u32) -> Self {
        let (tweak, t) = zvda_tweak(version, zone_id);
        let mut prefix = [0u8; 48];
        // P = [1, 2, 1] || [radix]^3 || [10] || [u mod 256] || [n]^4 || [t]^4
        prefix[..16].copy_from_slice(&[
            1,
            2,
            1,
            0,
            0,
            2,
            10,
            HALF_BITS as u8,
            0,
            0,
            0,
            48,
            0,
            0,
            0,
            t as u8,
        ]);
        // Q = T || [0]^((-t-b-1) mod 16) || [i] || [NUM(B)]^b
        prefix[16..16 + t].copy_from_slice(&tweak[..t]);
        let pad = (16 - (t + B + 1) % 16) % 16;
        Self {
            cipher: Aes256::new(GenericArray::from_slice(key)),
            prefix,
            prefix_len: 16 + t + pad,
        }
    }

    /// The round function: the first `d = 8` bytes of `PRF(P || Q)` as an integer.
    fn round(&self, i: u8, half: u64) -> u64 {
        let mut pq = [0u8; 64];
        pq[..self.prefix_len].copy_from_slice(&self.prefix[..self.prefix_len]);
        pq[self.prefix_len] = i;
        pq[self.prefix_len + 1..self.prefix_len + 1 + B].copy_from_slice(&half.to_be_bytes()[5..]);
        let len = self.prefix_len + 1 + B;
        debug_assert_eq!(len % 16, 0);

        let mut y = GenericArray::from([0u8; 16]);
        for block in pq[..len].as_chunks::<16>().0 {
            for (y, x) in y.iter_mut().zip(block) {
                *y ^= x;
            }
            self.cipher.encrypt_block(&mut y);
        }
        u64::from_be_bytes(y[..8].try_into().expect("8 bytes"))
    }
}

fn split(bytes: [u8; 6]) -> (u64, u64) {
    let value = u64::from_be_bytes([
        0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
    ]);
    (value >> HALF_BITS, value & HALF_MASK)
}

fn join(a: u64, b: u64) -> [u8; 6] {
    let value = (a << HALF_BITS) | b;
    value.to_be_bytes()[2..].try_into().expect("6 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    const SEQ_KEY: [u8; 32] =
        hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    /// (key, version, zone ID, plaintext, ciphertext)
    type Vector = ([u8; 32], u8, u32, [u8; 6], [u8; 6]);

    /// TIP-1094 conformance vectors.
    #[test]
    fn conformance_vectors() {
        let vectors: [Vector; 7] = [
            ([0; 32], 1, 0, [0; 6], hex!("e56104310de7")),
            ([0xff; 32], 1, 0xffffffff, [0xff; 6], hex!("da8800b07afe")),
            (
                SEQ_KEY,
                1,
                0x01020304,
                hex!("deadbeef1234"),
                hex!("90ab85ef21cb"),
            ),
            ([0; 32], 2, 0, [0; 6], hex!("7a6b49ff9d16")),
            ([0xff; 32], 2, 0xffffffff, [0xff; 6], hex!("7cedf916badb")),
            (
                SEQ_KEY,
                2,
                0x01020304,
                hex!("deadbeef1234"),
                hex!("d680dd219064"),
            ),
            (
                SEQ_KEY,
                10,
                0x01020304,
                hex!("deadbeef1234"),
                hex!("178d91c6cff1"),
            ),
        ];
        for (key, version, zone_id, plaintext, ciphertext) in vectors {
            assert_eq!(encrypt(&key, version, zone_id, plaintext), ciphertext);
            assert_eq!(decrypt(&key, version, zone_id, ciphertext), plaintext);
        }
    }

    /// The TIP's worked example: zone 7, master 41, tag 1.
    #[test]
    fn worked_example() {
        let pt = hex!("000000290001");
        assert_eq!(encrypt(&SEQ_KEY, 1, 7, pt), hex!("5a951fcc7419"));
        assert_eq!(encrypt(&SEQ_KEY, 2, 7, pt), hex!("0f43b3cc4c63"));
    }

    #[test]
    fn round_trips_boundary_tags() {
        for tag in [0u16, 1, 0x7fff, 0xffff] {
            let mut pt = [0u8; 6];
            pt[..4].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
            pt[4..].copy_from_slice(&tag.to_be_bytes());
            for version in [1, 9, 10, 99, 100, 255] {
                let ct = encrypt(&SEQ_KEY, version, 42, pt);
                assert_eq!(decrypt(&SEQ_KEY, version, 42, ct), pt);
            }
        }
    }
}
