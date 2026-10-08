//! BN254 scalar field helpers shared by public inputs and signature decoding.

use alloy_primitives::{Address, B256, U256, uint};
use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};

/// The BN254 scalar field modulus `r`.
pub const BN254_SCALAR_FIELD: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

/// The BN254 base field modulus `p`.
pub const BN254_BASE_FIELD: U256 =
    uint!(21888242871839275222246405745257275088696311157297823662689037894645226208583_U256);

/// Returns true if `value` is a canonical scalar field element, that is less than `r`.
pub fn is_canonical(value: &B256) -> bool {
    U256::from_be_bytes(value.0) < BN254_SCALAR_FIELD
}

/// Parses a canonical big-endian scalar field element, rejecting values of at least `r`.
pub fn fr_from_be(bytes: &[u8; 32]) -> Option<Fr> {
    Fr::from_bigint(bigint_from_be(bytes))
}

/// Reduces a big-endian 256-bit integer modulo `r`.
pub fn fr_reduce_be(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Encodes a scalar field element as 32 big-endian bytes.
pub fn fr_to_be(value: &Fr) -> B256 {
    let limbs = value.into_bigint().0;
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        out[24 - 8 * i..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
    }
    B256::from(out)
}

/// Maps an address to the field element `uint160(address)`.
pub fn fr_from_address(address: &Address) -> Fr {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(address.as_slice());
    Fr::from_bigint(bigint_from_be(&bytes)).expect("160-bit values are below r")
}

/// Splits 32 big-endian bytes into little-endian 64-bit limbs.
pub(crate) fn bigint_from_be(bytes: &[u8; 32]) -> BigInt<4> {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = 24 - 8 * i;
        *limb = u64::from_be_bytes(bytes[start..start + 8].try_into().expect("8 bytes"));
    }
    BigInt::new(limbs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bounds() {
        let r = B256::from(BN254_SCALAR_FIELD.to_be_bytes::<32>());
        let r_minus_one = B256::from((BN254_SCALAR_FIELD - U256::ONE).to_be_bytes::<32>());
        assert!(!is_canonical(&r));
        assert!(is_canonical(&r_minus_one));
        assert!(fr_from_be(&r.0).is_none());
        assert_eq!(fr_to_be(&fr_from_be(&r_minus_one.0).unwrap()), r_minus_one);
        assert_eq!(fr_reduce_be(&r.0), Fr::from(0u64));
    }

    #[test]
    fn address_is_uint160() {
        let address = Address::repeat_byte(0xff);
        let expected: U256 = (U256::ONE << 160usize) - U256::ONE;
        assert_eq!(
            fr_to_be(&fr_from_address(&address)),
            B256::from(expected.to_be_bytes::<32>())
        );
    }

    #[test]
    fn roundtrip_random() {
        for i in 0..64u64 {
            let value = Fr::from(i.wrapping_mul(0x9e37_79b9_7f4a_7c15)) * Fr::from(u64::MAX - i);
            assert_eq!(fr_from_be(&fr_to_be(&value).0), Some(value));
        }
    }
}
