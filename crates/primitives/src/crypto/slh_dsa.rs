//! SLH-DSA-SHA2-128s (FIPS 205) signatures, verified with the default build of rust-pq's `slhdsa`.

use alloy_primitives::{Address, B256, keccak256};

/// Parameter set identifier of SLH-DSA-SHA2-128s in the signature encoding.
pub const SLH_DSA_SHA2_128S_PARAM_ID: u8 = 0x01;

/// Public key length of SLH-DSA-SHA2-128s: `PK.seed || PK.root`.
pub const SLH_DSA_PUBLIC_KEY_LENGTH: usize = slhdsa::sha2_128s::params::PK_BYTES;

/// Signature length of SLH-DSA-SHA2-128s.
pub const SLH_DSA_SIGNATURE_LENGTH: usize = slhdsa::sha2_128s::params::SIG_BYTES;

/// Domain prefix of SLH-DSA owner address derivation.
pub const SLH_DSA_ADDRESS_DOMAIN: &[u8] = b"tempo:slh-dsa:address";

/// Derives the address of an SLH-DSA-SHA2-128s public key:
/// `last20(keccak256("tempo:slh-dsa:address" || param_id || public_key))`.
pub fn derive_slh_dsa_address(public_key: &B256) -> Address {
    let mut preimage = [0u8; SLH_DSA_ADDRESS_DOMAIN.len() + 1 + SLH_DSA_PUBLIC_KEY_LENGTH];
    let (domain, rest) = preimage.split_at_mut(SLH_DSA_ADDRESS_DOMAIN.len());
    domain.copy_from_slice(SLH_DSA_ADDRESS_DOMAIN);
    rest[0] = SLH_DSA_SHA2_128S_PARAM_ID;
    rest[1..].copy_from_slice(public_key.as_slice());
    Address::from_word(keccak256(preimage))
}

/// Whether `signature` is a pure SLH-DSA-SHA2-128s signature (FIPS 205 Algorithm 24, empty
/// context) by `public_key` over the 32-byte `digest`.
pub fn verify_slh_dsa(public_key: &B256, signature: &[u8], digest: &B256) -> bool {
    let public_key: &[u8; SLH_DSA_PUBLIC_KEY_LENGTH] = public_key.as_ref();
    slhdsa::sha2_128s::verify(digest.as_slice(), signature, &[], public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_match_fips_205() {
        assert_eq!(SLH_DSA_PUBLIC_KEY_LENGTH, 32);
        assert_eq!(SLH_DSA_SIGNATURE_LENGTH, 7856);
    }
}
