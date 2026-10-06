//! Public inputs of ZK signature proofs ([TIP-1131], [TIP-1133]).
//!
//! [TIP-1131]: https://docs.tempo.xyz/protocol/tips/tip-1131
//! [TIP-1133]: https://docs.tempo.xyz/protocol/tips/tip-1133

use crate::{
    field::{fr_from_address, fr_from_be, fr_reduce_be},
    poseidon::poseidon7,
};
use alloy_primitives::{Address, B256};
use ark_bn254::Fr;

/// Second committed value of the message form, `2^64`. It exceeds every `valid_until`, so the
/// signature and message forms never share a public input.
pub const MESSAGE_TAG: u128 = 1 << 64;

/// What a ZK signature's proof attests to: an issuer statement for an identity whose nonce
/// commits to an access key and an expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureStatement {
    /// The scheme byte.
    pub scheme: u8,
    /// Scheme-defined issuer hash.
    pub issuer: B256,
    /// Scheme-defined hash of the issuer key that signed the statement.
    pub key_hash: B256,
    /// Scheme-defined identity commitment.
    pub address_seed: B256,
    /// The access key the nonce commits to.
    pub access_key_id: Address,
    /// When the signature expires, in seconds.
    pub valid_until: u64,
    /// When the issuer signed the statement, in seconds.
    pub issued_at: u64,
}

impl SignatureStatement {
    /// Returns `Poseidon(scheme, issuer, key_hash, address_seed, uint160(access_key_id),
    /// valid_until, issued_at)`, or `None` if a field element is not canonical.
    pub fn public_input(&self) -> Option<Fr> {
        Some(poseidon7(&[
            Fr::from(self.scheme),
            fr_from_be(&self.issuer.0)?,
            fr_from_be(&self.key_hash.0)?,
            fr_from_be(&self.address_seed.0)?,
            fr_from_address(&self.access_key_id),
            Fr::from(self.valid_until),
            Fr::from(self.issued_at),
        ]))
    }
}

/// What a message signature's proof attests to: an issuer statement for an identity whose
/// nonce commits to a message digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageStatement {
    /// The scheme byte.
    pub scheme: u8,
    /// Scheme-defined issuer hash.
    pub issuer: B256,
    /// Scheme-defined hash of the issuer key that signed the statement.
    pub key_hash: B256,
    /// Scheme-defined identity commitment.
    pub address_seed: B256,
    /// The EIP-712 or EIP-191 digest of the message.
    pub digest: B256,
    /// When the issuer signed the statement, in seconds.
    pub issued_at: u64,
}

impl MessageStatement {
    /// Returns `Poseidon(scheme, issuer, key_hash, address_seed, uint256(digest) mod r,
    /// MESSAGE_TAG, issued_at)`, or `None` if a field element is not canonical.
    pub fn public_input(&self) -> Option<Fr> {
        Some(poseidon7(&[
            Fr::from(self.scheme),
            fr_from_be(&self.issuer.0)?,
            fr_from_be(&self.key_hash.0)?,
            fr_from_be(&self.address_seed.0)?,
            fr_reduce_be(&self.digest.0),
            Fr::from(MESSAGE_TAG),
            Fr::from(self.issued_at),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::BN254_SCALAR_FIELD;

    fn signature() -> SignatureStatement {
        SignatureStatement {
            scheme: 1,
            issuer: B256::with_last_byte(1),
            key_hash: B256::with_last_byte(2),
            address_seed: B256::with_last_byte(3),
            access_key_id: Address::repeat_byte(0x11),
            valid_until: 1_700_000_600,
            issued_at: 1_700_000_000,
        }
    }

    #[test]
    fn rejects_non_canonical_field_elements() {
        let r = B256::from(BN254_SCALAR_FIELD.to_be_bytes::<32>());
        let mut statement = signature();
        assert!(statement.public_input().is_some());
        statement.key_hash = r;
        assert!(statement.public_input().is_none());
    }

    #[test]
    fn forms_differ() {
        let signature = signature();
        let message = MessageStatement {
            scheme: signature.scheme,
            issuer: signature.issuer,
            key_hash: signature.key_hash,
            address_seed: signature.address_seed,
            digest: B256::left_padding_from(signature.access_key_id.as_slice()),
            issued_at: signature.issued_at,
        };
        assert_ne!(signature.public_input(), message.public_input());
    }
}
