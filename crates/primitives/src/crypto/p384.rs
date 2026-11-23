//! P-384 signatures, as AWS Nitro attestations use them.

use aws_lc_rs::{
    digest::{Digest, SHA384},
    signature::{
        ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED, EcdsaVerificationAlgorithm,
        ParsedPublicKey,
    },
};

/// SEC1 uncompressed public key size.
const PUBLIC_KEY_SIZE: usize = 97;
/// SHA-384 digest size.
const DIGEST_SIZE: usize = 48;
/// `r || s` signature size.
pub(super) const FIXED_SIGNATURE_SIZE: usize = 96;

/// Whether `signature` is a valid DER P-384 signature by SEC1 `key` over `digest`.
pub fn verify_p384_der(
    key: &[u8; PUBLIC_KEY_SIZE],
    digest: &[u8; DIGEST_SIZE],
    signature: &[u8],
) -> bool {
    #[cfg(feature = "mock-crypto")]
    if super::mock::verify_p384_der(key, digest, signature) {
        return true;
    }
    verify(&ECDSA_P384_SHA384_ASN1, key, digest, signature)
}

/// Whether `signature` is a valid `r || s` P-384 signature by SEC1 `key` over `digest`.
pub fn verify_p384_fixed(
    key: &[u8; PUBLIC_KEY_SIZE],
    digest: &[u8; DIGEST_SIZE],
    signature: &[u8; FIXED_SIGNATURE_SIZE],
) -> bool {
    #[cfg(feature = "mock-crypto")]
    if super::mock::verify_p384_fixed(key, digest, signature) {
        return true;
    }
    verify(&ECDSA_P384_SHA384_FIXED, key, digest, signature)
}

fn verify(
    algorithm: &'static EcdsaVerificationAlgorithm,
    key: &[u8; PUBLIC_KEY_SIZE],
    digest: &[u8; DIGEST_SIZE],
    signature: &[u8],
) -> bool {
    let (Ok(key), Ok(digest)) = (
        ParsedPublicKey::new(algorithm, key),
        Digest::import_less_safe(digest, &SHA384),
    ) else {
        return false;
    };
    key.verify_digest_sig(&digest, signature).is_ok()
}
