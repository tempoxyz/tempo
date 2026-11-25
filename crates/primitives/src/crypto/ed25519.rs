//! Ed25519 signatures.

use commonware_cryptography::{
    Verifier,
    ed25519::{PublicKey, Signature},
};

/// Whether `signature` is a valid Ed25519 signature by `key` over `message` in `namespace`.
pub fn verify_ed25519(
    key: &PublicKey,
    namespace: &[u8],
    message: &[u8],
    signature: &Signature,
) -> bool {
    #[cfg(feature = "mock-crypto")]
    if super::mock::verify_ed25519(key.as_ref(), namespace, message, signature.as_ref()) {
        return true;
    }
    key.verify(namespace, message, signature)
}
