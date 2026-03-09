//! Ed25519 signature verification and SHA-256 checksums for release artifacts.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::installer::error::InstallerError;

pub(super) fn decode_verifying_key(encoded_key: &str) -> Result<VerifyingKey, InstallerError> {
    let key_bytes =
        BASE64_STANDARD
            .decode(encoded_key)
            .map_err(|err| InstallerError::SignatureFormat {
                field: "release public key",
                details: err.to_string(),
            })?;
    let key_bytes: [u8; 32] =
        key_bytes
            .try_into()
            .map_err(|_| InstallerError::SignatureFormat {
                field: "release public key",
                details: "expected 32-byte Ed25519 key".to_string(),
            })?;

    VerifyingKey::from_bytes(&key_bytes).map_err(|err| InstallerError::SignatureFormat {
        field: "release public key",
        details: err.to_string(),
    })
}

pub(super) fn decode_signature(encoded_signature: &str) -> Result<Signature, InstallerError> {
    let signature_bytes = BASE64_STANDARD.decode(encoded_signature).map_err(|err| {
        InstallerError::SignatureFormat {
            field: "release signature",
            details: err.to_string(),
        }
    })?;
    let signature_bytes: [u8; 64] =
        signature_bytes
            .try_into()
            .map_err(|_| InstallerError::SignatureFormat {
                field: "release signature",
                details: "expected 64-byte Ed25519 signature".to_string(),
            })?;

    Ok(Signature::from_bytes(&signature_bytes))
}

pub(super) fn verify_signature(
    binary: &str,
    data: &[u8],
    encoded_signature: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), InstallerError> {
    let signature = decode_signature(encoded_signature)?;

    verifying_key
        .verify(data, &signature)
        .map_err(|_| InstallerError::SignatureVerificationFailed(binary.to_string()))
}

pub(super) fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
