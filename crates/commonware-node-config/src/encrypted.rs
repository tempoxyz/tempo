//! Encryption-at-rest for consensus key material.
//!
//! Provides AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 key
//! derivation. The on-disk format is intentionally simple and self-describing:
//!
//! ```text
//!  0..4   magic   b"TENC"
//!  4..5   version 0x01
//!  5..37  salt    32 bytes (random, per file)
//! 37..49  nonce   12 bytes (random, per encryption)
//! 49..    ciphertext + 16-byte GCM auth tag
//! ```
//!
//! The passphrase is never stored; it must be supplied at runtime, typically
//! via an environment variable (`TEMPO_KEY_PASSPHRASE`).

use std::path::Path;

use aes_gcm::{
    aead::{Aead, OsRng},
    Aes256Gcm, KeyInit, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// File header that identifies an encrypted key file.
const MAGIC: &[u8; 4] = b"TENC";

/// Current envelope version. Bump when the format changes.
const VERSION: u8 = 0x01;

/// PBKDF2 iteration count. 600 000 aligns with current OWASP guidance for
/// PBKDF2-HMAC-SHA256 (as of 2024).
const PBKDF2_ITERATIONS: u32 = 600_000;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN; // 49

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("failed reading encrypted file")]
    Read(#[source] std::io::Error),
    #[error("failed writing encrypted file")]
    Write(#[source] std::io::Error),
    #[error("file too short to contain a valid encrypted envelope")]
    TruncatedFile,
    #[error("not an encrypted key file (bad magic)")]
    BadMagic,
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("decryption failed (wrong passphrase or corrupted file)")]
    DecryptionFailed,
}

/// Derives a 256-bit key from `passphrase` and `salt` using PBKDF2-HMAC-SHA256.
fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase, salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypts `plaintext` and returns the full on-disk envelope.
pub fn seal(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    use aes_gcm::aead::rand_core::RngCore;

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("key is always 32 bytes");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    let mut envelope = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.push(VERSION);
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Decrypts an on-disk envelope produced by [`seal`].
pub fn open(envelope: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if envelope.len() < HEADER_LEN {
        return Err(EncryptionError::TruncatedFile);
    }

    if &envelope[..4] != MAGIC {
        return Err(EncryptionError::BadMagic);
    }

    let version = envelope[4];
    if version != VERSION {
        return Err(EncryptionError::UnsupportedVersion(version));
    }

    let salt: &[u8; SALT_LEN] = envelope[5..5 + SALT_LEN]
        .try_into()
        .expect("slice length matches SALT_LEN");
    let nonce_bytes = &envelope[5 + SALT_LEN..HEADER_LEN];
    let ciphertext = &envelope[HEADER_LEN..];

    let key = derive_key(passphrase, salt);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("key is always 32 bytes");
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EncryptionError::DecryptionFailed)
}

/// Returns `true` if `data` starts with the encrypted envelope magic bytes.
pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == MAGIC
}

/// Reads a file, decrypting it if the contents are an encrypted envelope.
/// Falls back to returning raw bytes for plaintext files, enabling transparent
/// migration.
pub fn read_maybe_encrypted(
    path: &Path,
    passphrase: Option<&[u8]>,
) -> Result<Vec<u8>, EncryptionError> {
    let raw = std::fs::read(path).map_err(EncryptionError::Read)?;

    if is_encrypted(&raw) {
        let passphrase = passphrase.ok_or(EncryptionError::DecryptionFailed)?;
        open(&raw, passphrase)
    } else {
        // Plaintext file — return as-is for backward compatibility.
        Ok(raw)
    }
}

/// Encrypts `plaintext` and writes the envelope to `path`.
pub fn write_encrypted(
    path: &Path,
    plaintext: &[u8],
    passphrase: &[u8],
) -> Result<(), EncryptionError> {
    let envelope = seal(plaintext, passphrase)?;
    std::fs::write(path, envelope).map_err(EncryptionError::Write)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let passphrase = b"correct horse battery staple";
        let plaintext = b"0x7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a";

        let envelope = seal(plaintext, passphrase).unwrap();
        assert!(is_encrypted(&envelope));

        let recovered = open(&envelope, passphrase).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let envelope = seal(b"secret", b"right").unwrap();
        assert!(matches!(
            open(&envelope, b"wrong"),
            Err(EncryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn truncated_file_is_rejected() {
        // Anything shorter than HEADER_LEN triggers TruncatedFile first.
        assert!(matches!(
            open(&[0u8; 10], b"pass"),
            Err(EncryptionError::TruncatedFile)
        ));

        // A full-length header with wrong magic triggers BadMagic.
        let bad = vec![0u8; HEADER_LEN + 32];
        assert!(matches!(
            open(&bad, b"pass"),
            Err(EncryptionError::BadMagic)
        ));
    }

    #[test]
    fn plaintext_is_not_detected_as_encrypted() {
        assert!(!is_encrypted(b"0xdeadbeef"));
    }

    #[test]
    fn each_seal_produces_unique_envelope() {
        let pass = b"pass";
        let data = b"key material";
        let a = seal(data, pass).unwrap();
        let b = seal(data, pass).unwrap();
        // Different salt + nonce means different ciphertext each time.
        assert_ne!(a, b);
        // But both decrypt to the same plaintext.
        assert_eq!(open(&a, pass).unwrap(), open(&b, pass).unwrap());
    }
}
