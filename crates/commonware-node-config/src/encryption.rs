//! Encryption for signing keys and shares using ChaCha20Poly1305.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use eyre::{bail, eyre};

/// Environment variable name for the signing key encryption secret.
pub const SIGNING_KEY_ENV_VAR: &str = "TEMPO_SIGNING_KEY_SECRET";

/// Environment variable name for the signing share encryption secret.
pub const SIGNING_SHARE_ENV_VAR: &str = "TEMPO_SIGNING_SHARE_SECRET";

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

fn derive_key(secret: &str) -> [u8; 32] {
    *blake3::hash(secret.as_bytes()).as_bytes()
}

/// Encrypt plaintext bytes. Returns nonce + ciphertext.
pub fn encrypt(plaintext: &[u8], secret: &str) -> eyre::Result<Vec<u8>> {
    let key = derive_key(secret);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| eyre!("encryption failed: {e:?}"))?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt encrypted data (nonce + ciphertext).
pub fn decrypt(data: &[u8], secret: &str) -> eyre::Result<Vec<u8>> {
    if data.len() < NONCE_SIZE + TAG_SIZE {
        bail!("ciphertext too short");
    }

    let nonce_bytes = &data[..NONCE_SIZE];
    let ciphertext = &data[NONCE_SIZE..];

    let key = derive_key(secret);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| eyre!("decryption failed: {e:?}"))
}

/// Get the signing key encryption secret from environment.
pub fn get_signing_key_secret() -> eyre::Result<String> {
    std::env::var(SIGNING_KEY_ENV_VAR).map_err(|_| eyre!("{SIGNING_KEY_ENV_VAR} not set"))
}

/// Get the signing share encryption secret from environment.
pub fn get_signing_share_secret() -> eyre::Result<String> {
    std::env::var(SIGNING_SHARE_ENV_VAR).map_err(|_| eyre!("{SIGNING_SHARE_ENV_VAR} not set"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let plaintext = b"secret data";
        let secret = "password";
        let encrypted = encrypt(plaintext, secret).unwrap();
        let decrypted = decrypt(&encrypted, secret).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password() {
        let encrypted = encrypt(b"data", "correct").unwrap();
        assert!(decrypt(&encrypted, "wrong").is_err());
    }
}
