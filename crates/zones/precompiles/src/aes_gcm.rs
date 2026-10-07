//! AES-256-GCM decryption for encrypted Zone deposits.
//!
//! Decrypts ECIES ciphertext and verifies the GCM authentication tag for the native
//! `ZoneInbox` implementation.
//!
//! Uses the NCC-audited `aes-gcm` crate (v0.10.3).

use alloc::vec::Vec;

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
use tempo_precompiles::{error::TempoPrecompileError, storage::StorageCtx};

/// Base gas cost for AES-GCM decryption.
const AES_GCM_BASE_GAS: u64 = 1_000;

/// Additional gas per byte of authenticated AES-GCM input.
const AES_GCM_PER_BYTE_GAS: u64 = 3;

/// Charge the native gas cost for AES-GCM authenticated input.
pub(crate) fn charge_gas(ciphertext_len: usize, aad_len: usize) -> tempo_precompiles::Result<()> {
    let len = u64::try_from(ciphertext_len.saturating_add(aad_len)).unwrap_or(u64::MAX);
    let gas = AES_GCM_BASE_GAS
        .checked_add(AES_GCM_PER_BYTE_GAS.saturating_mul(len))
        .ok_or_else(TempoPrecompileError::under_overflow)?;
    StorageCtx::default().deduct_gas(gas)
}

/// Decrypt AES-256-GCM ciphertext with tag verification.
///
/// The ciphertext, AAD, and tag are passed separately. Returns `(plaintext, true)` on success,
/// or `(empty, false)` on failure.
pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8; 16],
) -> (Vec<u8>, bool) {
    let cipher = Aes256Gcm::new(key.into());
    let gcm_nonce = Nonce::from_slice(nonce);
    let mut plaintext = ciphertext.to_vec();

    match cipher.decrypt_in_place_detached(gcm_nonce, aad, &mut plaintext, Tag::from_slice(tag)) {
        Ok(()) => (plaintext, true),
        Err(_) => (Vec::new(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{test_context, test_storage_provider};
    use aes_gcm::aead::{Aead, Payload};
    use tempo_precompiles::storage::PrecompileStorageProvider;

    fn encrypt(plaintext: &[u8], aad: &[u8]) -> ([u8; 32], [u8; 12], Vec<u8>, [u8; 16]) {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("encrypt");
        let tag = encrypted
            .split_off(encrypted.len() - 16)
            .try_into()
            .expect("16-byte tag");

        (key, nonce_bytes, encrypted, tag)
    }

    fn decrypt_with_native_gas(
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> (Vec<u8>, bool, u64) {
        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);
        let gas_before = storage.gas_used();
        let (plaintext, valid) = StorageCtx::enter(&mut storage, || {
            charge_gas(ciphertext.len(), aad.len()).expect("charge native gas");
            decrypt(key, nonce, ciphertext, aad, tag)
        });

        (plaintext, valid, storage.gas_used() - gas_before)
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"hello world test";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, &[], &tag);
        assert!(valid);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_bad_tag() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"hello";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let bad_tag = [0xFFu8; 16];

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, &[], &bad_tag);
        assert!(!valid);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aes_gcm_with_aad() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"hello world test";
        let aad = b"zone-inbox-v1";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: aad.as_ref(),
                },
            )
            .expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, aad, &tag);
        assert!(valid);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn precompile_gas_charges_aad_bytes() {
        let plaintext = b"";
        let aad = vec![0xA5; 128];
        let (key, nonce, ciphertext, tag) = encrypt(plaintext, &aad);
        let expected_gas =
            AES_GCM_BASE_GAS + AES_GCM_PER_BYTE_GAS * (ciphertext.len() + aad.len()) as u64;

        let (decrypted, valid, gas_used) =
            decrypt_with_native_gas(&key, &nonce, &ciphertext, &aad, &tag);

        assert!(valid);
        assert_eq!(decrypted, plaintext);
        assert_eq!(gas_used, expected_gas);
    }

    #[test]
    fn precompile_decrypts_without_aad_and_reports_ciphertext_gas() {
        let plaintext = b"normal precompile path";
        let (key, nonce, ciphertext, tag) = encrypt(plaintext, &[]);
        let expected_gas = AES_GCM_BASE_GAS + AES_GCM_PER_BYTE_GAS * ciphertext.len() as u64;

        let (decrypted, valid, gas_used) =
            decrypt_with_native_gas(&key, &nonce, &ciphertext, &[], &tag);

        assert!(valid);
        assert_eq!(decrypted, plaintext);
        assert_eq!(gas_used, expected_gas);
    }

    #[test]
    fn test_aes_gcm_wrong_aad() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"secret data";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: b"correct",
                },
            )
            .expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, b"wrong", &tag);
        assert!(!valid);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aes_gcm_missing_aad() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"secret data";
        let aad = b"zone-inbox-v1";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: aad.as_ref(),
                },
            )
            .expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, &[], &tag);
        assert!(!valid);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aes_gcm_flipped_ciphertext_bit() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"hello world test";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

        let mut ct = encrypted[..encrypted.len() - 16].to_vec();
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        ct[0] ^= 0x01;

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, &ct, &[], &tag);
        assert!(!valid);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"";

        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");

        let ct = &encrypted[..encrypted.len() - 16];
        let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();

        let (decrypted, valid) = decrypt(&key, &nonce_bytes, ct, &[], &tag);
        assert!(valid);
        assert!(decrypted.is_empty());
    }
}
