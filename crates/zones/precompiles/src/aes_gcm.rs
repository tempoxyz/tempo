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
    use test_case::test_case;

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

    #[test_case(b"hello world test", &[], &[] => true)]
    #[test_case(b"", &[], &[] => true)]
    #[test_case(b"hello world test", b"zone-inbox-v1", b"zone-inbox-v1" => true)]
    // AAD bytes are charged.
    #[test_case(b"", &[0xA5; 128], &[0xA5; 128] => true)]
    #[test_case(b"secret data", b"correct", b"wrong" => false)]
    #[test_case(b"secret data", b"zone-inbox-v1", &[] => false)]
    fn test_aes_gcm_decrypt_charges_gas(
        plaintext: &[u8],
        encrypt_aad: &[u8],
        decrypt_aad: &[u8],
    ) -> bool {
        let (key, nonce, ciphertext, tag) = encrypt(plaintext, encrypt_aad);
        let expected_gas =
            AES_GCM_BASE_GAS + AES_GCM_PER_BYTE_GAS * (ciphertext.len() + decrypt_aad.len()) as u64;

        let mut ctx = test_context();
        let mut storage = test_storage_provider(&mut ctx, u64::MAX, true);
        let gas_before = storage.gas_used();
        let (decrypted, valid) = StorageCtx::enter(&mut storage, || {
            charge_gas(ciphertext.len(), decrypt_aad.len()).expect("charge native gas");
            decrypt(&key, &nonce, &ciphertext, decrypt_aad, &tag)
        });

        let expected_plaintext: &[u8] = if valid { plaintext } else { &[] };
        assert_eq!(decrypted, expected_plaintext);
        assert_eq!(storage.gas_used() - gas_before, expected_gas);
        valid
    }

    #[test]
    fn test_aes_gcm_tampered_input() {
        let (key, nonce, ciphertext, tag) = encrypt(b"hello world test", &[]);
        let mut flipped_ciphertext = ciphertext.clone();
        flipped_ciphertext[0] ^= 0x01;

        for (case, ciphertext, tag) in [
            ("bad tag", &ciphertext, [0xFFu8; 16]),
            ("flipped ciphertext bit", &flipped_ciphertext, tag),
        ] {
            assert_eq!(
                decrypt(&key, &nonce, ciphertext, &[], &tag),
                (Vec::new(), false),
                "{case}"
            );
        }
    }
}
