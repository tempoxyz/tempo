pub mod dispatch;

use crate::{SIGNATURE_VERIFIER_ADDRESS, error::Result};
use alloy::primitives::{Address, B256, Bytes};
use tempo_contracts::precompiles::SignatureVerifierError;
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::{SignatureType, tt_signature::PrimitiveSignature};

/// Gas cost for secp256k1 signature verification.
const SECP256K1_VERIFY_GAS: u64 = 3_000;

/// Gas cost for P256 signature verification.
const P256_VERIFY_GAS: u64 = 8_000;

/// Gas cost for WebAuthn signature verification.
const WEBAUTHN_VERIFY_GAS: u64 = 8_000;

#[contract(addr = SIGNATURE_VERIFIER_ADDRESS)]
pub struct SignatureVerifier {}

impl SignatureVerifier {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn recover(&mut self, hash: B256, signature: Bytes) -> Result<Address> {
        // Parse and validate signature (handles size checks + type disambiguation).
        let sig = PrimitiveSignature::from_bytes(&signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;

        // Charge verification gas before performing verification.
        let verify_gas = match sig.signature_type() {
            SignatureType::Secp256k1 => SECP256K1_VERIFY_GAS,
            SignatureType::P256 => P256_VERIFY_GAS,
            SignatureType::WebAuthn => WEBAUTHN_VERIFY_GAS,
        };
        self.storage.deduct_gas(verify_gas)?;

        // Verify and recover signer.
        sig.recover_signer(&hash)
            .map_err(|_| SignatureVerifierError::invalid_signature().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::transaction::tt_signature::{
        SIGNATURE_TYPE_P256, SIGNATURE_TYPE_WEBAUTHN,
    };

    fn sign_recover(hash: B256, signature: Vec<u8>) -> Result<Address> {
        SignatureVerifier::new().recover(hash, Bytes::from(signature))
    }

    #[test]
    fn test_verify_secp256k1_valid() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let signer = PrivateKeySigner::random();
            let hash = B256::from([0xAA; 32]);
            let sig = signer.sign_hash_sync(&hash)?;
            let sig_bytes = sig.as_bytes().to_vec();
            assert_eq!(sig_bytes.len(), 65);

            let result = sign_recover(hash, sig_bytes)?;
            assert_eq!(result, signer.address());
            Ok(())
        })
    }

    #[test]
    fn test_verify_p256_valid() -> eyre::Result<()> {
        use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
        use tempo_primitives::transaction::tt_signature::{derive_p256_address, normalize_p256_s};

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let encoded = verifying_key.to_encoded_point(false);
            let pub_key_x =
                B256::from_slice(encoded.x().ok_or_else(|| eyre::eyre!("missing x coord"))?);
            let pub_key_y =
                B256::from_slice(encoded.y().ok_or_else(|| eyre::eyre!("missing y coord"))?);
            let expected_address = derive_p256_address(&pub_key_x, &pub_key_y);

            let hash = B256::from([0xBB; 32]);
            let (signature, _) = signing_key.sign_prehash_recoverable(hash.as_slice())?;
            let r = B256::from_slice(&signature.r().to_bytes());
            let s =
                normalize_p256_s(&signature.s().to_bytes()).expect("p256 crate produces valid s");

            // Build encoded P256 signature: 0x01 || r || s || x || y || prehash(0)
            let mut sig_bytes = Vec::new();
            sig_bytes.push(SIGNATURE_TYPE_P256);
            sig_bytes.extend_from_slice(r.as_slice());
            sig_bytes.extend_from_slice(s.as_slice());
            sig_bytes.extend_from_slice(pub_key_x.as_slice());
            sig_bytes.extend_from_slice(pub_key_y.as_slice());
            sig_bytes.push(0); // pre_hash = false
            assert_eq!(sig_bytes.len(), 130);

            let result = sign_recover(hash, sig_bytes)?;
            assert_eq!(result, expected_address);
            Ok(())
        })
    }

    #[test]
    fn test_verify_empty_signature_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let result = sign_recover(B256::ZERO, vec![]);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_secp256k1_wrong_length_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            // 64 bytes — not 65
            let result = sign_recover(B256::ZERO, vec![0u8; 64]);
            assert!(result.is_err());
            // 66 bytes — not 65
            let result = sign_recover(B256::ZERO, vec![0u8; 66]);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_p256_wrong_length_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            // 0x01 prefix + 128 bytes (should be 129)
            let mut sig = vec![SIGNATURE_TYPE_P256];
            sig.extend_from_slice(&[0u8; 128]);
            let result = sign_recover(B256::ZERO, sig);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_webauthn_too_short_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            // 0x02 prefix + 127 bytes (min is 128)
            let mut sig = vec![SIGNATURE_TYPE_WEBAUTHN];
            sig.extend_from_slice(&[0u8; 127]);
            let result = sign_recover(B256::ZERO, sig);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_webauthn_too_long_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            // 0x02 prefix + 2049 bytes (max is 2048)
            let mut sig = vec![SIGNATURE_TYPE_WEBAUTHN];
            sig.extend_from_slice(&[0u8; 2049]);
            let result = sign_recover(B256::ZERO, sig);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_unknown_type_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut sig = vec![0x05];
            sig.extend_from_slice(&[0u8; 129]);
            let result = sign_recover(B256::ZERO, sig);
            assert!(result.is_err());
            Ok(())
        })
    }

    #[test]
    fn test_verify_invalid_secp256k1_signature_reverts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let result = sign_recover(B256::ZERO, vec![0u8; 65]);
            assert!(result.is_err());
            Ok(())
        })
    }
}
