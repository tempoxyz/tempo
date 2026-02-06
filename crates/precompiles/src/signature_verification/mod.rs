//! Signature Verification Precompile (TIP-1020)
//!
//! Enables contracts to verify Tempo signature types (secp256k1, P256, WebAuthn, Keychain)
//! using the same verification logic as Tempo transaction processing.

pub mod dispatch;

use crate::{
    SIGNATURE_VERIFICATION_ADDRESS, account_keychain::AccountKeychain, error::Result,
};
use alloy::primitives::{Address, B256};
use tempo_contracts::precompiles::{
    ISignatureVerification::verifyCall, SignatureVerificationError,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::{
    precompile_signature_verification_gas,
    tt_signature::{KeychainSignature, TempoSignature},
};

pub use tempo_contracts::precompiles::ISignatureVerification;

/// Signature Verification precompile
#[contract(addr = SIGNATURE_VERIFICATION_ADDRESS)]
pub struct SignatureVerification {}

impl SignatureVerification {
    /// Verify a Tempo signature
    ///
    /// Returns true if the signature is valid and the recovered signer matches.
    /// Reverts with appropriate error otherwise.
    pub fn verify(&mut self, call: verifyCall) -> Result<bool> {
        let signer = call.signer;
        let hash = call.hash;
        let signature_bytes = call.signature;

        let signature = TempoSignature::from_bytes(&signature_bytes)
            .map_err(|_| SignatureVerificationError::invalid_signature())?;

        let verification_gas = precompile_signature_verification_gas(&signature);
        self.storage.deduct_gas(verification_gas)?;

        let recovered = signature
            .recover_signer(&hash)
            .map_err(|_| SignatureVerificationError::invalid_signature())?;

        if let Some(keychain_sig) = signature.as_keychain() {
            self.validate_keychain_authorization(&hash, signer, keychain_sig)?;
        }

        if recovered != signer {
            return Err(SignatureVerificationError::signer_mismatch(signer, recovered).into());
        }

        Ok(true)
    }

    /// Validate that a keychain access key is authorized
    fn validate_keychain_authorization(
        &mut self,
        hash: &B256,
        expected_signer: Address,
        keychain_sig: &KeychainSignature,
    ) -> Result<()> {
        let access_key = keychain_sig
            .key_id(hash)
            .map_err(|_| SignatureVerificationError::invalid_signature())?;

        let user_address = keychain_sig.user_address;

        if user_address != expected_signer {
            return Err(
                SignatureVerificationError::signer_mismatch(expected_signer, user_address).into(),
            );
        }

        let key_slot = AccountKeychain::new().keys[user_address][access_key].base_slot();
        let key_value = self.storage.sload(
            tempo_contracts::precompiles::ACCOUNT_KEYCHAIN_ADDRESS,
            key_slot,
        )?;

        let key_info = crate::account_keychain::AuthorizedKey::decode_from_slot(key_value);

        if key_info.expiry == 0 {
            return Err(SignatureVerificationError::unauthorized_keychain_key().into());
        }

        if key_info.is_revoked {
            return Err(SignatureVerificationError::unauthorized_keychain_key().into());
        }

        let now = self.storage.timestamp().saturating_to::<u64>();
        if key_info.expiry != u64::MAX && key_info.expiry <= now {
            return Err(SignatureVerificationError::unauthorized_keychain_key().into());
        }

        let expected_sig_type = keychain_sig.signature.signature_type() as u8;
        if key_info.signature_type != expected_sig_type {
            return Err(SignatureVerificationError::unauthorized_keychain_key().into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account_keychain::AuthorizedKey,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::{Address, Bytes, keccak256};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_primitives::transaction::PrimitiveSignature;

    /// Helper to create a secp256k1 signature for a hash
    fn sign_secp256k1(signer: &PrivateKeySigner, hash: &B256) -> TempoSignature {
        let sig = signer.sign_hash_sync(hash).unwrap();
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(sig))
    }

    #[test]
    fn test_verify_secp256k1_valid() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut precompile = SignatureVerification::new();

            let signer = PrivateKeySigner::random();
            let signer_addr = signer.address();
            let message_hash = keccak256(b"test message");

            let tempo_sig = sign_secp256k1(&signer, &message_hash);
            let sig_bytes = Bytes::from(tempo_sig.to_bytes());

            let call = verifyCall {
                signer: signer_addr,
                hash: message_hash,
                signature: sig_bytes,
            };

            let result = precompile.verify(call)?;
            assert!(result, "Valid secp256k1 signature should return true");

            Ok(())
        })
    }

    #[test]
    fn test_verify_secp256k1_wrong_signer() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut precompile = SignatureVerification::new();

            let actual_signer = PrivateKeySigner::random();
            let wrong_signer = Address::random();
            let message_hash = keccak256(b"test message");

            let tempo_sig = sign_secp256k1(&actual_signer, &message_hash);
            let sig_bytes = Bytes::from(tempo_sig.to_bytes());

            let call = verifyCall {
                signer: wrong_signer,
                hash: message_hash,
                signature: sig_bytes,
            };

            let result = precompile.verify(call);
            assert!(result.is_err(), "Wrong signer should fail");

            Ok(())
        })
    }

    #[test]
    fn test_verify_secp256k1_wrong_hash() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut precompile = SignatureVerification::new();

            let signer = PrivateKeySigner::random();
            let signer_addr = signer.address();
            let signed_hash = keccak256(b"original message");
            let wrong_hash = keccak256(b"different message");

            let tempo_sig = sign_secp256k1(&signer, &signed_hash);
            let sig_bytes = Bytes::from(tempo_sig.to_bytes());

            let call = verifyCall {
                signer: signer_addr,
                hash: wrong_hash,
                signature: sig_bytes,
            };

            let result = precompile.verify(call);
            assert!(result.is_err(), "Wrong hash should fail (signer mismatch)");

            Ok(())
        })
    }

    #[test]
    fn test_verify_invalid_signature_bytes() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut precompile = SignatureVerification::new();

            let signer_addr = Address::random();
            let message_hash = keccak256(b"test message");

            // Completely invalid signature bytes (wrong length)
            let invalid_sig = Bytes::from(vec![0u8; 10]);

            let call = verifyCall {
                signer: signer_addr,
                hash: message_hash,
                signature: invalid_sig,
            };

            let result = precompile.verify(call);
            assert!(result.is_err(), "Invalid signature bytes should fail");

            Ok(())
        })
    }

    #[test]
    fn test_verify_empty_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut precompile = SignatureVerification::new();

            let signer_addr = Address::random();
            let message_hash = keccak256(b"test message");

            let call = verifyCall {
                signer: signer_addr,
                hash: message_hash,
                signature: Bytes::new(),
            };

            let result = precompile.verify(call);
            assert!(result.is_err(), "Empty signature should fail");

            Ok(())
        })
    }

    #[test]
    fn test_gas_calculation_secp256k1() {
        let signer = PrivateKeySigner::random();
        let hash = keccak256(b"test");
        let sig = sign_secp256k1(&signer, &hash);

        let gas = precompile_signature_verification_gas(&sig);
        // ECRECOVER_GAS (3000) + tempo_signature_verification_gas for secp256k1 (0)
        assert_eq!(gas, 3000, "secp256k1 should cost 3000 gas");
    }

    #[test]
    fn test_gas_calculation_p256() {
        use tempo_primitives::transaction::tt_signature::P256SignatureWithPreHash;

        let p256_sig = P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: B256::ZERO,
            pub_key_y: B256::ZERO,
            pre_hash: false,
        };
        let sig = TempoSignature::Primitive(PrimitiveSignature::P256(p256_sig));

        let gas = precompile_signature_verification_gas(&sig);
        // ECRECOVER_GAS (3000) + P256_VERIFY_GAS (5000) = 8000
        assert_eq!(gas, 8000, "P256 should cost 8000 gas");
    }

    #[test]
    fn test_gas_calculation_keychain_secp256k1() {
        use alloy_signer::Signature;
        use tempo_primitives::transaction::KeychainSignature;

        let inner_sig = PrimitiveSignature::Secp256k1(Signature::new(
            alloy_primitives::U256::ZERO,
            alloy_primitives::U256::ZERO,
            false,
        ));
        let keychain_sig = KeychainSignature::new(Address::ZERO, inner_sig);
        let sig = TempoSignature::Keychain(keychain_sig);

        let gas = precompile_signature_verification_gas(&sig);
        // ECRECOVER_GAS (3000) + 0 (secp256k1) + KEYCHAIN_VALIDATION_GAS (2100 + 900 = 3000) = 6000
        assert_eq!(gas, 6000, "Keychain with secp256k1 should cost 6000 gas");
    }

    #[test]
    fn test_gas_calculation_keychain_p256() {
        use tempo_primitives::transaction::{KeychainSignature, tt_signature::P256SignatureWithPreHash};

        let p256_sig = P256SignatureWithPreHash {
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: B256::ZERO,
            pub_key_y: B256::ZERO,
            pre_hash: false,
        };
        let inner_sig = PrimitiveSignature::P256(p256_sig);
        let keychain_sig = KeychainSignature::new(Address::ZERO, inner_sig);
        let sig = TempoSignature::Keychain(keychain_sig);

        let gas = precompile_signature_verification_gas(&sig);
        // ECRECOVER_GAS (3000) + P256_VERIFY_GAS (5000) + KEYCHAIN_VALIDATION_GAS (3000) = 11000
        assert_eq!(gas, 11000, "Keychain with P256 should cost 11000 gas");
    }

    #[test]
    fn test_keychain_unauthorized_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut precompile = SignatureVerification::new();

            // Create a keychain signature with an access key that doesn't exist
            let root_signer = PrivateKeySigner::random();
            let root_addr = root_signer.address();
            let access_key_signer = PrivateKeySigner::random();
            let message_hash = keccak256(b"test keychain message");

            // Sign with the access key
            let access_sig = access_key_signer.sign_hash_sync(&message_hash)?;
            let inner_sig = PrimitiveSignature::Secp256k1(access_sig);
            let keychain_sig =
                TempoSignature::Keychain(tempo_primitives::transaction::KeychainSignature::new(
                    root_addr,
                    inner_sig,
                ));
            let sig_bytes = Bytes::from(keychain_sig.to_bytes());

            let call = verifyCall {
                signer: root_addr,
                hash: message_hash,
                signature: sig_bytes,
            };

            // Should fail because access key is not authorized (expiry=0)
            let result = precompile.verify(call);
            assert!(
                result.is_err(),
                "Keychain with unauthorized key should fail"
            );

            Ok(())
        })
    }

    #[test]
    fn test_keychain_revoked_key() -> eyre::Result<()> {
        use crate::account_keychain::AccountKeychain;
        use tempo_contracts::precompiles::ACCOUNT_KEYCHAIN_ADDRESS;

        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut precompile = SignatureVerification::new();

            let root_signer = PrivateKeySigner::random();
            let root_addr = root_signer.address();
            let access_key_signer = PrivateKeySigner::random();
            let access_key_addr = access_key_signer.address();
            let message_hash = keccak256(b"test keychain message");

            // Set up a revoked key in storage
            let key_slot =
                AccountKeychain::new().keys[root_addr][access_key_addr].base_slot();
            let revoked_key = AuthorizedKey {
                signature_type: 0, // secp256k1
                expiry: u64::MAX,
                enforce_limits: false,
                is_revoked: true,
            };
            precompile
                .storage
                .sstore(ACCOUNT_KEYCHAIN_ADDRESS, key_slot, revoked_key.encode_to_slot())?;

            // Create keychain signature
            let access_sig = access_key_signer.sign_hash_sync(&message_hash)?;
            let inner_sig = PrimitiveSignature::Secp256k1(access_sig);
            let keychain_sig =
                TempoSignature::Keychain(tempo_primitives::transaction::KeychainSignature::new(
                    root_addr,
                    inner_sig,
                ));
            let sig_bytes = Bytes::from(keychain_sig.to_bytes());

            let call = verifyCall {
                signer: root_addr,
                hash: message_hash,
                signature: sig_bytes,
            };

            let result = precompile.verify(call);
            assert!(result.is_err(), "Keychain with revoked key should fail");

            Ok(())
        })
    }

    #[test]
    fn test_keychain_expired_key() -> eyre::Result<()> {
        use crate::account_keychain::AccountKeychain;
        use tempo_contracts::precompiles::ACCOUNT_KEYCHAIN_ADDRESS;

        // Create storage with a fixed timestamp
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut precompile = SignatureVerification::new();

            let root_signer = PrivateKeySigner::random();
            let root_addr = root_signer.address();
            let access_key_signer = PrivateKeySigner::random();
            let access_key_addr = access_key_signer.address();
            let message_hash = keccak256(b"test keychain message");

            // Set up an expired key (expiry in the past)
            let key_slot =
                AccountKeychain::new().keys[root_addr][access_key_addr].base_slot();
            let expired_key = AuthorizedKey {
                signature_type: 0, // secp256k1
                expiry: 1,         // Very old timestamp
                enforce_limits: false,
                is_revoked: false,
            };
            precompile
                .storage
                .sstore(ACCOUNT_KEYCHAIN_ADDRESS, key_slot, expired_key.encode_to_slot())?;

            // Create keychain signature
            let access_sig = access_key_signer.sign_hash_sync(&message_hash)?;
            let inner_sig = PrimitiveSignature::Secp256k1(access_sig);
            let keychain_sig =
                TempoSignature::Keychain(tempo_primitives::transaction::KeychainSignature::new(
                    root_addr,
                    inner_sig,
                ));
            let sig_bytes = Bytes::from(keychain_sig.to_bytes());

            let call = verifyCall {
                signer: root_addr,
                hash: message_hash,
                signature: sig_bytes,
            };

            let result = precompile.verify(call);
            assert!(result.is_err(), "Keychain with expired key should fail");

            Ok(())
        })
    }

    #[test]
    fn test_keychain_valid() -> eyre::Result<()> {
        use crate::account_keychain::AccountKeychain;
        use tempo_contracts::precompiles::ACCOUNT_KEYCHAIN_ADDRESS;

        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut precompile = SignatureVerification::new();

            let root_signer = PrivateKeySigner::random();
            let root_addr = root_signer.address();
            let access_key_signer = PrivateKeySigner::random();
            let access_key_addr = access_key_signer.address();
            let message_hash = keccak256(b"test keychain message");

            // Set up a valid authorized key
            let key_slot =
                AccountKeychain::new().keys[root_addr][access_key_addr].base_slot();
            let valid_key = AuthorizedKey {
                signature_type: 0, // secp256k1
                expiry: u64::MAX,  // Never expires
                enforce_limits: false,
                is_revoked: false,
            };
            precompile
                .storage
                .sstore(ACCOUNT_KEYCHAIN_ADDRESS, key_slot, valid_key.encode_to_slot())?;

            // Create keychain signature
            let access_sig = access_key_signer.sign_hash_sync(&message_hash)?;
            let inner_sig = PrimitiveSignature::Secp256k1(access_sig);
            let keychain_sig =
                TempoSignature::Keychain(tempo_primitives::transaction::KeychainSignature::new(
                    root_addr,
                    inner_sig,
                ));
            let sig_bytes = Bytes::from(keychain_sig.to_bytes());

            let call = verifyCall {
                signer: root_addr,
                hash: message_hash,
                signature: sig_bytes,
            };

            let result = precompile.verify(call)?;
            assert!(result, "Valid keychain signature should return true");

            Ok(())
        })
    }

    #[test]
    fn test_keychain_wrong_signature_type() -> eyre::Result<()> {
        use crate::account_keychain::AccountKeychain;
        use tempo_contracts::precompiles::ACCOUNT_KEYCHAIN_ADDRESS;

        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut precompile = SignatureVerification::new();

            let root_signer = PrivateKeySigner::random();
            let root_addr = root_signer.address();
            let access_key_signer = PrivateKeySigner::random();
            let access_key_addr = access_key_signer.address();
            let message_hash = keccak256(b"test keychain message");

            // Set up a key authorized for P256 (type 1)
            let key_slot =
                AccountKeychain::new().keys[root_addr][access_key_addr].base_slot();
            let wrong_type_key = AuthorizedKey {
                signature_type: 1, // P256, but we'll sign with secp256k1
                expiry: u64::MAX,
                enforce_limits: false,
                is_revoked: false,
            };
            precompile
                .storage
                .sstore(ACCOUNT_KEYCHAIN_ADDRESS, key_slot, wrong_type_key.encode_to_slot())?;

            // Create keychain signature with secp256k1 (type 0)
            let access_sig = access_key_signer.sign_hash_sync(&message_hash)?;
            let inner_sig = PrimitiveSignature::Secp256k1(access_sig);
            let keychain_sig =
                TempoSignature::Keychain(tempo_primitives::transaction::KeychainSignature::new(
                    root_addr,
                    inner_sig,
                ));
            let sig_bytes = Bytes::from(keychain_sig.to_bytes());

            let call = verifyCall {
                signer: root_addr,
                hash: message_hash,
                signature: sig_bytes,
            };

            let result = precompile.verify(call);
            assert!(
                result.is_err(),
                "Keychain with wrong signature type should fail"
            );

            Ok(())
        })
    }
}
