pub mod dispatch;

use crate::{
    SIGNATURE_VERIFIER_ADDRESS,
    account_keychain::{AccountKeychain, AuthorizedKey},
    configurable_account::{valid_account, valid_account_code},
    error::{Result, TempoPrecompileError},
    storage::account_config_commitment,
};
use alloy::primitives::{Address, B256};
use tempo_contracts::precompiles::SignatureVerifierError;
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::{
    ConfigurableAccountSignature, SignatureType,
    tt_signature::{AccountSignature, KeychainSignature, PrimitiveSignature, TempoSignature},
};
use tracing::trace;

#[contract(addr = SIGNATURE_VERIFIER_ADDRESS)]
pub struct SignatureVerifier {}

impl SignatureVerifier {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Returns the address of the key that produced the primitive `signature` over `hash`.
    ///
    /// Only says which key signed: a migrated account's retired root key still recovers to its
    /// address (TIP-1113). Use [`Self::verify`] to check whether an account approves a hash.
    pub fn recover(&self, hash: B256, signature: &[u8]) -> Result<Address> {
        // Parse and validate signature (handles size checks + type disambiguation).
        let sig = PrimitiveSignature::from_bytes(signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;
        self.recover_primitive(hash, &sig)
    }

    fn recover_primitive(&self, hash: B256, sig: &PrimitiveSignature) -> Result<Address> {
        // Charge verification gas before performing verification.
        self.storage.deduct_gas(sig.base_verification_gas())?;

        // Verify and recover signer.
        sig.recover_signer(&hash)
            .map_err(|_| SignatureVerifierError::invalid_signature().into())
    }

    /// Returns whether `signature` is an active access-key signature for `account`.
    ///
    /// From T14, `false` when a primitive inner signature's key ID has a nonzero configuration
    /// commitment (TIP-1113), even under a stored grant, or when the inner signature type differs
    /// from the stored key type.
    pub fn verify_keychain(&self, account: Address, hash: B256, signature: &[u8]) -> Result<bool> {
        let sig = TempoSignature::from_bytes(signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;
        if self.storage.spec().is_t14()
            && let Some(keychain_sig) = sig.as_keychain()
            && let Some(delegate) = keychain_sig.signature.as_configurable_account()
        {
            if keychain_sig.user_address != account {
                return Ok(false);
            }
            let signing_hash = KeychainSignature::signing_hash(hash, account);
            let Some(commitment) =
                self.verify_configurable_signature(delegate.account(), signing_hash, delegate)?
            else {
                return Ok(false);
            };
            let Some(key) = self.active_key(account, delegate.account(), None)? else {
                return Ok(false);
            };
            return AccountKeychain::accepts_signature_type(
                &key,
                SignatureType::ConfigurableAccount.into(),
                || Ok(!commitment.is_zero()),
            );
        }
        let recovered = self.recover_keychain_key(hash, &sig)?;
        if recovered.account != account || self.storage.is_retired_root(recovered.key_id)? {
            return Ok(false);
        }

        Ok(self
            .active_key(account, recovered.key_id, Some(recovered.signature_type))?
            .is_some())
    }

    /// Returns whether `signature` is an active admin access-key signature for `account`, or its
    /// root key's.
    ///
    /// From T14, `false` when the recovered key ID has a nonzero configuration commitment
    /// (TIP-1113), including the implicit root of `account` itself, or when the inner signature
    /// type of an access-key signature differs from the stored key type.
    pub fn verify_keychain_admin(
        &self,
        account: Address,
        hash: B256,
        signature: &[u8],
    ) -> Result<bool> {
        let sig = TempoSignature::from_bytes(signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;
        self.verify_keychain_admin_signature(account, hash, &sig)
    }

    /// Returns whether `account` approves `hash`: the one check to use for any account and
    /// signature type. It follows `account`'s current state, so it stays correct when the account
    /// migrates or changes owners (TIP-1168).
    ///
    /// By signature type, including the routed checks' reverts:
    /// - primitive: recovers to `account`, and `account` has no configuration commitment
    /// - keychain: as `verifyKeychainAdmin`
    /// - configurable account: as `verifyConfigurableAccount`
    ///
    /// Before T15, only checks that a primitive `signature` recovers to `account`.
    pub fn verify(&self, account: Address, hash: B256, signature: &[u8]) -> Result<bool> {
        if !self.storage.spec().is_t15() {
            return Ok(self.recover(hash, signature)? == account);
        }
        match TempoSignature::from_bytes(signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?
        {
            TempoSignature::Primitive(primitive) => Ok(self.recover_primitive(hash, &primitive)?
                == account
                && !self.storage.is_retired_root(account)?),
            sig @ TempoSignature::Keychain(_) => {
                self.verify_keychain_admin_signature(account, hash, &sig)
            }
            TempoSignature::ConfigurableAccount(configurable) => Ok(self
                .verify_configurable_signature(account, hash, &configurable)?
                .is_some()),
        }
    }

    fn verify_keychain_admin_signature(
        &self,
        account: Address,
        hash: B256,
        sig: &TempoSignature,
    ) -> Result<bool> {
        let recovered = self.recover_keychain_key(hash, sig)?;
        if recovered.account != account || self.storage.is_retired_root(recovered.key_id)? {
            return Ok(false);
        }

        // The root is implicitly admin without a stored access-key grant.
        if recovered.key_id == account {
            return Ok(true);
        }
        Ok(self
            .active_key(account, recovered.key_id, Some(recovered.signature_type))?
            .is_some_and(|key| key.is_admin))
    }

    /// Returns the active access key, or `None` when the keychain rejects it.
    fn active_key(
        &self,
        account: Address,
        key_id: Address,
        signature_type: Option<SignatureType>,
    ) -> Result<Option<AuthorizedKey>> {
        let timestamp = self.storage.timestamp().saturating_to::<u64>();
        let expected_type = signature_type
            .filter(|_| self.storage.spec().is_t14())
            .map(Into::into);
        match AccountKeychain::new().validate_keychain_authorization(
            account,
            key_id,
            timestamp,
            expected_type,
        ) {
            Ok(key) => Ok(Some(key)),
            Err(err) if err.is_system_error() => Err(err),
            Err(err) => {
                trace!(?err, %account, %key_id, "keychain rejected the key");
                Ok(None)
            }
        }
    }

    fn recover_keychain_key(
        &self,
        hash: B256,
        sig: &TempoSignature,
    ) -> Result<RecoveredKeychainKey> {
        let keychain_sig = sig
            .as_keychain()
            .ok_or_else(SignatureVerifierError::invalid_format)?;

        if keychain_sig.is_legacy() {
            return Err(SignatureVerifierError::invalid_format().into());
        }
        let AccountSignature::Primitive(signature) = &keychain_sig.signature else {
            return Err(SignatureVerifierError::invalid_format().into());
        };

        let signing_hash = KeychainSignature::signing_hash(hash, keychain_sig.user_address);
        let key_id = self.recover_primitive(signing_hash, signature)?;
        Ok(RecoveredKeychainKey {
            account: keychain_sig.user_address,
            key_id,
            signature_type: signature.signature_type(),
        })
    }

    pub(crate) fn verify_configurable_account(
        &self,
        account: Address,
        hash: B256,
        bytes: &[u8],
    ) -> Result<bool> {
        let signature = TempoSignature::from_bytes(bytes).map_err(|error| {
            trace!(%error, "malformed configurable account signature");
            SignatureVerifierError::invalid_format()
        })?;
        let Some(signature) = signature.as_configurable_account() else {
            return Err(SignatureVerifierError::invalid_format().into());
        };
        Ok(self
            .verify_configurable_signature(account, hash, signature)?
            .is_some())
    }

    fn verify_configurable_signature(
        &self,
        account: Address,
        hash: B256,
        signature: &ConfigurableAccountSignature,
    ) -> Result<Option<B256>> {
        let spec = self.storage.spec();
        let (commitment, code_hash) = self.storage.with_account_info(account, |info| {
            Ok((account_config_commitment(info, spec)?, info.code_hash))
        })?;

        let initial_proof_gas = if commitment.is_zero() {
            signature
                .config()
                .derivation_gas()
                .ok_or(TempoPrecompileError::OutOfGas)?
        } else {
            0
        };
        let verification_gas = signature
            .verification_gas()
            .and_then(|gas| gas.checked_add(initial_proof_gas))
            .ok_or(TempoPrecompileError::OutOfGas)?;
        self.storage.deduct_gas(verification_gas)?;
        if signature.account() != account
            || !valid_account(account, spec)
            || !valid_account_code(code_hash, commitment)
            || signature.validate_account_commitment(commitment).is_err()
        {
            return Ok(None);
        }

        signature.verify_approvals(hash).map_err(|error| {
            trace!(%error, "invalid configurable account approvals");
            SignatureVerifierError::invalid_signature()
        })?;
        Ok(Some(commitment))
    }
}

/// The access key a keychain signature was made with, and the account it claims to act for.
struct RecoveredKeychainKey {
    /// Account embedded in the keychain signature.
    account: Address,
    /// Key ID recovered from the inner primitive signature.
    key_id: Address,
    /// Type of the inner primitive signature.
    signature_type: SignatureType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::transaction::tt_signature::{
        SIGNATURE_TYPE_P256, SIGNATURE_TYPE_WEBAUTHN, derive_p256_address, normalize_p256_s,
    };

    fn sign_recover(hash: B256, signature: Vec<u8>) -> Result<Address> {
        SignatureVerifier::new().recover(hash, &signature)
    }

    #[test]
    fn test_verify_secp256k1_valid() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let signer = PrivateKeySigner::random();
            let hash = B256::repeat_byte(0xAA);
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

            let hash = B256::repeat_byte(0xBB);
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
