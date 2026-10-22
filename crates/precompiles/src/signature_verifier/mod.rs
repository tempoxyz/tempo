pub mod dispatch;

use crate::{
    SIGNATURE_VERIFIER_ADDRESS,
    account_keychain::{AccountKeychain, AuthorizedKey},
    configurable_account::{initial_account_proof_gas, valid_account},
    error::{Result, TempoPrecompileError},
    storage::{account_config_commitment, keccak_cost},
};
use alloy::{
    primitives::{Address, B256, Bytes, KECCAK256_EMPTY},
    rlp::{self, Encodable},
};
use evm2::interpreter::gas::STANDARD_TOKEN_COST;
use tempo_contracts::precompiles::SignatureVerifierError;
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::{
    ConfigurableAccountSignature, SignatureType,
    configurable_account::CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN,
    tt_signature::{AccountSignature, KeychainSignature, PrimitiveSignature, TempoSignature},
};
use tracing::trace;

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

    pub fn recover(&self, hash: B256, signature: Bytes) -> Result<Address> {
        // Parse and validate signature (handles size checks + type disambiguation).
        let sig = PrimitiveSignature::from_bytes(&signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;

        // Charge verification gas before performing verification.
        let verify_gas = match &sig {
            PrimitiveSignature::Secp256k1(_) => SECP256K1_VERIFY_GAS,
            PrimitiveSignature::P256(_) => P256_VERIFY_GAS,
            PrimitiveSignature::WebAuthn(_) => WEBAUTHN_VERIFY_GAS,
        };
        self.storage.deduct_gas(verify_gas)?;

        // Verify and recover signer.
        sig.recover_signer(&hash)
            .map_err(|_| SignatureVerifierError::invalid_signature().into())
    }

    /// Returns whether `signature` is an active access-key signature for `account`.
    ///
    /// From T14, `false` when the recovered key ID has a nonzero configuration commitment
    /// (TIP-1112), even under a stored grant, or when the inner signature type differs from the
    /// stored key type.
    pub fn verify_keychain(&self, account: Address, hash: B256, signature: Bytes) -> Result<bool> {
        let recovered = self.recover_keychain_key(hash, signature)?;
        if recovered.account != account || self.storage.is_retired_root(recovered.key_id)? {
            return Ok(false);
        }

        Ok(self
            .active_key(account, recovered.key_id, recovered.signature_type)?
            .is_some())
    }

    /// Returns whether `signature` is an active admin access-key signature for `account`, or its
    /// root key's.
    ///
    /// From T14, `false` when the recovered key ID has a nonzero configuration commitment
    /// (TIP-1112), including the implicit root of `account` itself, or when the inner signature
    /// type of an access-key signature differs from the stored key type.
    pub fn verify_keychain_admin(
        &self,
        account: Address,
        hash: B256,
        signature: Bytes,
    ) -> Result<bool> {
        let recovered = self.recover_keychain_key(hash, signature)?;
        if recovered.account != account || self.storage.is_retired_root(recovered.key_id)? {
            return Ok(false);
        }

        // The root is implicitly admin without a stored access-key grant.
        if recovered.key_id == account {
            return Ok(true);
        }
        Ok(self
            .active_key(account, recovered.key_id, recovered.signature_type)?
            .is_some_and(|key| key.is_admin))
    }

    fn verify_configurable_account(
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
        let config = signature.config();
        let spec = self.storage.spec();
        let (commitment, has_code) = self.storage.with_account_info(account, |info| {
            Ok((
                account_config_commitment(info, spec)?,
                info.code_hash != KECCAK256_EMPTY,
            ))
        })?;

        let initial_proof_gas = if commitment.is_zero() {
            initial_account_proof_gas(config)?
        } else {
            0
        };
        let verification_gas = configurable_account_verification_gas(signature)?
            .checked_add(initial_proof_gas)
            .ok_or(TempoPrecompileError::OutOfGas)?;
        self.storage.deduct_gas(verification_gas)?;
        if signature.account() != account || !valid_account(account, spec) || has_code {
            return Ok(false);
        }
        let factory = self
            .storage
            .with_block_env(|block_env| block_env.ext.configurable_account_recovery_factory());
        if signature
            .validate_account_commitment(commitment, factory)
            .is_err()
        {
            return Ok(false);
        }

        signature.verify_approvals(hash).map_err(|error| {
            trace!(%error, "invalid configurable account approvals");
            SignatureVerifierError::invalid_signature()
        })?;
        Ok(true)
    }

    /// Returns the active access key, or `None` when the keychain rejects it.
    fn active_key(
        &self,
        account: Address,
        key_id: Address,
        signature_type: SignatureType,
    ) -> Result<Option<AuthorizedKey>> {
        let timestamp = self.storage.timestamp().saturating_to::<u64>();
        let expected_type = self
            .storage
            .spec()
            .is_t14()
            .then_some(signature_type.into());
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

    fn recover_keychain_key(&self, hash: B256, signature: Bytes) -> Result<RecoveredKeychainKey> {
        let sig = TempoSignature::from_bytes(&signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;
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
        let key_id = self.recover(signing_hash, signature.to_bytes())?;
        Ok(RecoveredKeychainKey {
            account: keychain_sig.user_address,
            key_id,
            signature_type: signature.signature_type(),
        })
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

/// Full configurable account verification cost for a registered account, before account access.
/// Initial address derivation is charged separately when the stored commitment is zero.
///
/// Fails with `OutOfGas` if the cost overflows `u64`.
pub fn configurable_account_verification_gas(
    signature: &ConfigurableAccountSignature,
) -> Result<u64> {
    let mut witness = rlp::encode(signature.account());
    signature.config().encode(&mut witness);
    signature
        .signatures()
        .iter()
        .map(primitive_verification_gas)
        .chain([
            calldata_gas(&witness),
            keccak_cost(signature.config().commitment_preimage_len())?,
            keccak_cost(CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN.len() + 32 + 20 + 8)?,
        ])
        .try_fold(0u64, u64::checked_add)
        .ok_or(TempoPrecompileError::OutOfGas)
}

/// Full primitive verification cost, including `WebAuthn` data calldata.
///
/// Unlike `tempo_evm`'s `primitive_signature_verification_gas`, this does not subtract the
/// ecrecover baseline already covered by ordinary intrinsic gas.
fn primitive_verification_gas(signature: &PrimitiveSignature) -> u64 {
    match signature {
        PrimitiveSignature::Secp256k1(_) => SECP256K1_VERIFY_GAS,
        PrimitiveSignature::P256(_) => P256_VERIFY_GAS,
        PrimitiveSignature::WebAuthn(sig) => WEBAUTHN_VERIFY_GAS + calldata_gas(&sig.webauthn_data),
    }
}

/// Istanbul calldata cost of `input`: one token per zero byte, four per nonzero byte.
fn calldata_gas(input: &[u8]) -> u64 {
    input
        .iter()
        .map(|byte| if *byte == 0 { 1 } else { 4 })
        .sum::<u64>()
        * u64::from(STANDARD_TOKEN_COST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::transaction::{
        ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        tt_signature::{SIGNATURE_TYPE_P256, SIGNATURE_TYPE_WEBAUTHN},
    };

    fn sign_recover(hash: B256, signature: Vec<u8>) -> Result<Address> {
        SignatureVerifier::new().recover(hash, Bytes::from(signature))
    }

    #[test]
    fn keychain_verification_rejects_configurable_account() -> eyre::Result<()> {
        let account = Address::repeat_byte(1);
        let configurable_account = ConfigurableAccountSignature::try_new(
            Address::repeat_byte(2),
            ConfigurableAccountConfig {
                salt: B256::ZERO,
                version: 1,
                threshold: 1,
                owners: vec![ConfigurableAccountOwner {
                    owner: Address::repeat_byte(3),
                    weight: 1,
                }],
            },
            vec![PrimitiveSignature::default()],
        )
        .unwrap();
        let signature =
            TempoSignature::Keychain(KeychainSignature::new(account, configurable_account));
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || {
            let verifier = SignatureVerifier::new();
            for result in [
                verifier.verify_keychain(account, B256::ZERO, signature.to_bytes()),
                verifier.verify_keychain_admin(account, B256::ZERO, signature.to_bytes()),
            ] {
                assert_eq!(
                    result.unwrap_err(),
                    SignatureVerifierError::invalid_format().into()
                );
            }
            Ok(())
        })
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
