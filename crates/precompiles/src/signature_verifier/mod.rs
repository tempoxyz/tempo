pub mod dispatch;

use crate::{
    SIGNATURE_VERIFIER_ADDRESS,
    account_keychain::{AccountKeychain, AuthorizedKey},
    attested_key_registry::AttestedKeyRegistry,
    configurable_account::valid_account,
    error::{Result, TempoPrecompileError},
    storage::account_config_commitment,
};
use alloy::primitives::{Address, B256, Bytes, KECCAK256_EMPTY};
use tempo_contracts::precompiles::SignatureVerifierError;
use tempo_precompiles_macros::contract;
use tempo_primitives::transaction::{
    ATTESTED_MAX_VALIDITY_WINDOW, AttestedSignature, OwnerApproval, SECP256K1_SIGNATURE_LENGTH,
    SIGNATURE_TYPE_ATTESTED, SignatureType,
    tt_signature::{AccountSignature, KeychainSignature, PrimitiveSignature, TempoSignature},
};
use tracing::trace;

/// Cold storage read cost of each Attested Key Registry read.
const ATTESTED_REGISTRY_READ_GAS: u64 = 2_100;

#[contract(addr = SIGNATURE_VERIFIER_ADDRESS)]
pub struct SignatureVerifier {}

impl SignatureVerifier {
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    /// Recovers the signer of `hash`.
    ///
    /// From T14, an attested signature (type `0x06`) recovers its attested address if it passes
    /// every check of [`Self::verify_attested`], and reverts with `InvalidSignature` otherwise.
    pub fn recover(&self, hash: B256, signature: Bytes) -> Result<Address> {
        if let Some(attested) = self.decode_attested(&signature)? {
            return self
                .verify_attested(hash, &attested)?
                .ok_or_else(|| SignatureVerifierError::invalid_signature().into());
        }

        // Parse and validate signature (handles size checks + type disambiguation).
        let sig = PrimitiveSignature::from_bytes(&signature)
            .map_err(|_| SignatureVerifierError::invalid_format())?;

        // Charge verification gas before performing verification.
        let verify_gas = sig.base_verification_gas();
        self.storage.deduct_gas(verify_gas)?;

        // Verify and recover signer.
        sig.recover_signer(&hash)
            .map_err(|_| SignatureVerifierError::invalid_signature().into())
    }

    /// Returns whether `signature` signs `hash` for `signer`.
    ///
    /// From T14, an attested signature returns `false`, instead of reverting, when it fails the
    /// validity window or registry check, or names another address.
    pub fn verify(&self, signer: Address, hash: B256, signature: Bytes) -> Result<bool> {
        if let Some(attested) = self.decode_attested(&signature)? {
            return Ok(self.verify_attested(hash, &attested)? == Some(signer));
        }
        self.recover(hash, signature)
            .map(|recovered| recovered == signer)
    }

    /// Decodes a `0x06` attested signature from T14, reverting with `InvalidFormat` for a
    /// non-canonical one. Returns `None` for other signature types.
    fn decode_attested(&self, signature: &[u8]) -> Result<Option<AttestedSignature>> {
        if !self.storage.spec().is_t14() {
            return Ok(None);
        }
        match signature {
            [SIGNATURE_TYPE_ATTESTED, ..] if signature.len() != SECP256K1_SIGNATURE_LENGTH => {
                match TempoSignature::from_bytes(signature) {
                    Ok(TempoSignature::Attested(attested)) => Ok(Some(attested)),
                    _ => Err(SignatureVerifierError::invalid_format().into()),
                }
            }
            _ => Ok(None),
        }
    }

    /// Checks an attested signature against current state, as a transaction signature is
    /// checked: `valid_until` within `[now, now + 600]`, the program key current in the
    /// Attested Key Registry, and the P256 signature over the attested digest of `hash`.
    ///
    /// Charges the P256 verification and calldata gas before any check; the two registry reads
    /// charge their own storage gas. Returns the attested address, or `None` if a check fails.
    fn verify_attested(
        &self,
        hash: B256,
        signature: &AttestedSignature,
    ) -> Result<Option<Address>> {
        // `verification_gas` includes the two cold reads, which the storage reads charge.
        self.storage
            .deduct_gas(signature.verification_gas() - 2 * ATTESTED_REGISTRY_READ_GAS)?;
        if !self.attested_key_current(signature)? {
            return Ok(None);
        }
        Ok(signature.recover_signer(&hash).ok())
    }

    /// Returns whether `now <= valid_until <= now + 600` and the Attested Key Registry holds the
    /// program key as current for the policy. Reads the registry only inside the window.
    fn attested_key_current(&self, signature: &AttestedSignature) -> Result<bool> {
        let now = self.storage.timestamp().saturating_to::<u64>();
        if signature.valid_until < now || signature.valid_until - now > ATTESTED_MAX_VALIDITY_WINDOW
        {
            return Ok(false);
        }
        AttestedKeyRegistry::new().program_key_current(
            signature.policy_id,
            signature.program_key_x(),
            signature.program_key_y(),
        )
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
        let attested: Vec<_> = signature
            .signatures()
            .iter()
            .filter_map(OwnerApproval::as_attested)
            .collect();
        let config = signature.config();
        let spec = self.storage.spec();
        let (commitment, has_code) = self.storage.with_account_info(account, |info| {
            Ok((
                account_config_commitment(info, spec)?,
                info.code_hash != KECCAK256_EMPTY,
            ))
        })?;

        let initial_proof_gas = if commitment.is_zero() {
            config
                .derivation_gas()
                .ok_or(TempoPrecompileError::OutOfGas)?
        } else {
            0
        };
        // Each attested approval costs a standalone `0x06` signature: its two registry reads
        // charge their own storage gas instead of the cold reads `verification_gas` includes.
        let verification_gas = signature
            .verification_gas()
            .and_then(|gas| gas.checked_add(initial_proof_gas))
            .and_then(|gas| gas.checked_sub(attested.len() as u64 * 2 * ATTESTED_REGISTRY_READ_GAS))
            .ok_or(TempoPrecompileError::OutOfGas)?;
        self.storage.deduct_gas(verification_gas)?;
        if signature.account() != account || !valid_account(account, spec) || has_code {
            return Ok(false);
        }
        if signature.validate_account_commitment(commitment).is_err() {
            return Ok(false);
        }
        for approval in attested {
            if !self.attested_key_current(approval)? {
                return Ok(false);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attested_key_registry::{
            DEV_CHAIN_ID,
            tests::{NOW, OWNER, program_key, register_dev_key, with_registry},
        },
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::B512;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::transaction::{
        AttestedSignature, ConfigurableAccountConfig, ConfigurableAccountOwner,
        ConfigurableAccountSignature, configurable_account_digest,
        tt_signature::{
            P256SignatureWithPreHash, SIGNATURE_TYPE_P256, SIGNATURE_TYPE_WEBAUTHN,
            derive_p256_address, normalize_p256_s,
        },
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
    fn attested_signatures_are_invalid_format() -> eyre::Result<()> {
        let mut signature = B512::ZERO;
        signature[31] = 1;
        signature[63] = 1;
        let attested = TempoSignature::Attested(AttestedSignature {
            policy_id: B256::repeat_byte(1),
            user_tag: B256::repeat_byte(2),
            program_key: B512::repeat_byte(3),
            valid_until: 1,
            signature,
        });
        let bytes = attested.to_bytes();
        assert_eq!(TempoSignature::from_bytes(&bytes).unwrap(), attested);
        let account = Address::repeat_byte(4);

        // Before T14 the type is unknown.
        let mut storage = HashMapStorageProvider::new_with_spec(1337, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let verifier = SignatureVerifier::new();
            assert_eq!(
                verifier.recover(B256::ZERO, bytes.clone()).unwrap_err(),
                SignatureVerifierError::invalid_format().into()
            );
            assert_eq!(
                verifier
                    .verify(account, B256::ZERO, bytes.clone())
                    .unwrap_err(),
                SignatureVerifierError::invalid_format().into()
            );
        });

        // From T14 a non-canonical encoding is still an invalid format.
        let mut non_canonical = bytes.to_vec();
        non_canonical.push(0);
        let mut storage = HashMapStorageProvider::new_with_spec(1337, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || {
            let verifier = SignatureVerifier::new();
            assert_eq!(
                verifier
                    .verify(account, B256::ZERO, non_canonical.into())
                    .unwrap_err(),
                SignatureVerifierError::invalid_format().into()
            );
            assert_eq!(
                verifier
                    .verify_configurable_account(account, B256::ZERO, &bytes)
                    .unwrap_err(),
                SignatureVerifierError::invalid_format().into()
            );
            let keychain = [&[0x04][..], account.as_slice(), &bytes].concat();
            for result in [
                verifier.verify_keychain(account, B256::ZERO, keychain.clone().into()),
                verifier.verify_keychain_admin(account, B256::ZERO, keychain.into()),
            ] {
                assert_eq!(
                    result.unwrap_err(),
                    SignatureVerifierError::invalid_format().into()
                );
            }
            Ok(())
        })
    }

    /// Signs `hash` as an attested signature for user tag `0x7A…` with the program key of
    /// `seed`, registered under `policy_id`.
    fn attested_sign(policy_id: B256, seed: u8, hash: B256, valid_until: u64) -> AttestedSignature {
        let (x, y) = program_key(seed);
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let mut signature = AttestedSignature {
            policy_id,
            user_tag: B256::repeat_byte(0x7A),
            program_key: B512::from_slice(&[x.as_slice(), y.as_slice()].concat()),
            valid_until,
            signature: B512::ZERO,
        };
        let raw: Signature = key.sign_prehash(signature.digest(hash).as_slice()).unwrap();
        let raw = raw.normalize_s().unwrap_or(raw);
        signature.signature = B512::from_slice(&raw.to_bytes());
        signature
    }

    #[test]
    fn verifies_attested_signatures_against_the_registry() {
        with_registry(DEV_CHAIN_ID, |registry| {
            let policy_id = register_dev_key(registry, 7);
            let sign =
                |hash: B256, valid_until: u64| attested_sign(policy_id, 7, hash, valid_until);
            let verifier = SignatureVerifier::new();
            let hash = B256::repeat_byte(0x42);
            let valid = sign(hash, NOW + 600);
            let signer = valid.address();
            let bytes = TempoSignature::Attested(valid).to_bytes();
            let verify = |signer: Address, hash: B256, signature: &Bytes| {
                verifier.verify(signer, hash, signature.clone()).unwrap()
            };

            assert!(verify(signer, hash, &bytes));
            assert_eq!(verifier.recover(hash, bytes.clone()).unwrap(), signer);
            assert!(!verify(Address::repeat_byte(9), hash, &bytes));
            assert!(!verify(signer, B256::ZERO, &bytes));

            for valid_until in [NOW - 1, NOW + 601] {
                let bytes = TempoSignature::Attested(sign(hash, valid_until)).to_bytes();
                assert!(!verify(signer, hash, &bytes));
                assert_eq!(
                    verifier.recover(hash, bytes).unwrap_err(),
                    SignatureVerifierError::invalid_signature().into()
                );
            }

            registry.set_paused(OWNER, policy_id, true).unwrap();
            assert!(!verify(signer, hash, &bytes));
            registry.set_paused(OWNER, policy_id, false).unwrap();
            assert!(verify(signer, hash, &bytes));

            registry.revoke_keys(OWNER, policy_id).unwrap();
            assert!(!verify(signer, hash, &bytes));
            assert_eq!(
                verifier.recover(hash, bytes).unwrap_err(),
                SignatureVerifierError::invalid_signature().into()
            );
        });
    }

    #[test]
    fn verifies_attested_owner_approvals_against_the_registry() {
        with_registry(DEV_CHAIN_ID, |registry| {
            let policy_id = register_dev_key(registry, 7);
            let attested_owner = attested_sign(policy_id, 7, B256::ZERO, NOW).address();
            let p256_key = SigningKey::from_slice(&[9; 32]).unwrap();
            let (p256_x, p256_y) = program_key(9);
            let p256_owner = derive_p256_address(&p256_x, &p256_y);
            let hash = B256::repeat_byte(0x42);

            // Owners of weight one each: the attested address and a P256 key.
            let account_with = |threshold: u8| {
                let mut owners = [attested_owner, p256_owner]
                    .map(|owner| ConfigurableAccountOwner { owner, weight: 1 })
                    .to_vec();
                owners.sort_by_key(|owner| owner.owner);
                let config = ConfigurableAccountConfig {
                    salt: B256::ZERO,
                    version: 0,
                    threshold,
                    owners,
                };
                (config.derive_account().unwrap(), config)
            };
            let sign = |account: Address,
                        config: &ConfigurableAccountConfig,
                        valid_until: u64,
                        with_p256: bool| {
                let digest = configurable_account_digest(hash, account, config.version);
                let mut approvals: Vec<(Address, OwnerApproval)> = vec![(
                    attested_owner,
                    attested_sign(policy_id, 7, digest, valid_until).into(),
                )];
                if with_p256 {
                    let (raw, _) = p256_key
                        .sign_prehash_recoverable(digest.as_slice())
                        .unwrap();
                    let approval = PrimitiveSignature::P256(P256SignatureWithPreHash {
                        r: B256::from_slice(&raw.r().to_bytes()),
                        s: normalize_p256_s(&raw.s().to_bytes()).unwrap(),
                        pub_key_x: p256_x,
                        pub_key_y: p256_y,
                        pre_hash: false,
                    });
                    approvals.push((p256_owner, approval.into()));
                }
                approvals.sort_by_key(|(owner, _)| *owner);
                TempoSignature::ConfigurableAccount(
                    ConfigurableAccountSignature::try_new(
                        account,
                        config.clone(),
                        approvals.into_iter().map(|(_, approval)| approval),
                    )
                    .unwrap(),
                )
                .to_bytes()
            };
            let verifier = SignatureVerifier::new();
            let verify = |account: Address, bytes: &[u8]| {
                verifier.verify_configurable_account(account, hash, bytes)
            };

            // Threshold 1: the attested approval alone verifies, within its validity window.
            let (single, single_config) = account_with(1);
            assert!(verify(single, &sign(single, &single_config, NOW + 600, false)).unwrap());
            for valid_until in [NOW - 1, NOW + 601] {
                let bytes = sign(single, &single_config, valid_until, false);
                assert!(!verify(single, &bytes).unwrap());
            }

            // Threshold 2: the attested approval needs the P256 approval too.
            let (pair, pair_config) = account_with(2);
            assert_eq!(
                verify(pair, &sign(pair, &pair_config, NOW + 600, false)).unwrap_err(),
                SignatureVerifierError::invalid_signature().into()
            );
            let both = sign(pair, &pair_config, NOW + 600, true);
            assert!(verify(pair, &both).unwrap());

            // A revoked program key no longer approves, alone or with the P256 approval.
            registry.revoke_keys(OWNER, policy_id).unwrap();
            assert!(!verify(single, &sign(single, &single_config, NOW + 600, false)).unwrap());
            assert!(!verify(pair, &both).unwrap());
        });
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
