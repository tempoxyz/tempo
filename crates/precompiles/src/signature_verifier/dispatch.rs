use super::SignatureVerifier;
use crate::{Precompile, charge_input_cost, dispatch, view};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{ISignatureVerifier, SignatureVerifierError};
use tempo_primitives::{
    MAX_WEBAUTHN_SIGNATURE_LENGTH,
    transaction::multisig::{
        MAX_MULTISIG_OWNER_SIGNATURE_BYTES, MAX_MULTISIG_OWNERS, MAX_MULTISIG_SIGNATURES,
    },
};

/// Maximum valid calldata size: `verify(address,bytes32,bytes)` with a WebAuthn signature is the
/// worst case. ABI encoding pads the dynamic `bytes` field independently, so only round the
/// dynamic portion: selector(4) + args(4×32) + padded_sig_bytes.
const MAX_CALLDATA_LEN: usize =
    4 + 32 * 4 + (MAX_WEBAUTHN_SIGNATURE_LENGTH + 1).next_multiple_of(32);

// Upper bound for 0x05 || rlp([account, config, approvals]) with 48 owners and 8 approvals.
const MAX_OWNERS_RLP_PAYLOAD: usize = MAX_MULTISIG_OWNERS * (1 + 21 + 2);
const MAX_CONFIG_RLP_PAYLOAD: usize =
    33 + 9 + 2 + alloy::rlp::length_of_length(MAX_OWNERS_RLP_PAYLOAD) + MAX_OWNERS_RLP_PAYLOAD;
const MAX_APPROVALS_RLP_PAYLOAD: usize = MAX_MULTISIG_SIGNATURES
    * (alloy::rlp::length_of_length(MAX_MULTISIG_OWNER_SIGNATURE_BYTES)
        + MAX_MULTISIG_OWNER_SIGNATURE_BYTES);
const MAX_MULTISIG_RLP_PAYLOAD: usize = 21
    + alloy::rlp::length_of_length(MAX_CONFIG_RLP_PAYLOAD)
    + MAX_CONFIG_RLP_PAYLOAD
    + alloy::rlp::length_of_length(MAX_APPROVALS_RLP_PAYLOAD)
    + MAX_APPROVALS_RLP_PAYLOAD;
const MAX_MULTISIG_CALLDATA_LEN: usize = 4
    + 32 * 4
    + (1 + alloy::rlp::length_of_length(MAX_MULTISIG_RLP_PAYLOAD) + MAX_MULTISIG_RLP_PAYLOAD)
        .next_multiple_of(32);

impl Precompile for SignatureVerifier {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        let max_len = if self.storage.spec().is_t14()
            && calldata.starts_with(&ISignatureVerifier::verifyMultisigCall::SELECTOR)
        {
            MAX_MULTISIG_CALLDATA_LEN
        } else {
            MAX_CALLDATA_LEN
        };
        if calldata.len() > max_len {
            return Ok(self
                .storage
                .abi_revert(SignatureVerifierError::invalid_format()));
        }

        dispatch!(
            calldata,
            |call| match call {
                ISignatureVerifier::ISignatureVerifierCalls {
                    recover(call) => view(call, |c| self.recover(c.hash, c.signature)),
                    verify(call) => view(call, |c| {
                        self.recover(c.hash, c.signature).map(|sig| sig == c.signer)
                    }),
                    #[schedule(since = T6)]
                    verifyKeychain(call) => view(call, |c| {
                        self.verify_keychain(c.account, c.hash, c.signature)
                    }),
                    #[schedule(since = T6)]
                    verifyKeychainAdmin(call) => view(call, |c| {
                        self.verify_keychain_admin(c.account, c.hash, c.signature)
                    }),
                    #[schedule(since = T14)]
                    verifyMultisig(call) => view(call, |c| {
                        self.verify_multisig(c.account, c.hash, c.signature)
                    }),
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Precompile,
        account_keychain::{AccountKeychain, KeyRestrictions, SignatureType},
        expect_precompile_revert,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::B256,
        sol_types::{SolCall, SolError, SolInterface},
    };
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        ISignatureVerifier, ISignatureVerifier::ISignatureVerifierCalls as ISVCalls,
        UnknownFunctionSelector,
    };
    use tempo_primitives::transaction::{
        MultisigConfig, MultisigOwner, MultisigSignature,
        tt_signature::{
            KeychainSignature, P256SignatureWithPreHash, PrimitiveSignature, TempoSignature,
            WebAuthnSignature, derive_p256_address,
        },
    };

    fn call_verify_keychain(
        account: Address,
        hash: B256,
        signature: Vec<u8>,
    ) -> eyre::Result<bool> {
        let calldata = ISignatureVerifier::verifyKeychainCall {
            account,
            hash,
            signature: signature.into(),
        }
        .abi_encode();

        let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
        let ret = ISignatureVerifier::verifyKeychainCall::abi_decode_returns(&output.bytes)?;
        Ok(ret)
    }

    fn call_verify_keychain_admin(
        account: Address,
        hash: B256,
        signature: Vec<u8>,
    ) -> eyre::Result<bool> {
        let calldata = ISignatureVerifier::verifyKeychainAdminCall {
            account,
            hash,
            signature: signature.into(),
        }
        .abi_encode();

        let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
        let ret = ISignatureVerifier::verifyKeychainAdminCall::abi_decode_returns(&output.bytes)?;
        Ok(ret)
    }

    fn keychain_signature(
        account: Address,
        key: &PrivateKeySigner,
        hash: B256,
    ) -> eyre::Result<Vec<u8>> {
        let signing_hash = KeychainSignature::signing_hash(hash, account);
        let inner = key.sign_hash_sync(&signing_hash)?;
        Ok(TempoSignature::Keychain(KeychainSignature::new(
            account,
            PrimitiveSignature::Secp256k1(inner),
        ))
        .to_bytes()
        .to_vec())
    }

    #[test]
    fn test_signature_verifier_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || {
            let mut verifier = SignatureVerifier::new();

            let unsupported = check_selector_coverage(
                &mut verifier,
                ISVCalls::SELECTORS,
                "ISignatureVerifier",
                ISVCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_selector_rejected_before_t6() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let calldata = ISignatureVerifier::verifyKeychainCall {
                account: Address::random(),
                hash: B256::ZERO,
                signature: vec![0u8; 65].into(),
            }
            .abi_encode();

            let result = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            assert!(result.is_revert());
            assert!(
                UnknownFunctionSelector::abi_decode(&result.bytes).is_ok(),
                "verifyKeychain should be selector-gated before T6"
            );
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_admin_selector_rejected_before_t6() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let calldata = ISignatureVerifier::verifyKeychainAdminCall {
                account: Address::random(),
                hash: B256::ZERO,
                signature: vec![0u8; 65].into(),
            }
            .abi_encode();

            let result = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            assert!(result.is_revert());
            assert!(
                UnknownFunctionSelector::abi_decode(&result.bytes).is_ok(),
                "verifyKeychainAdmin should be selector-gated before T6"
            );
            Ok(())
        })
    }

    #[test]
    fn test_verify_multisig_selector_rejected_before_t14() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let calldata = ISignatureVerifier::verifyMultisigCall {
                account: Address::repeat_byte(0x71),
                hash: B256::ZERO,
                signature: vec![0x05].into(),
            }
            .abi_encode();
            let result = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            assert!(UnknownFunctionSelector::abi_decode(&result.bytes).is_ok());
            Ok(())
        })
    }

    #[test]
    fn test_verify_returns_true_for_correct_signer() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let signer = PrivateKeySigner::random();
            let hash = B256::from([0xAA; 32]);
            let sig = signer.sign_hash_sync(&hash)?;

            let calldata = ISignatureVerifier::verifyCall {
                signer: signer.address(),
                hash,
                signature: sig.as_bytes().to_vec().into(),
            }
            .abi_encode();

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::verifyCall::abi_decode_returns(&output.bytes)?;
            assert!(ret, "verify should return true for the correct signer");
            Ok(())
        })
    }

    #[test]
    fn test_verify_returns_false_for_wrong_signer() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let signer = PrivateKeySigner::random();
            let hash = B256::from([0xBB; 32]);
            let sig = signer.sign_hash_sync(&hash)?;

            let calldata = ISignatureVerifier::verifyCall {
                signer: Address::random(),
                hash,
                signature: sig.as_bytes().to_vec().into(),
            }
            .abi_encode();

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::verifyCall::abi_decode_returns(&output.bytes)?;
            assert!(!ret, "verify should return false for a wrong signer");
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_returns_true_for_active_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let account = Address::random();
            let access_key = PrivateKeySigner::random();

            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_tx_origin(account)?;
            keychain.authorize_key(
                account,
                access_key.address(),
                SignatureType::Secp256k1,
                KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
                None,
            )?;

            let hash = B256::from([0x44; 32]);
            let signature = keychain_signature(account, &access_key, hash)?;

            let ret = call_verify_keychain(account, hash, signature)?;
            assert!(ret, "active keychain key should verify");
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_returns_false_for_missing_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let account = Address::random();
            let access_key = PrivateKeySigner::random();
            let hash = B256::from([0x55; 32]);
            let signature = keychain_signature(account, &access_key, hash)?;

            let ret = call_verify_keychain(account, hash, signature)?;
            assert!(!ret, "unknown keychain key should not verify");
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_returns_false_for_root_key_without_access_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let root = PrivateKeySigner::random();
            let account = root.address();
            let hash = B256::from([0x56; 32]);
            let signature = keychain_signature(account, &root, hash)?;

            let ret = call_verify_keychain(account, hash, signature)?;
            assert!(
                !ret,
                "root key should not verify as an active access key unless explicitly stored"
            );
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_returns_false_for_account_mismatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let account = Address::random();
            let access_key = PrivateKeySigner::random();

            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_tx_origin(account)?;
            keychain.authorize_key(
                account,
                access_key.address(),
                SignatureType::Secp256k1,
                KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
                None,
            )?;

            let hash = B256::from([0x57; 32]);
            let signature = keychain_signature(account, &access_key, hash)?;

            let ret = call_verify_keychain(Address::random(), hash, signature)?;
            assert!(
                !ret,
                "keychain signature should not verify for a different account"
            );
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_admin_returns_true_for_admin_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let account = Address::random();
            let admin = PrivateKeySigner::random();

            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_tx_origin(account)?;
            keychain.authorize_admin_key(
                account,
                admin.address(),
                SignatureType::Secp256k1,
                None,
            )?;

            let hash = B256::from([0x66; 32]);
            let signature = keychain_signature(account, &admin, hash)?;

            let ret = call_verify_keychain_admin(account, hash, signature)?;
            assert!(ret, "active admin keychain key should verify as admin");
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_stored_type_check_starts_at_t14() -> eyre::Result<()> {
        let account = Address::random();
        let hash = B256::from([0x69; 32]);
        let signing_key = SigningKey::random(&mut OsRng);
        let point = signing_key.verifying_key().to_encoded_point(false);
        let pub_key_x = B256::from_slice(point.x().unwrap());
        let pub_key_y = B256::from_slice(point.y().unwrap());
        let key_id = derive_p256_address(&pub_key_x, &pub_key_y);
        let signing_hash = KeychainSignature::signing_hash(hash, account);
        let (signature, _) = signing_key.sign_prehash_recoverable(signing_hash.as_slice())?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature = TempoSignature::Keychain(KeychainSignature::new(
            account,
            PrimitiveSignature::P256(P256SignatureWithPreHash {
                r: B256::from_slice(&signature.r().to_bytes()),
                s: B256::from_slice(&signature.s().to_bytes()),
                pub_key_x,
                pub_key_y,
                pre_hash: false,
            }),
        ))
        .to_bytes()
        .to_vec();

        // P256 and WebAuthn derive the same key address from the same public key.
        for (spec, stored_type, expected) in [
            (TempoHardfork::T13, SignatureType::P256, true),
            (TempoHardfork::T13, SignatureType::WebAuthn, true),
            (TempoHardfork::T14, SignatureType::P256, true),
            (TempoHardfork::T14, SignatureType::WebAuthn, false),
            (TempoHardfork::T14, SignatureType::Multisig, false),
        ] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, spec);
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                let mut keychain = AccountKeychain::new();
                keychain.initialize()?;
                keychain.set_tx_origin(account)?;
                keychain.authorize_admin_key(account, key_id, stored_type, None)?;

                for actual in [
                    call_verify_keychain(account, hash, signature.clone())?,
                    call_verify_keychain_admin(account, hash, signature.clone())?,
                ] {
                    assert_eq!(actual, expected, "{spec:?}, {stored_type:?}");
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn test_verify_keychain_admin_returns_true_for_root_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let root = PrivateKeySigner::random();
            let account = root.address();
            let hash = B256::from([0x67; 32]);
            let signature = keychain_signature(account, &root, hash)?;

            let ret = call_verify_keychain_admin(account, hash, signature)?;
            assert!(ret, "root keychain key should verify as admin");
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_admin_returns_false_for_account_mismatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let account = Address::random();
            let admin = PrivateKeySigner::random();

            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_tx_origin(account)?;
            keychain.authorize_admin_key(
                account,
                admin.address(),
                SignatureType::Secp256k1,
                None,
            )?;

            let hash = B256::from([0x68; 32]);
            let signature = keychain_signature(account, &admin, hash)?;

            let ret = call_verify_keychain_admin(Address::random(), hash, signature)?;
            assert!(
                !ret,
                "admin keychain signature should not verify for a different account"
            );
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_admin_returns_false_for_non_admin_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let account = Address::random();
            let access_key = PrivateKeySigner::random();

            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_tx_origin(account)?;
            keychain.authorize_key(
                account,
                access_key.address(),
                SignatureType::Secp256k1,
                KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
                None,
            )?;

            let hash = B256::from([0x77; 32]);
            let signature = keychain_signature(account, &access_key, hash)?;

            let ret = call_verify_keychain_admin(account, hash, signature)?;
            assert!(!ret, "non-admin keychain key should not verify as admin");
            Ok(())
        })
    }

    #[test]
    fn test_verify_keychain_reverts_for_non_keychain_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let signer = PrivateKeySigner::random();
            let hash = B256::from([0x88; 32]);
            let sig = signer.sign_hash_sync(&hash)?;

            let calldata = ISignatureVerifier::verifyKeychainCall {
                account: signer.address(),
                hash,
                signature: sig.as_bytes().to_vec().into(),
            }
            .abi_encode();

            let result = SignatureVerifier::new().call(&calldata, Address::ZERO);
            expect_precompile_revert(&result, SignatureVerifierError::invalid_format());
            Ok(())
        })
    }

    #[test]
    fn test_oversized_calldata_reverts_with_invalid_format() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let calldata = vec![0u8; MAX_CALLDATA_LEN + 1];
            let result = SignatureVerifier::new().call(&calldata, Address::ZERO);

            expect_precompile_revert(&result, SignatureVerifierError::invalid_format());
            Ok(())
        })
    }

    #[test]
    fn test_max_webauthn_verify_passes_size_guard() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut sig = vec![0x02u8];
            sig.extend_from_slice(&[0u8; MAX_WEBAUTHN_SIGNATURE_LENGTH]);

            let calldata = ISignatureVerifier::verifyCall {
                signer: Address::ZERO,
                hash: B256::ZERO,
                signature: sig.into(),
            }
            .abi_encode();

            let result = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            // Should NOT be rejected by the size guard, should fail later at signature validation
            assert!(
                SignatureVerifierError::abi_decode(&result.bytes)
                    .map(|e| e != SignatureVerifierError::invalid_format())
                    .unwrap_or(true),
                "max-size WebAuthn calldata was wrongly rejected by size guard"
            );
            Ok(())
        })
    }

    #[test]
    fn test_max_calldata_is_not_rejected() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            // Exactly MAX_CALLDATA_LEN bytes should pass the size guard (and fail at ABI
            // decode instead). A zeroed selector is unknown, so we expect an
            // UnknownFunctionSelector revert — not InvalidFormat.
            let calldata = vec![0u8; MAX_CALLDATA_LEN];
            let result = SignatureVerifier::new().call(&calldata, Address::ZERO)?;

            assert!(result.is_revert());
            assert!(
                SignatureVerifierError::abi_decode(&result.bytes).is_err(),
                "should not be an InvalidFormat revert"
            );
            Ok(())
        })
    }

    #[test]
    fn test_max_multisig_calldata_fits_size_guard() {
        let owners = (1..=MAX_MULTISIG_OWNERS as u8)
            .map(|index| MultisigOwner {
                owner: Address::repeat_byte(index),
                weight: 1,
            })
            .collect();
        let approval = PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: vec![0xff; MAX_WEBAUTHN_SIGNATURE_LENGTH - 128].into(),
            r: B256::ZERO,
            s: B256::ZERO,
            pub_key_x: B256::ZERO,
            pub_key_y: B256::ZERO,
        });
        let signature = MultisigSignature::try_new(
            Address::repeat_byte(0x71),
            MultisigConfig {
                salt: B256::repeat_byte(0xff),
                version: u64::MAX,
                threshold: 8,
                owners,
            },
            vec![approval; MAX_MULTISIG_SIGNATURES],
        )
        .unwrap();
        let calldata = ISignatureVerifier::verifyMultisigCall {
            account: signature.account(),
            hash: B256::ZERO,
            signature: TempoSignature::Multisig(signature).to_bytes(),
        }
        .abi_encode();
        assert!(calldata.len() <= MAX_MULTISIG_CALLDATA_LEN);
    }
}
