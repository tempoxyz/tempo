use super::SignatureVerifier;
use crate::{Precompile, charge_input_cost, dispatch, view};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{
    ISignatureVerifier::{self, ISignatureVerifierCalls as ISVCalls},
    SignatureVerifierError,
};
use tempo_primitives::MAX_WEBAUTHN_SIGNATURE_LENGTH;

/// Maximum valid calldata size: `verify(address,bytes32,bytes)` with a WebAuthn signature is the
/// worst case. ABI encoding pads the dynamic `bytes` field independently, so only round the
/// dynamic portion: selector(4) + args(4×32) + padded_sig_bytes.
const MAX_CALLDATA_LEN: usize =
    4 + 32 * 4 + (MAX_WEBAUTHN_SIGNATURE_LENGTH + 1).next_multiple_of(32);

impl Precompile for SignatureVerifier {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        if calldata.len() > MAX_CALLDATA_LEN {
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
        sol_types::{SolCall, SolError},
    };
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_contracts::precompiles::{ISignatureVerifier, UnknownFunctionSelector};
    use tempo_primitives::transaction::tt_signature::{
        KeychainSignature, PrimitiveSignature, TempoSignature,
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
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
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
}
