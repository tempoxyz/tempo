use super::SignatureVerifier;
use crate::{Precompile, SelectorSchedule, charge_input_cost, dispatch_call, view};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::PrecompileResult;
use tempo_chainspec::hardfork::TempoHardfork;
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

const T6_ADDED: &[[u8; 4]] = &[ISignatureVerifier::verifyAdminCall::SELECTOR];

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

        dispatch_call(
            calldata,
            &[SelectorSchedule::new(TempoHardfork::T6).with_added(T6_ADDED)],
            ISVCalls::abi_decode,
            |call| match call {
                ISVCalls::recover(call) => view(call, |c| self.recover(c.hash, c.signature)),
                ISVCalls::verify(call) => view(call, |c| {
                    self.recover(c.hash, c.signature).map(|sig| sig == c.signer)
                }),
                ISVCalls::verifyAdmin(call) => {
                    view(call, |c| self.verify_admin(c.account, c.hash, c.signature))
                }
            },
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
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{ISignatureVerifier, UnknownFunctionSelector};

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
    fn test_verify_admin_selector_rejected_before_t6() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
        StorageCtx::enter(&mut storage, || {
            let calldata = ISignatureVerifier::verifyAdminCall {
                account: Address::random(),
                hash: B256::ZERO,
                signature: vec![0u8; 65].into(),
            }
            .abi_encode();

            let result = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            assert!(result.is_revert());
            assert!(
                UnknownFunctionSelector::abi_decode(&result.bytes).is_ok(),
                "verifyAdmin should be selector-gated before T6"
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
    fn test_verify_admin_returns_true_for_root_key() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let signer = PrivateKeySigner::random();
            let hash = B256::from([0xCC; 32]);
            let sig = signer.sign_hash_sync(&hash)?;

            let calldata = ISignatureVerifier::verifyAdminCall {
                account: signer.address(),
                hash,
                signature: sig.as_bytes().to_vec().into(),
            }
            .abi_encode();

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::verifyAdminCall::abi_decode_returns(&output.bytes)?;
            assert!(ret, "root key should verify as admin");
            Ok(())
        })
    }

    #[test]
    fn test_verify_admin_returns_true_for_admin_key() -> eyre::Result<()> {
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

            let hash = B256::from([0xDD; 32]);
            let sig = admin.sign_hash_sync(&hash)?;
            let calldata = ISignatureVerifier::verifyAdminCall {
                account,
                hash,
                signature: sig.as_bytes().to_vec().into(),
            }
            .abi_encode();

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::verifyAdminCall::abi_decode_returns(&output.bytes)?;
            assert!(ret, "admin access key should verify as admin");
            Ok(())
        })
    }

    #[test]
    fn test_verify_admin_returns_false_for_non_admin_key() -> eyre::Result<()> {
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

            let hash = B256::from([0xEE; 32]);
            let sig = access_key.sign_hash_sync(&hash)?;
            let calldata = ISignatureVerifier::verifyAdminCall {
                account,
                hash,
                signature: sig.as_bytes().to_vec().into(),
            }
            .abi_encode();

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::verifyAdminCall::abi_decode_returns(&output.bytes)?;
            assert!(!ret, "non-admin access key should not verify as admin");
            Ok(())
        })
    }

    #[test]
    fn test_verify_admin_returns_false_for_invalid_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let signer = PrivateKeySigner::random();
            let signed_hash = B256::from([0x11; 32]);
            let checked_hash = B256::from([0x22; 32]);
            let sig = signer.sign_hash_sync(&signed_hash)?;

            let calldata = ISignatureVerifier::verifyAdminCall {
                account: signer.address(),
                hash: checked_hash,
                signature: sig.as_bytes().to_vec().into(),
            }
            .abi_encode();

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::verifyAdminCall::abi_decode_returns(&output.bytes)?;
            assert!(!ret, "wrong digest should not verify as admin");
            Ok(())
        })
    }

    #[test]
    fn test_verify_admin_returns_false_for_malformed_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let calldata = ISignatureVerifier::verifyAdminCall {
                account: Address::random(),
                hash: B256::ZERO,
                signature: vec![0u8; 64].into(),
            }
            .abi_encode();

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::verifyAdminCall::abi_decode_returns(&output.bytes)?;
            assert!(!ret, "malformed signature should not verify as admin");
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
