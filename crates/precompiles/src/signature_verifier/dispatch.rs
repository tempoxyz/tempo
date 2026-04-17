use super::SignatureVerifier;
use crate::{Precompile, charge_input_cost, dispatch_call, view};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{
    ISignatureVerifier, ISignatureVerifier::ISignatureVerifierCalls as ISVCalls,
    SignatureVerifierError,
};
use tempo_primitives::MAX_WEBAUTHN_SIGNATURE_LENGTH;

/// Maximum valid calldata size for the signature-verification entrypoints.
/// `verify(address,bytes32,bytes)` with a WebAuthn signature is the
/// worst case. ABI encoding pads the dynamic `bytes` field independently, so only round the
/// dynamic portion: selector(4) + args(4×32) + padded_sig_bytes.
const MAX_SIGNATURE_CALLDATA_LEN: usize =
    4 + 32 * 4 + (MAX_WEBAUTHN_SIGNATURE_LENGTH + 1).next_multiple_of(32);

#[inline]
fn is_size_guarded_selector(calldata: &[u8]) -> bool {
    calldata
        .first_chunk::<4>()
        .is_none_or(|selector| selector != &ISignatureVerifier::sha384Call::SELECTOR)
}

impl Precompile for SignatureVerifier {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        if is_size_guarded_selector(calldata) && calldata.len() > MAX_SIGNATURE_CALLDATA_LEN {
            return Ok(self
                .storage
                .abi_revert(SignatureVerifierError::invalid_format()));
        }

        dispatch_call(calldata, &[], ISVCalls::abi_decode, |call| match call {
            ISVCalls::recover(call) => view(call, |c| self.recover(c.hash, c.signature)),
            ISVCalls::verify(call) => view(call, |c| {
                self.recover(c.hash, c.signature).map(|sig| sig == c.signer)
            }),
            ISVCalls::verifyES384(call) => view(call, |c| {
                self.verify_es384(c.digest, c.signature, c.publicKey)
            }),
            ISVCalls::sha384(call) => view(call, |c| self.sha384(c.data)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{P384_VERIFY_GAS, sha384_gas_cost},
        *,
    };
    use crate::{
        Precompile, expect_precompile_revert,
        storage::{StorageCtx, evm::EvmPrecompileStorageProvider, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{primitives::B256, sol_types::SolCall};
    use alloy_evm::{EvmEnv, EvmFactory, EvmInternals};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use p384::{
        ecdsa::{SigningKey, signature::hazmat::PrehashSigner},
        elliptic_curve::rand_core::OsRng,
    };
    use revm::{
        database::{CacheDB, EmptyDB},
        precompile::PrecompileError,
    };
    use sha2::{Digest, Sha384};
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::ISignatureVerifier;
    use tempo_evm::TempoEvmFactory;

    fn call_with_gas_limit(calldata: &[u8], gas_limit: u64) -> PrecompileResult {
        let db = CacheDB::new(EmptyDB::new());
        let mut evm = TempoEvmFactory::default().create_evm(db, EvmEnv::default());
        let ctx = evm.ctx_mut();
        let evm_internals =
            EvmInternals::new(&mut ctx.journaled_state, &ctx.block, &ctx.cfg, &ctx.tx);
        let mut storage =
            EvmPrecompileStorageProvider::new_with_gas_limit(evm_internals, &ctx.cfg, gas_limit);

        StorageCtx::enter(&mut storage, || {
            SignatureVerifier::new().call(calldata, Address::ZERO)
        })
    }

    fn sample_verify_es384_calldata() -> eyre::Result<Vec<u8>> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let digest = Sha384::digest(b"tempo es384 gas test");
        let signature: p384::ecdsa::Signature = signing_key.sign_prehash(digest.as_slice())?;

        Ok(ISignatureVerifier::verifyES384Call {
            digest: digest.to_vec().into(),
            signature: signature.to_bytes().to_vec().into(),
            publicKey: verifying_key
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
                .into(),
        }
        .abi_encode())
    }

    #[test]
    fn test_signature_verifier_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
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
    fn test_verify_es384_returns_true_for_valid_signature() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let digest = Sha384::digest(b"tempo es384 dispatch test");
            let signature: p384::ecdsa::Signature = signing_key.sign_prehash(digest.as_slice())?;

            let calldata = ISignatureVerifier::verifyES384Call {
                digest: digest.to_vec().into(),
                signature: signature.to_bytes().to_vec().into(),
                publicKey: verifying_key
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec()
                    .into(),
            }
            .abi_encode();

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::verifyES384Call::abi_decode_returns(&output.bytes)?;
            assert!(ret, "verifyES384 should return true for a valid signature");
            Ok(())
        })
    }

    #[test]
    fn test_verify_es384_returns_false_for_wrong_digest() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let signing_key = SigningKey::random(&mut OsRng);
            let verifying_key = signing_key.verifying_key();
            let digest = Sha384::digest(b"tempo es384 dispatch test");
            let wrong_digest = Sha384::digest(b"tempo es384 wrong digest");
            let signature: p384::ecdsa::Signature = signing_key.sign_prehash(digest.as_slice())?;

            let calldata = ISignatureVerifier::verifyES384Call {
                digest: wrong_digest.to_vec().into(),
                signature: signature.to_bytes().to_vec().into(),
                publicKey: verifying_key
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec()
                    .into(),
            }
            .abi_encode();

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::verifyES384Call::abi_decode_returns(&output.bytes)?;
            assert!(
                !ret,
                "verifyES384 should return false for a mismatched digest"
            );
            Ok(())
        })
    }

    #[test]
    fn test_verify_es384_charges_expected_gas() -> eyre::Result<()> {
        let calldata = sample_verify_es384_calldata()?;
        let expected_gas = input_cost(calldata.len()) + P384_VERIFY_GAS;

        let output = call_with_gas_limit(&calldata, expected_gas)?;

        assert_eq!(output.gas_used, expected_gas);
        Ok(())
    }

    #[test]
    fn test_verify_es384_out_of_gas_before_completion() -> eyre::Result<()> {
        let calldata = sample_verify_es384_calldata()?;
        let expected_gas = input_cost(calldata.len()) + P384_VERIFY_GAS;

        let result = call_with_gas_limit(&calldata, expected_gas - 1);

        assert!(matches!(result, Err(PrecompileError::OutOfGas)));
        Ok(())
    }

    #[test]
    fn test_oversized_calldata_reverts_with_invalid_format() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let calldata = vec![0u8; MAX_SIGNATURE_CALLDATA_LEN + 1];
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
            // Exactly MAX_SIGNATURE_CALLDATA_LEN bytes should pass the size guard (and fail at ABI
            // decode instead). A zeroed selector is unknown, so we expect an
            // UnknownFunctionSelector revert — not InvalidFormat.
            let calldata = vec![0u8; MAX_SIGNATURE_CALLDATA_LEN];
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
    fn test_sha384_hashes_input() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let calldata = ISignatureVerifier::sha384Call {
                data: b"tempo sha384 dispatch".to_vec().into(),
            }
            .abi_encode();

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::sha384Call::abi_decode_returns(&output.bytes)?;
            assert_eq!(
                ret.as_ref(),
                Sha384::digest(b"tempo sha384 dispatch").as_slice()
            );
            Ok(())
        })
    }

    #[test]
    fn test_sha384_charges_expected_gas() -> eyre::Result<()> {
        let data = vec![0xAB; 77];
        let calldata = ISignatureVerifier::sha384Call {
            data: data.clone().into(),
        }
        .abi_encode();
        let expected_gas = input_cost(calldata.len()) + sha384_gas_cost(data.len());

        let output = call_with_gas_limit(&calldata, expected_gas)?;

        assert_eq!(output.gas_used, expected_gas);
        Ok(())
    }

    #[test]
    fn test_sha384_out_of_gas_before_completion() -> eyre::Result<()> {
        let data = vec![0xCD; 77];
        let calldata = ISignatureVerifier::sha384Call {
            data: data.clone().into(),
        }
        .abi_encode();
        let expected_gas = input_cost(calldata.len()) + sha384_gas_cost(data.len());

        let result = call_with_gas_limit(&calldata, expected_gas - 1);

        assert!(matches!(result, Err(PrecompileError::OutOfGas)));
        Ok(())
    }

    #[test]
    fn test_sha384_bypasses_signature_size_guard() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let calldata = ISignatureVerifier::sha384Call {
                data: vec![0xAB; MAX_SIGNATURE_CALLDATA_LEN].into(),
            }
            .abi_encode();

            assert!(calldata.len() > MAX_SIGNATURE_CALLDATA_LEN);

            let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
            let ret = ISignatureVerifier::sha384Call::abi_decode_returns(&output.bytes)?;
            assert_eq!(ret.len(), 48);
            Ok(())
        })
    }
}
