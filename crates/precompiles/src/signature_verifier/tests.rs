use super::*;
use crate::{
    Precompile, expect_precompile_revert,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
};
use alloy::{primitives::Signature, sol_types::SolCall};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::ISignatureVerifier;
use tempo_primitives::transaction::{
    MultisigConfig, MultisigOwner, MultisigSignature,
    tt_signature::{SIGNATURE_TYPE_P256, SIGNATURE_TYPE_WEBAUTHN},
};

fn sign_recover(hash: B256, signature: Vec<u8>) -> Result<Address> {
    SignatureVerifier::new().recover(hash, Bytes::from(signature))
}

fn multisig_signature(
    account: Address,
    config: MultisigConfig,
    hash: B256,
    signers: &[&PrivateKeySigner],
) -> eyre::Result<Vec<u8>> {
    let digest = tempo_primitives::transaction::multisig_digest(hash, account, config.version);
    let approvals = signers
        .iter()
        .map(|signer| {
            signer
                .sign_hash_sync(&digest)
                .map(PrimitiveSignature::Secp256k1)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(
        TempoSignature::Multisig(MultisigSignature::try_new(account, config, approvals).unwrap())
            .to_bytes()
            .to_vec(),
    )
}

fn verify_multisig(account: Address, hash: B256, signature: Vec<u8>) -> eyre::Result<bool> {
    let calldata = ISignatureVerifier::verifyMultisigCall {
        account,
        hash,
        signature: signature.into(),
    }
    .abi_encode();
    let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
    Ok(ISignatureVerifier::verifyMultisigCall::abi_decode_returns(
        &output.bytes,
    )?)
}

#[test]
fn test_verify_multisig_unregistered_and_registered() -> eyre::Result<()> {
    let factory = Address::repeat_byte(0x71);
    let signer = PrivateKeySigner::random();
    let config = MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 200,
        owners: vec![MultisigOwner {
            owner: signer.address(),
            weight: 200,
        }],
    };
    let account = config.derive_account(factory).unwrap();
    let hash = B256::repeat_byte(0x42);
    let signature = multisig_signature(account, config.clone(), hash, &[&signer])?;
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14)
        .with_multisig_recovery_factory(factory);
    StorageCtx::enter(&mut storage, || {
        assert!(verify_multisig(account, hash, signature.clone())?);
        assert_eq!(StorageCtx.config_commitment(account)?, B256::ZERO);

        StorageCtx.set_config_commitment(
            account,
            config.commitment().unwrap(),
            crate::storage::ConfigCommitmentWriteGas::Intrinsic,
        )?;
        assert!(verify_multisig(account, hash, signature.clone())?);
        assert!(!verify_multisig(
            Address::repeat_byte(0x72),
            hash,
            signature.clone()
        )?);
        let wrong_hash_call = ISignatureVerifier::verifyMultisigCall {
            account,
            hash: B256::repeat_byte(0x43),
            signature: signature.clone().into(),
        }
        .abi_encode();
        expect_precompile_revert(
            &SignatureVerifier::new().call(&wrong_hash_call, Address::ZERO),
            SignatureVerifierError::invalid_signature(),
        );
        StorageCtx.set_config_commitment(
            account,
            B256::repeat_byte(0x12),
            crate::storage::ConfigCommitmentWriteGas::Precompile,
        )?;
        assert!(!verify_multisig(account, hash, signature)?);
        Ok(())
    })
}

#[test]
fn test_verify_multisig_rejects_invalid_state_and_signature() -> eyre::Result<()> {
    let factory = Address::repeat_byte(0x71);
    let signer = PrivateKeySigner::random();
    let config = MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 1,
        owners: vec![MultisigOwner {
            owner: signer.address(),
            weight: 1,
        }],
    };
    let account = config.derive_account(factory).unwrap();
    let hash = B256::repeat_byte(0x42);
    let signature = multisig_signature(account, config.clone(), hash, &[&signer])?;
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14)
        .with_multisig_recovery_factory(factory);
    StorageCtx::enter(&mut storage, || {
        let call = |signature: Vec<u8>| {
            let calldata = ISignatureVerifier::verifyMultisigCall {
                account,
                hash,
                signature: signature.into(),
            }
            .abi_encode();
            SignatureVerifier::new().call(&calldata, Address::ZERO)
        };
        expect_precompile_revert(&call(vec![0x05]), SignatureVerifierError::invalid_format());

        let wrong_signer = PrivateKeySigner::random();
        let wrong_approval = multisig_signature(account, config.clone(), hash, &[&wrong_signer])?;
        expect_precompile_revert(
            &call(wrong_approval),
            SignatureVerifierError::invalid_signature(),
        );
        assert!(!verify_multisig(
            account,
            hash,
            multisig_signature(
                account,
                MultisigConfig {
                    salt: B256::repeat_byte(1),
                    ..config.clone()
                },
                hash,
                &[&signer],
            )?
        )?);

        StorageCtx.set_code(
            account,
            revm::state::Bytecode::new_raw(vec![0x60, 0x00].into()),
        )?;
        assert!(!verify_multisig(account, hash, signature)?);
        Ok(())
    })
}

#[test]
fn keychain_verification_rejects_multisig() -> eyre::Result<()> {
    let account = Address::repeat_byte(1);
    let multisig = MultisigSignature::try_new(
        Address::repeat_byte(2),
        MultisigConfig {
            salt: B256::ZERO,
            version: 1,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: Address::repeat_byte(3),
                weight: 1,
            }],
        },
        vec![PrimitiveSignature::Secp256k1(Signature::test_signature())],
    )
    .unwrap();
    let signature = TempoSignature::Keychain(KeychainSignature::new(account, multisig));
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
    StorageCtx::enter(&mut storage, || {
        let mut verifier = SignatureVerifier::new();
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
        let s = normalize_p256_s(&signature.s().to_bytes()).expect("p256 crate produces valid s");

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
