use super::*;
use crate::{
    Precompile, expect_precompile_revert, input_cost,
    storage::{
        ConfigCommitmentWriteGas, StorageCtx, evm::EvmPrecompileStorageProvider,
        hashmap::HashMapStorageProvider,
    },
};
use alloy::sol_types::SolCall;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use eyre::OptionExt;
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use tempo_chainspec::{gas_params, hardfork::TempoHardfork};
use tempo_contracts::precompiles::ISignatureVerifier;
use tempo_primitives::transaction::{
    ConfigurableAccountConfig, ConfigurableAccountOwner, configurable_account_digest,
    tt_signature::{
        SIGNATURE_TYPE_P256, SIGNATURE_TYPE_WEBAUTHN, derive_p256_address, normalize_p256_s,
    },
};

/// Random P256 key with its public coordinates and the address derived from them.
pub(super) struct P256Key {
    pub(super) signing_key: SigningKey,
    pub(super) pub_key_x: B256,
    pub(super) pub_key_y: B256,
    pub(super) address: Address,
}

/// A single-owner configurable account whose owner holds all of `threshold`, with that owner's signature over `hash`.
struct ConfigurableAccountFixture {
    factory: Address,
    config: ConfigurableAccountConfig,
    account: Address,
    hash: B256,
    signature: Vec<u8>,
}

pub(super) fn random_p256_key() -> eyre::Result<P256Key> {
    let signing_key = SigningKey::random(&mut OsRng);
    let point = signing_key.verifying_key().to_encoded_point(false);
    let pub_key_x = B256::from_slice(point.x().ok_or_eyre("missing x coord")?);
    let pub_key_y = B256::from_slice(point.y().ok_or_eyre("missing y coord")?);
    let address = derive_p256_address(&pub_key_x, &pub_key_y);
    Ok(P256Key {
        signing_key,
        pub_key_x,
        pub_key_y,
        address,
    })
}

fn sign_recover(hash: B256, signature: Vec<u8>) -> Result<Address> {
    SignatureVerifier::new().recover(hash, Bytes::from(signature))
}

#[test]
fn keychain_verification_rejects_configurable_account() -> eyre::Result<()> {
    let account = Address::repeat_byte(1);
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
    StorageCtx::enter(&mut storage, || {
        for claimed_account in [Address::repeat_byte(2), account] {
            let config = ConfigurableAccountConfig {
                salt: B256::ZERO,
                version: 1,
                threshold: 1,
                owners: vec![ConfigurableAccountOwner {
                    owner: Address::repeat_byte(3),
                    weight: 1,
                }],
            };
            let configurable_account = ConfigurableAccountSignature::try_new(
                claimed_account,
                config,
                vec![PrimitiveSignature::default()],
            )
            .unwrap();
            let signature =
                TempoSignature::Keychain(KeychainSignature::new(account, configurable_account));
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
        let sig_bytes = Vec::from(&signer.sign_hash_sync(&hash)?);
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
        let P256Key {
            signing_key,
            pub_key_x,
            pub_key_y,
            address: expected_address,
        } = random_p256_key()?;

        let hash = B256::repeat_byte(0xBB);
        let (signature, _) = signing_key.sign_prehash_recoverable(hash.as_slice())?;
        let r = B256::from_slice(&signature.r().to_bytes());
        let s = normalize_p256_s(&signature.s().to_bytes()).expect("p256 crate produces valid s");

        // Build encoded P256 signature: 0x01 || r || s || x || y || prehash(0)
        let sig_bytes = [
            [SIGNATURE_TYPE_P256].as_slice(),
            r.as_slice(),
            s.as_slice(),
            pub_key_x.as_slice(),
            pub_key_y.as_slice(),
            [0].as_slice(), // pre_hash = false
        ]
        .concat();
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

fn configurable_account_signature(
    account: Address,
    config: ConfigurableAccountConfig,
    hash: B256,
    signers: &[&PrivateKeySigner],
) -> eyre::Result<Vec<u8>> {
    let digest = configurable_account_digest(hash, account, config.version);
    let approvals = signers
        .iter()
        .map(|signer| {
            signer
                .sign_hash_sync(&digest)
                .map(PrimitiveSignature::Secp256k1)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(TempoSignature::ConfigurableAccount(
        ConfigurableAccountSignature::try_new(account, config, approvals).unwrap(),
    )
    .to_bytes()
    .to_vec())
}

fn verify_configurable_account(
    account: Address,
    hash: B256,
    signature: Vec<u8>,
) -> eyre::Result<bool> {
    let calldata = ISignatureVerifier::verifyConfigurableAccountCall {
        account,
        hash,
        signature: signature.into(),
    }
    .abi_encode();
    let output = SignatureVerifier::new().call(&calldata, Address::ZERO)?;
    Ok(ISignatureVerifier::verifyConfigurableAccountCall::abi_decode_returns(output.bytes())?)
}

fn configurable_account_fixture(
    signer: &PrivateKeySigner,
    threshold: u8,
) -> eyre::Result<ConfigurableAccountFixture> {
    let factory = Address::repeat_byte(0x71);
    let config = ConfigurableAccountConfig {
        salt: B256::ZERO,
        version: 0,
        threshold,
        owners: vec![ConfigurableAccountOwner {
            owner: signer.address(),
            weight: threshold,
        }],
    };
    let account = config.derive_account(factory).unwrap();
    let hash = B256::repeat_byte(0x42);
    let signature = configurable_account_signature(account, config.clone(), hash, &[signer])?;
    Ok(ConfigurableAccountFixture {
        factory,
        config,
        account,
        hash,
        signature,
    })
}

#[test]
fn test_verify_configurable_account_unregistered_and_registered() -> eyre::Result<()> {
    let ConfigurableAccountFixture {
        factory,
        config,
        account,
        hash,
        signature,
    } = configurable_account_fixture(&PrivateKeySigner::random(), 200)?;
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
    storage.set_configurable_account_recovery_factory(factory);
    StorageCtx::enter(&mut storage, || {
        assert!(verify_configurable_account(
            account,
            hash,
            signature.clone()
        )?);
        assert_eq!(StorageCtx.config_commitment(account)?, B256::ZERO);

        StorageCtx.set_config_commitment(
            account,
            config.commitment().unwrap(),
            ConfigCommitmentWriteGas::Intrinsic,
        )?;
        assert!(verify_configurable_account(
            account,
            hash,
            signature.clone()
        )?);
        assert!(!verify_configurable_account(
            Address::repeat_byte(0x72),
            hash,
            signature.clone()
        )?);
        let wrong_hash_call = ISignatureVerifier::verifyConfigurableAccountCall {
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
            ConfigCommitmentWriteGas::Precompile,
        )?;
        assert!(!verify_configurable_account(account, hash, signature)?);
        Ok(())
    })
}

#[test]
fn test_verify_configurable_account_rejects_invalid_state_and_signature() -> eyre::Result<()> {
    let signer = PrivateKeySigner::random();
    let ConfigurableAccountFixture {
        factory,
        config,
        account,
        hash,
        signature,
    } = configurable_account_fixture(&signer, 1)?;
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
    storage.set_configurable_account_recovery_factory(factory);
    StorageCtx::enter(&mut storage, || {
        let call = |signature: Vec<u8>| {
            let calldata = ISignatureVerifier::verifyConfigurableAccountCall {
                account,
                hash,
                signature: signature.into(),
            }
            .abi_encode();
            SignatureVerifier::new().call(&calldata, Address::ZERO)
        };
        expect_precompile_revert(&call(vec![0x05]), SignatureVerifierError::invalid_format());

        let wrong_signer = PrivateKeySigner::random();
        let wrong_approval =
            configurable_account_signature(account, config.clone(), hash, &[&wrong_signer])?;
        expect_precompile_revert(
            &call(wrong_approval),
            SignatureVerifierError::invalid_signature(),
        );
        assert!(!verify_configurable_account(
            account,
            hash,
            configurable_account_signature(
                account,
                ConfigurableAccountConfig {
                    salt: B256::repeat_byte(1),
                    ..config.clone()
                },
                hash,
                &[&signer],
            )?
        )?);

        StorageCtx.set_code(account, Bytes::from_static(&[0x60, 0x00]))?;
        assert!(!verify_configurable_account(account, hash, signature)?);
        Ok(())
    })
}

#[test]
fn verify_configurable_account_staticcall_charges_gas_and_halts_when_short() -> eyre::Result<()> {
    use evm2::{
        BaseEvmConfigSelector, Evm, EvmTypesHost, ExecutionConfig, SpecId,
        evm::{InMemoryDB, precompile::NoPrecompiles},
        interpreter::GasTracker,
        precompiles::{PrecompileError, PrecompileHalt},
        registry::TxRegistry,
        version::GasId,
    };
    use tempo_primitives::{TempoBlockEnv, TempoBlockExt};

    struct TestTypes;

    impl EvmTypesHost for TestTypes {
        type ConfigSelector = BaseEvmConfigSelector;
        type SpecId = SpecId;
        type Tx = ();
        type EvmExt = ();
        type MessageExt = ();
        type MessageResultExt = ();
        type TxEnvExt = ();
        type TxResultExt = ();
        type BlockEnvExt = TempoBlockExt;
        type Host<'a> = Evm<'a, Self>;
    }

    let ConfigurableAccountFixture {
        factory,
        config,
        account,
        hash,
        signature,
    } = configurable_account_fixture(&PrivateKeySigner::random(), 1)?;
    let calldata = ISignatureVerifier::verifyConfigurableAccountCall {
        account,
        hash,
        signature: signature.clone().into(),
    }
    .abi_encode();
    let spec = TempoHardfork::T14;
    let version = gas_params::version(SpecId::OSAKA, spec, false);
    let parsed = TempoSignature::from_bytes(&signature).unwrap();
    let expected = input_cost(spec, calldata.len())?
        + u64::from(version.gas_params.get(GasId::WarmStorageReadCost))
        + version.gas_params.cold_account_additional_cost()
        + configurable_account_verification_gas(parsed.as_configurable_account().unwrap())?
        + initial_account_proof_gas(&config)?;

    let call = |gas_limit| {
        let block_env = TempoBlockEnv {
            ext: TempoBlockExt {
                configurable_account_recovery_factory: Some(factory),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut evm = Evm::<TestTypes>::new_with_execution_config(
            ExecutionConfig::for_spec_and_version(SpecId::OSAKA, version),
            SpecId::OSAKA,
            block_env,
            TxRegistry::new(),
            InMemoryDB::default(),
            NoPrecompiles::default(),
        );
        let mut gas_tracker = GasTracker::new(gas_limit);
        let mut provider =
            EvmPrecompileStorageProvider::new(&mut evm, &mut gas_tracker, spec, true);
        let result = StorageCtx::enter(&mut provider, || {
            SignatureVerifier::new().call(&calldata, Address::ZERO)
        });
        (result, gas_tracker.spent())
    };

    let (output, gas_used) = call(expected);
    assert!(
        ISignatureVerifier::verifyConfigurableAccountCall::abi_decode_returns(output?.bytes())?
    );
    assert_eq!(gas_used, expected);
    assert!(matches!(
        call(expected - 1).0,
        Err(PrecompileError::Halt(PrecompileHalt::OutOfGas))
    ));
    Ok(())
}
