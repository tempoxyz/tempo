use super::*;

mod cost;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use revm::{
    Journal,
    database::{CacheDB, EmptyDB},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::transaction::{MultisigConfig, MultisigOwner, PrimitiveSignature};

#[test]
fn native_hash_gas_layout_matches_all_owner_counts() {
    use tempo_primitives::transaction::{MAX_MULTISIG_OWNERS, MULTISIG_SIGNATURE_DOMAIN};
    for (count, version) in (1..=MAX_MULTISIG_OWNERS)
        .flat_map(|count| [0, 127, 128, 255, 256, u64::MAX].map(|version| (count, version)))
    {
        let config = MultisigConfig {
            salt: B256::ZERO,
            version,
            threshold: 1,
            owners: (1..=count)
                .map(|index| MultisigOwner {
                    owner: Address::repeat_byte(index as u8),
                    weight: 1,
                })
                .collect(),
        };
        assert_eq!(config.account_salt_preimage_len(), 56 + 21 * count);
        assert_eq!(config.commitment_preimage_len(), 63 + 21 * count);
        assert_eq!(
            config.account_salt_preimage_len(),
            config.account_salt_preimage().unwrap().len()
        );
        assert_eq!(
            config.commitment_preimage_len(),
            config.commitment_preimage().unwrap().len()
        );
        assert_eq!(
            keccak_cost(config.account_salt_preimage_len())
                + keccak_cost(MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN),
            keccak_cost(56 + 21 * count) + keccak_cost(85),
            "derivation gas for {count} owners"
        );
        let signature = MultisigSignature::try_new(
            config.derive_account(Address::repeat_byte(0x71)).unwrap(),
            config.clone(),
            vec![PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            )],
        )
        .unwrap();
        let mut witness = alloy_rlp::encode(signature.account());
        witness.extend(alloy_rlp::encode(&config));
        let calldata = revm::interpreter::gas::get_tokens_in_calldata_istanbul(&witness)
            * revm::interpreter::gas::STANDARD_TOKEN_COST;
        assert_eq!(MULTISIG_SIGNATURE_DOMAIN.len() + 32 + 20 + 8, 84);
        assert_eq!(
            crate::signature_gas::multisig_verification_gas(&signature),
            calldata + keccak_cost(63 + 21 * count) + keccak_cost(84) + 3_000,
            "verification gas for {count} owners"
        );
    }
}

fn fixture() -> (TempoTxEnv, TempoBlockEnv) {
    let signer = PrivateKeySigner::random();
    let factory = Address::repeat_byte(0x71);
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
    let digest = B256::repeat_byte(0x34);
    let signature = signer
        .sign_hash_sync(&tempo_primitives::transaction::multisig_digest(
            digest, account, 0,
        ))
        .unwrap();
    let signature = MultisigSignature::try_new(
        account,
        config,
        vec![PrimitiveSignature::Secp256k1(signature)],
    )
    .unwrap();
    let mut tx = TempoTxEnv {
        execution_context: ExecutionContext::Transaction {
            tx_hash: B256::ZERO,
        },
        tempo_tx_env: Some(Box::new(crate::TempoBatchCallEnv {
            signature: TempoSignature::Multisig(signature),
            signature_hash: digest,
            ..Default::default()
        })),
        ..Default::default()
    };
    tx.caller = account;
    (
        tx,
        TempoBlockEnv {
            multisig_recovery_factory: Some(factory),
            ..Default::default()
        },
    )
}

#[test]
fn native_authorization_roles_preserve_order_and_duplicate_accounts() {
    use tempo_primitives::transaction::{AccessKeySignature, KeyAuthorization};
    assert!(
        authorizations(&TempoTxEnv::default())
            .iter()
            .all(Option::is_none)
    );
    let (mut tx, _) = fixture();
    assert!(authorizations(&tx)[0].is_some());
    assert!(authorizations(&tx)[1].is_none());
    let caller = tx.caller;
    let aa = tx.tempo_tx_env.as_mut().unwrap();
    let native = aa.signature.as_multisig().unwrap().clone();
    let outer_digest = aa.signature_hash;
    let grant = KeyAuthorization::unrestricted(1, SignatureType::Multisig, caller);
    let grant_digest = grant.signature_hash();
    aa.key_authorization = Some(grant.into_signed(TempoSignature::Multisig(native.clone())));
    let roles = authorizations(&tx);
    let outer = roles[0].as_ref().unwrap();
    let grant = roles[1].as_ref().unwrap();
    assert_eq!(outer.signature.account(), grant.signature.account());
    assert_eq!(outer.inner_digest, outer_digest);
    assert_eq!(grant.inner_digest, grant_digest);
    assert_ne!(outer.inner_digest, grant.inner_digest);

    tx.tempo_tx_env.as_mut().unwrap().signature = TempoSignature::Keychain(KeychainSignature::new(
        tx.caller,
        AccessKeySignature::Multisig(native),
    ));
    assert_eq!(
        authorizations(&tx)[0].as_ref().unwrap().inner_digest,
        KeychainSignature::signing_hash(outer_digest, tx.caller)
    );
    let aa = tx.tempo_tx_env.as_mut().unwrap();
    aa.signature = TempoSignature::default();
    assert!(authorizations(&tx)[0].is_none());
    assert!(authorizations(&tx)[1].is_some());
    tx.tempo_tx_env.as_mut().unwrap().key_authorization = None;
    assert!(authorizations(&tx).iter().all(Option::is_none));
}

#[test]
fn native_state_registration_gas_and_registered_v0() {
    let (tx, block) = fixture();
    let mut journal: Journal<CacheDB<EmptyDB>> = Journal::new(CacheDB::new(EmptyDB::default()));
    let gas = crate::gas_params::tempo_gas_params(TempoHardfork::T12);
    assert_eq!(
        validate_state(&mut journal, &tx, &block, TempoHardfork::T12, &gas).unwrap(),
        20_000 + keccak_cost(77) + keccak_cost(85)
    );
    verify(&tx).unwrap();
    let hash = authorizations(&tx)[0]
        .as_ref()
        .unwrap()
        .signature
        .config_commitment();
    journal.state.get_mut(&tx.caller).unwrap().info.extension =
        tempo_primitives::account::encode_config_commitment(hash).into();
    assert_eq!(
        validate_state(&mut journal, &tx, &block, TempoHardfork::T12, &gas).unwrap(),
        0
    );
    journal.state.get_mut(&tx.caller).unwrap().info.extension =
        tempo_primitives::account::encode_config_commitment(B256::repeat_byte(0x99)).into();
    assert!(matches!(
        validate_state(&mut journal, &tx, &block, TempoHardfork::T12, &gas),
        Err(EVMError::Transaction(
            TempoInvalidTransaction::NativeMultisig(
                NativeMultisigError::ConfigurationCommitmentMismatch { .. }
            )
        ))
    ));
}

#[test]
fn native_contexts_fail_closed_and_simulation_is_explicit() {
    let (mut tx, mut block) = fixture();
    let mut journal: Journal<CacheDB<EmptyDB>> = Journal::new(CacheDB::new(EmptyDB::default()));
    let gas = crate::gas_params::tempo_gas_params(TempoHardfork::T12);
    assert!(validate_state(&mut journal, &tx, &block, TempoHardfork::T11, &gas).is_err());
    block.multisig_recovery_factory = None;
    assert!(validate_state(&mut journal, &tx, &block, TempoHardfork::T12, &gas).is_err());
    tx.execution_context = ExecutionContext::Unspecified;
    assert!(verify(&tx).is_err());
    tx.execution_context = ExecutionContext::Transaction {
        tx_hash: B256::ZERO,
    };
    tx.tempo_tx_env.as_mut().unwrap().signature_hash = B256::repeat_byte(0x99);
    assert!(verify(&tx).is_err());
    tx.execution_context = ExecutionContext::Simulation;
    verify(&tx).unwrap();
}

#[test_case::test_case(8; "invalid_final_signature")]
#[test_case::test_case(1; "excess_valid_approval")]
fn native_approvals_reject_invalid_quorums(threshold: u8) {
    let factory = Address::repeat_byte(0x71);
    let mut owners = (0..if threshold == 1 { 2 } else { 8 })
        .map(|_| PrivateKeySigner::random())
        .collect::<Vec<_>>();
    owners.sort_by_key(|signer| signer.address());
    let config = MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold,
        owners: owners
            .iter()
            .map(|signer| MultisigOwner {
                owner: signer.address(),
                weight: 1,
            })
            .collect(),
    };
    let account = config.derive_account(factory).unwrap();
    let inner_digest = B256::repeat_byte(0x42);
    let digest = tempo_primitives::transaction::multisig_digest(inner_digest, account, 0);
    let mut signatures = owners
        .iter()
        .map(|signer| PrimitiveSignature::Secp256k1(signer.sign_hash_sync(&digest).unwrap()))
        .collect::<Vec<_>>();
    let signature = MultisigSignature::try_new(
        account,
        config.clone(),
        signatures[..threshold as usize].to_vec(),
    )
    .unwrap();
    NativeAuthorization {
        signature: &signature,
        inner_digest,
    }
    .verify()
    .unwrap();
    if threshold == 1 {
        // Both approvals recover ordered configured owners; only the extra
        // approval after the first owner's quorum makes this witness invalid.
        for (approval, owner) in signatures.iter().zip(&owners) {
            assert_eq!(approval.recover_signer(&digest).unwrap(), owner.address());
        }
    } else {
        signatures[7] =
            PrimitiveSignature::Secp256k1(owners[7].sign_hash_sync(&B256::ZERO).unwrap());
    }
    let signature = MultisigSignature::try_new(account, config, signatures).unwrap();
    let result = NativeAuthorization {
        signature: &signature,
        inner_digest,
    }
    .verify();
    if threshold == 1 {
        assert!(
            matches!(
                result,
                Err(NativeMultisigError::Quorum(
                    MultisigQuorumError::ExcessSignatures
                ))
            ),
            "{result:?}"
        );
    } else {
        assert!(result.is_err(), "{result:?}");
    }
}
