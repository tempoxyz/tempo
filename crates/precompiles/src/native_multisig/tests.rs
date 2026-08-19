use super::*;
use crate::{
    error::TempoPrecompileError,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
};
use alloy::primitives::{IntoLogData, address, keccak256};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::transaction::MultisigOwner;

fn initial_config() -> MultisigConfig {
    MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 1,
        owners: vec![MultisigOwner {
            owner: address!("0000000000000000000000000000000000000011"),
            weight: 1,
        }],
    }
}

fn abi_config(config: &MultisigConfig) -> INativeMultisig::MultisigConfig {
    config.clone().into()
}

fn abi_owners(owner: Address) -> Vec<INativeMultisig::MultisigOwner> {
    vec![INativeMultisig::MultisigOwner { owner, weight: 1 }]
}

fn update_error(
    account: Address,
    current: &MultisigConfig,
    stored: B256,
    threshold: u8,
    owners: Vec<INativeMultisig::MultisigOwner>,
) -> NativeMultisigError {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12)
        .with_tx_kind(TxKind::Call(NATIVE_MULTISIG_ADDRESS));
    StorageCtx::enter(&mut storage, || {
        let mut multisig = NativeMultisig::new();
        multisig.set_tx_origin(account)?;
        multisig.set_directly_authorized_account(account)?;
        if !stored.is_zero() {
            multisig.config_commitments[account].write(stored)?;
        }
        match multisig.update_multisig_config(account, abi_config(current), threshold, owners) {
            Err(TempoPrecompileError::NativeMultisigError(error)) => {
                Ok::<_, TempoPrecompileError>(error)
            }
            result => panic!("expected native multisig error, got {result:?}"),
        }
    })
    .unwrap()
}

#[test]
fn commitment_slot_matches_tip_layout() {
    let account = Address::repeat_byte(0x11);
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(account.as_slice());

    assert_eq!(
        NativeMultisig::config_commitment_storage_slot(account),
        U256::from_be_bytes(keccak256(preimage).0)
    );
}

#[test]
fn derive_account_is_stateless() -> eyre::Result<()> {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
    let config = initial_config();
    let expected = config.derive_account().unwrap();

    StorageCtx::enter(&mut storage, || {
        assert_eq!(
            NativeMultisig::new().derive_account(
                config.salt,
                config.threshold,
                config.owners.clone().into_iter().map(Into::into).collect(),
            )?,
            expected
        );
        Ok::<_, TempoPrecompileError>(())
    })?;

    assert_eq!(storage.counter_sload(), 0);
    assert_eq!(storage.counter_sstore(), 0);
    Ok(())
}

#[test]
fn updates_replace_one_commitment_and_emit_config() -> eyre::Result<()> {
    let config = initial_config();
    let account = config.derive_account().unwrap();
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12)
        .with_tx_kind(TxKind::Call(NATIVE_MULTISIG_ADDRESS));

    let first_owner = address!("0000000000000000000000000000000000000022");
    StorageCtx::enter(&mut storage, || {
        let mut multisig = NativeMultisig::new();
        multisig.set_tx_origin(account)?;
        multisig.set_directly_authorized_account(account)?;
        multisig.update_multisig_config(
            account,
            abi_config(&config),
            1,
            abi_owners(first_owner),
        )?;
        Ok::<_, TempoPrecompileError>(())
    })?;

    assert_eq!(storage.counter_sstore(), 1);
    let first_event = NativeMultisigEvent::multisig_config_updated(
        account,
        config.salt,
        1,
        1,
        abi_owners(first_owner),
    )
    .into_log_data();
    assert_eq!(
        storage.get_events(NATIVE_MULTISIG_ADDRESS).as_slice(),
        std::slice::from_ref(&first_event)
    );
    let current = MultisigConfig {
        salt: config.salt,
        version: 1,
        threshold: 1,
        owners: vec![MultisigOwner {
            owner: first_owner,
            weight: 1,
        }],
    };
    StorageCtx::enter(&mut storage, || {
        assert_eq!(
            NativeMultisig::new().get_config_commitment(account)?,
            current.commitment().unwrap()
        );
        Ok::<_, TempoPrecompileError>(())
    })?;

    storage.clear_transient();
    storage.reset_counters();
    let second_owner = address!("0000000000000000000000000000000000000033");
    StorageCtx::enter(&mut storage, || {
        let mut multisig = NativeMultisig::new();
        multisig.set_tx_origin(account)?;
        multisig.set_directly_authorized_account(account)?;
        multisig.update_multisig_config(account, abi_config(&current), 1, abi_owners(second_owner))
    })?;
    assert_eq!(storage.counter_sstore(), 1);

    let next = MultisigConfig {
        owners: vec![MultisigOwner {
            owner: second_owner,
            weight: 1,
        }],
        version: 2,
        ..current
    };
    StorageCtx::enter(&mut storage, || {
        assert_eq!(
            NativeMultisig::new().get_config_commitment(account)?,
            next.commitment().unwrap()
        );
        Ok::<_, TempoPrecompileError>(())
    })?;
    let second_event = NativeMultisigEvent::multisig_config_updated(
        account,
        next.salt,
        next.version,
        next.threshold,
        abi_owners(second_owner),
    )
    .into_log_data();
    assert_eq!(
        storage.get_events(NATIVE_MULTISIG_ADDRESS).as_slice(),
        &[first_event, second_event]
    );
    Ok(())
}

#[test]
fn update_requires_root_authorized_direct_outer_call() -> eyre::Result<()> {
    let config = initial_config();
    let account = config.derive_account().unwrap();
    let other = Address::repeat_byte(0x44);
    let valid_target = Some(TxKind::Call(NATIVE_MULTISIG_ADDRESS));

    assert_eq!(
        update_error(
            Address::ZERO,
            &config,
            B256::ZERO,
            1,
            abi_owners(Address::repeat_byte(0x22)),
        ),
        NativeMultisigError::unauthorized_multisig_caller(),
    );

    let cases = [
        (
            "missing transaction target",
            None,
            account,
            account,
            Address::ZERO,
        ),
        (
            "wrong transaction target",
            Some(TxKind::Call(other)),
            account,
            account,
            Address::ZERO,
        ),
        (
            "contract-creation transaction",
            Some(TxKind::Create),
            account,
            account,
            Address::ZERO,
        ),
        (
            "different transaction origin",
            valid_target,
            other,
            account,
            Address::ZERO,
        ),
        (
            "different outer authority",
            valid_target,
            account,
            other,
            Address::ZERO,
        ),
        (
            "access-key transaction",
            valid_target,
            account,
            account,
            other,
        ),
    ];

    for (case, tx_kind, origin, directly_authorized, transaction_key) in cases {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        if let Some(tx_kind) = tx_kind {
            storage = storage.with_tx_kind(tx_kind);
        }
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.set_tx_origin(origin)?;
            multisig.set_directly_authorized_account(directly_authorized)?;
            AccountKeychain::new().set_transaction_key(transaction_key)?;
            assert!(
                matches!(
                    multisig.update_multisig_config(
                        account,
                        abi_config(&config),
                        1,
                        abi_owners(Address::repeat_byte(0x22)),
                    ),
                    Err(TempoPrecompileError::NativeMultisigError(
                        NativeMultisigError::UnauthorizedMultisigCaller(_)
                    ))
                ),
                "{case}"
            );
            Ok::<_, TempoPrecompileError>(())
        })?;
    }
    Ok(())
}

#[test]
fn update_rejects_invalid_state_and_version() {
    let initial = initial_config();
    let account = initial.derive_account().unwrap();
    let mut current = initial.clone();
    current.version = 1;
    let mut overflow = current.clone();
    overflow.version = u64::MAX;
    let next = abi_owners(Address::repeat_byte(0x22));

    for (case, config, stored) in [
        (
            "initial against nonzero state",
            &initial,
            B256::repeat_byte(1),
        ),
        ("current against zero state", &current, B256::ZERO),
        (
            "current against mismatching state",
            &current,
            B256::repeat_byte(2),
        ),
        (
            "version overflow",
            &overflow,
            overflow.commitment().unwrap(),
        ),
    ] {
        assert_eq!(
            update_error(account, config, stored, 1, next.clone()),
            NativeMultisigError::invalid_config(),
            "{case}",
        );
    }
}

#[test]
fn update_config_errors_follow_tip_order() {
    let current = initial_config();
    let account = current.derive_account().unwrap();
    let owner = |byte, weight| INativeMultisig::MultisigOwner {
        owner: Address::repeat_byte(byte),
        weight,
    };
    let too_many = (1..=49).map(|byte| owner(byte, 1)).collect::<Vec<_>>();

    let cases = [
        (
            "empty owners precede zero threshold",
            0,
            vec![],
            NativeMultisigError::invalid_multisig_owner(),
        ),
        (
            "owner limit precedes zero threshold",
            0,
            too_many,
            NativeMultisigError::too_many_owners(),
        ),
        (
            "zero owner precedes zero weight",
            1,
            vec![INativeMultisig::MultisigOwner {
                owner: Address::ZERO,
                weight: 0,
            }],
            NativeMultisigError::invalid_multisig_owner(),
        ),
        (
            "self owner precedes zero weight",
            1,
            vec![INativeMultisig::MultisigOwner {
                owner: account,
                weight: 0,
            }],
            NativeMultisigError::invalid_multisig_owner(),
        ),
        (
            "zero weight precedes duplicate owner",
            1,
            vec![owner(0x22, 1), owner(0x22, 0)],
            NativeMultisigError::invalid_weight(),
        ),
        (
            "duplicate owner",
            1,
            vec![owner(0x22, 1), owner(0x22, 1)],
            NativeMultisigError::duplicate_owner(),
        ),
        (
            "owner order",
            1,
            vec![owner(0x33, 1), owner(0x22, 1)],
            NativeMultisigError::invalid_owner_order(),
        ),
        (
            "weight overflow precedes reachability",
            u8::MAX,
            vec![owner(0x22, 128), owner(0x33, 128)],
            NativeMultisigError::invalid_weight(),
        ),
        (
            "unreachable threshold",
            2,
            vec![owner(0x22, 1)],
            NativeMultisigError::invalid_threshold(),
        ),
    ];

    for (case, threshold, owners, expected) in cases {
        assert_eq!(
            update_error(account, &current, B256::ZERO, threshold, owners),
            expected,
            "{case}",
        );
    }
}

mod auth {
    use crate::{
        native_multisig::{
            NativeMultisig, NativeMultisigAuthError, NativeMultisigAuthorizationError,
            NativeMultisigStateError,
        },
        storage::{Handler, StorageCtx, hashmap::HashMapStorageProvider},
    };
    use alloy::primitives::{Address, B256, Signature};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_primitives::transaction::{
        MultisigConfig, MultisigOwner, MultisigQuorumError, MultisigSignature, PrimitiveSignature,
        TempoSignature, multisig_digest,
    };
    fn signer(seed: u8) -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::with_last_byte(seed)).unwrap()
    }

    fn initial_config(owners: &[(Address, u8)], threshold: u8) -> MultisigConfig {
        let mut owners = owners
            .iter()
            .map(|&(owner, weight)| MultisigOwner { owner, weight })
            .collect::<Vec<_>>();
        owners.sort_by_key(|owner| owner.owner);
        MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold,
            owners,
        }
    }

    fn signed_initial(
        config: MultisigConfig,
        inner_digest: B256,
        signers: &[&PrivateKeySigner],
    ) -> MultisigSignature {
        let account = config.derive_account().unwrap();
        let digest = multisig_digest(inner_digest, account, 0);
        let approvals = signers
            .iter()
            .map(|signer| {
                TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                    signer.sign_hash_sync(&digest).unwrap(),
                ))
            })
            .collect();
        MultisigSignature::try_new(account, config, approvals).unwrap()
    }

    fn assert_quorum_error(signature: &MultisigSignature, expected: MultisigQuorumError) {
        assert_eq!(
            NativeMultisig::verify_authorization_quorum(B256::repeat_byte(0x42), signature),
            Err(NativeMultisigAuthError::Invalid(
                NativeMultisigAuthorizationError::Quorum(expected)
            ))
        );
    }

    fn signature(version: u64) -> MultisigSignature {
        let config = MultisigConfig {
            salt: B256::ZERO,
            version,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: Address::repeat_byte(0x11),
                weight: 1,
            }],
        };
        let account = if version == 0 {
            config.derive_account().unwrap()
        } else {
            Address::repeat_byte(0x22)
        };
        MultisigSignature::try_new(
            account,
            config,
            vec![TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                Signature::test_signature(),
            ))],
        )
        .unwrap()
    }

    #[test]
    fn initial_witness_requires_zero_commitment() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        StorageCtx::enter(&mut storage, || {
            NativeMultisig::new().validate_authorization_state(&signature(0))
        })?;
        Ok(())
    }

    #[test]
    fn current_witness_requires_matching_commitment() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let signature = signature(1);
        StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.config_commitments[signature.account()]
                .write(signature.config().commitment().unwrap())
                .map_err(NativeMultisigAuthError::from_state_access_error)?;
            multisig.validate_authorization_state(&signature)
        })?;
        Ok(())
    }

    #[test]
    fn commitment_mismatch_reports_expected_and_actual() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T12);
        let signature = signature(1);
        let expected = B256::repeat_byte(0x11);
        let actual = signature.config_commitment();
        let error = StorageCtx::enter(&mut storage, || {
            let mut multisig = NativeMultisig::new();
            multisig.config_commitments[signature.account()]
                .write(expected)
                .map_err(NativeMultisigAuthError::from_state_access_error)?;
            multisig.validate_authorization_state(&signature)
        })
        .unwrap_err();

        assert_eq!(
            error,
            NativeMultisigAuthError::State(
                NativeMultisigStateError::ConfigurationCommitmentMismatch { expected, actual }
            )
        );
        Ok(())
    }

    #[test]
    fn primitive_quorum_enforces_membership_order_weight_and_minimality() {
        let signer_a = signer(1);
        let signer_b = signer(2);
        let outsider = signer(3);
        let mut owners = [&signer_a, &signer_b];
        owners.sort_by_key(|signer| signer.address());
        let config = initial_config(
            &owners
                .iter()
                .map(|signer| (signer.address(), 1))
                .collect::<Vec<_>>(),
            2,
        );
        let inner_digest = B256::repeat_byte(0x42);

        let valid = signed_initial(config.clone(), inner_digest, &owners);
        assert_eq!(
            NativeMultisig::verify_authorization_quorum(inner_digest, &valid),
            Ok(())
        );

        let insufficient = signed_initial(config.clone(), inner_digest, &owners[..1]);
        assert_quorum_error(&insufficient, MultisigQuorumError::WeightBelowThreshold);

        owners.reverse();
        let unordered = signed_initial(config.clone(), inner_digest, &owners);
        assert_quorum_error(&unordered, MultisigQuorumError::SignersNotAscending);
        owners.reverse();

        let excess = signed_initial(
            MultisigConfig {
                threshold: 1,
                ..config
            },
            inner_digest,
            &owners,
        );
        assert_quorum_error(&excess, MultisigQuorumError::ExcessSignatures);

        let non_owner = signed_initial(
            initial_config(&[(owners[0].address(), 1)], 1),
            inner_digest,
            &[&outsider],
        );
        assert_quorum_error(&non_owner, MultisigQuorumError::SignerNotOwner);
    }

    #[test]
    fn nested_multisig_quorum_is_verified_recursively() {
        let owner = signer(4);
        let inner_digest = B256::repeat_byte(0x42);
        let nested_config = initial_config(&[(owner.address(), 1)], 1);
        let nested_account = nested_config.derive_account().unwrap();
        let outer_config = initial_config(&[(nested_account, 1)], 1);
        let outer_account = outer_config.derive_account().unwrap();
        let nested = signed_initial(
            nested_config,
            multisig_digest(inner_digest, outer_account, 0),
            &[&owner],
        );
        let outer = MultisigSignature::try_new(
            outer_account,
            outer_config,
            vec![TempoSignature::Multisig(nested)],
        )
        .unwrap();

        assert_eq!(
            NativeMultisig::verify_authorization_quorum(inner_digest, &outer),
            Ok(())
        );
    }
}
