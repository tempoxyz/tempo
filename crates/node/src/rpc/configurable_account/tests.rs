use super::*;
use alloy::signers::{SignerSync, local::PrivateKeySigner};
use alloy_primitives::{B256, Signature, U256, map::AddressMap};
use alloy_rpc_types_eth::TransactionRequest;
use evm2::{bytecode::Bytecode, evm::AccountInfo};
use reth_errors::ProviderError;
use reth_rpc_eth_api::TryIntoTxEnv;
use tempo_alloy::rpc::{ConfigurableAccountSimulationApproval, ConfigurableAccountSimulationSpec};
use tempo_evm::{ExecutionContext, TempoEvmEnv};
use tempo_primitives::{
    account::encode_config_commitment,
    transaction::{
        ConfigurableAccountConfig, ConfigurableAccountOwner, KeyAuthorization, PrimitiveSignature,
        configurable_account_digest,
    },
};

const FACTORY: Address = Address::repeat_byte(0x99);
#[derive(Default)]
struct AccountDb(AddressMap<AccountInfo>);
impl AccountDb {
    fn insert_commitment(&mut self, account: Address, hash: B256) {
        self.0.entry(account).or_default().extension = encode_config_commitment(hash).into();
    }
}
impl Database for AccountDb {
    type Error = ProviderError;
    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.0.get(address).cloned())
    }
    fn get_code_by_hash(&mut self, _: &B256) -> Result<Bytecode, Self::Error> {
        panic!("metadata suffices")
    }
    fn get_storage(&mut self, _: &Address, _: &U256) -> Result<U256, Self::Error> {
        panic!("no storage fallback")
    }
    fn get_block_hash(&mut self, _: &U256) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}
#[derive(Clone, Copy)]
enum WitnessRejection {
    BeforeT14(TempoHardfork),
    Code,
    UnregisteredVersion,
    WrongIdentity,
}

/// One stored-commitment and approval combination, with the error it must produce.
struct Case {
    stored: B256,
    approval: Signature,
    expected: Option<String>,
}

fn spec(salt: u8, version: u64) -> (Address, ConfigurableAccountSimulationSpec) {
    let owner = Address::repeat_byte(1);
    let config = ConfigurableAccountConfig {
        salt: B256::repeat_byte(salt),
        version,
        threshold: 1,
        owners: vec![ConfigurableAccountOwner { owner, weight: 1 }],
    };
    let account = config.derive_account(FACTORY).unwrap();
    (
        account,
        ConfigurableAccountSimulationSpec {
            signer: None,
            config,
            approvals: vec![ConfigurableAccountSimulationApproval {
                owner,
                key_type: Some(SignatureType::Secp256k1),
                key_data: None,
            }],
        },
    )
}
fn block() -> TempoBlockExt {
    TempoBlockExt {
        configurable_account_recovery_factory: Some(FACTORY),
        ..TempoBlockExt::default()
    }
}

#[test_case::test_case(false; "parent signer")]
#[test_case::test_case(true; "admin signer")]
fn real_grant_checks_state_before_cryptography(admin: bool) {
    let signer = PrivateKeySigner::from_slice(&[1; 32]).unwrap();
    let (signing_account, mut spec) = spec(1, 1);
    let parent = if admin {
        Address::repeat_byte(0x77)
    } else {
        signing_account
    };
    spec.config.owners[0].owner = signer.address();
    let mut authorization =
        KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, Address::repeat_byte(8));
    if admin {
        authorization.account = Some(parent);
    }
    let digest = configurable_account_digest(
        authorization.signature_hash(),
        signing_account,
        spec.config.version,
    );
    let valid = signer.sign_hash_sync(&digest).unwrap();
    let invalid = Signature::new(U256::ZERO, U256::ZERO, false);
    let commitment = spec.config.commitment().unwrap();
    let stale = B256::repeat_byte(7);
    let state_error = format!(
        "{} for {signing_account} at the requested state",
        ConfigurableAccountStateError::CommitmentMismatch {
            expected: stale,
            actual: commitment,
        }
    );
    let crypto_error =
        ConfigurableAccountError::OwnerSignatureRecoveryFailed { approval_index: 0 }.to_string();
    for Case {
        stored,
        approval,
        expected,
    } in [
        Case {
            stored: stale,
            approval: invalid,
            expected: Some(state_error.clone()),
        },
        Case {
            stored: stale,
            approval: valid,
            expected: Some(state_error),
        },
        Case {
            stored: commitment,
            approval: invalid,
            expected: Some(crypto_error),
        },
        Case {
            stored: commitment,
            approval: valid,
            expected: None,
        },
    ] {
        let mut db = AccountDb::default();
        db.insert_commitment(signing_account, stored);
        let signature = ConfigurableAccountSignature::try_new(
            signing_account,
            spec.config.clone(),
            vec![PrimitiveSignature::Secp256k1(approval)],
        )
        .unwrap();
        let mut request = TempoTransactionRequest {
            inner: TransactionRequest::default().from(parent),
            key_id: admin.then_some(signing_account),
            key_authorization: Some(authorization.clone().into_signed(signature)),
            ..Default::default()
        };
        let result = prepare_configurable_account_simulation(
            &mut request,
            TempoHardfork::T14,
            &block(),
            &mut db,
        );
        if let Some(expected) = expected {
            let Err(EthApiError::InvalidParams(message)) = result else {
                panic!("expected {expected}")
            };
            assert_eq!(message, expected);
        } else {
            result.unwrap();
            request
                .key_authorization
                .as_mut()
                .unwrap()
                .authorization
                .chain_id += 1;
            assert!(
                prepare_configurable_account_simulation(
                    &mut request,
                    TempoHardfork::T14,
                    &block(),
                    &mut db
                )
                .is_err(),
                "prepared real grant must be reverified after digest mutation"
            );
        }
    }
}

#[test_case::test_case(0, false; "initial_parent")]
#[test_case::test_case(1, false; "registered_parent")]
#[test_case::test_case(1, true; "registered_admin")]
fn prepares_independent_delegate_and_parent_roles(version: u64, admin: bool) {
    let (parent, parent_spec) = spec(1, version);
    let (delegate, delegate_spec) = spec(2, version);
    let mut db = AccountDb::default();
    if version != 0 {
        db.insert_commitment(parent, parent_spec.config.commitment().unwrap());
        db.insert_commitment(delegate, delegate_spec.config.commitment().unwrap());
    }
    let recipient = if admin { spec(3, version).0 } else { delegate };
    let mut authorization =
        KeyAuthorization::unrestricted(4217, SignatureType::ConfigurableAccount, recipient);
    if admin {
        authorization.account = Some(parent);
    }
    let grant_spec = if admin {
        ConfigurableAccountSimulationSpec {
            signer: Some(delegate),
            ..delegate_spec.clone()
        }
    } else {
        parent_spec
    };
    let mut request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(parent),
            to: Some(Address::repeat_byte(8).into()),
            ..Default::default()
        },
        key_id: Some(delegate),
        key_type: Some(SignatureType::ConfigurableAccount),
        configurable_account_simulation: Some(delegate_spec),
        key_authorization_simulation: Some(grant_spec),
        key_authorization: Some(authorization.into_signed(PrimitiveSignature::default())),
        ..Default::default()
    };
    let wrong = Address::repeat_byte(9);
    let mut wrong_metadata = request.clone();
    wrong_metadata
        .key_authorization
        .as_mut()
        .unwrap()
        .authorization
        .account = Some(wrong);
    let Err(EthApiError::InvalidParams(message)) = prepare_configurable_account_simulation(
        &mut wrong_metadata,
        TempoHardfork::T14,
        &block(),
        &mut db,
    ) else {
        panic!("expected grant metadata rejection")
    };
    assert_eq!(
        message,
        format!("key authorization account mismatch: expected {parent}, actual {wrong}")
    );
    prepare_configurable_account_simulation(&mut request, TempoHardfork::T14, &block(), &mut db)
        .unwrap();

    let mut wrong_metadata = request.clone();
    wrong_metadata
        .key_authorization
        .as_mut()
        .unwrap()
        .authorization
        .account = Some(wrong);
    let mut wrong_signer = request.clone();
    wrong_signer.key_authorization_simulation = None;
    wrong_signer.key_authorization.as_mut().unwrap().signature = request
        .configurable_account_simulation_signature
        .clone()
        .unwrap()
        .into();
    let mut wrong_delegate = request.clone();
    wrong_delegate.set_key_id(parent);
    let mut missing_witness = request.clone();
    missing_witness.configurable_account_simulation = None;
    let mut unbound_admin_grant = request.clone();
    unbound_admin_grant
        .key_authorization
        .as_mut()
        .unwrap()
        .authorization
        .account = None;
    let mut invalid_cases = vec![
        (
            wrong_metadata,
            format!("key authorization account mismatch: expected {parent}, actual {wrong}"),
        ),
        (
            wrong_delegate,
            "a configurable delegate cannot be its own parent".into(),
        ),
        (
            missing_witness,
            "configurable account simulation signature requires its source witness".into(),
        ),
    ];
    if admin {
        invalid_cases.push((
            unbound_admin_grant,
            "admin-signed grant simulation requires its signer as keyId and the parent as account"
                .into(),
        ));
    } else {
        invalid_cases.push((
            wrong_signer,
            "admin-signed grant requires its signer as keyId and the parent as account".into(),
        ));
    }
    for (mut invalid, expected) in invalid_cases {
        let Err(EthApiError::InvalidParams(message)) = prepare_configurable_account_simulation(
            &mut invalid,
            TempoHardfork::T14,
            &block(),
            &mut db,
        ) else {
            panic!("expected {expected}")
        };
        assert_eq!(message, expected);
        assert!(!invalid.configurable_account_simulation_prepared);
    }
    // Repeated preparation must retain both valid roles after the rejected alternatives.
    prepare_configurable_account_simulation(&mut request, TempoHardfork::T14, &block(), &mut db)
        .unwrap();
    let tx = request.try_into_tx_env(&TempoEvmEnv::default()).unwrap();
    let signed = tx.as_aa().unwrap().inner();
    let TempoSignature::Keychain(keychain) = signed.signature() else {
        panic!("delegate role expected")
    };
    assert_eq!(
        keychain
            .signature
            .as_configurable_account()
            .unwrap()
            .account(),
        delegate
    );
    let grant = signed.tx().key_authorization.as_ref().unwrap();
    assert_eq!(
        grant.signature.as_configurable_account().unwrap().account(),
        if admin { delegate } else { parent }
    );
    assert_eq!(tx.execution_context(), ExecutionContext::Simulation);
}

#[test_case::test_case(WitnessRejection::BeforeT14(TempoHardfork::T12); "before_t14_at_t12")]
#[test_case::test_case(WitnessRejection::BeforeT14(TempoHardfork::T13); "before_t14_at_t13")]
#[test_case::test_case(WitnessRejection::Code; "account_has_code")]
#[test_case::test_case(WitnessRejection::UnregisteredVersion; "unregistered_positive_version")]
#[test_case::test_case(WitnessRejection::WrongIdentity; "wrong_initial_identity")]
fn rejects_invalid_witness_state(case: WitnessRejection) {
    let version = u64::from(matches!(case, WitnessRejection::UnregisteredVersion));
    let (account, spec) = spec(1, version);
    let mut request = TempoTransactionRequest {
        inner: TransactionRequest::default().from(account),
        configurable_account_simulation: Some(spec.clone()),
        ..Default::default()
    };
    let mut db = AccountDb::default();
    if version != 0 {
        db.insert_commitment(account, spec.config.commitment().unwrap());
    }
    prepare_configurable_account_simulation(
        &mut request.clone(),
        TempoHardfork::T14,
        &block(),
        &mut db,
    )
    .unwrap();
    let mut fork = TempoHardfork::T14;
    let expected = match case {
        WitnessRejection::BeforeT14(pre_activation) => {
            fork = pre_activation;
            "configurable account simulation requires T14 at the requested state".to_owned()
        }
        WitnessRejection::Code => {
            db.0.entry(account).or_default().code_hash =
                Bytecode::new_legacy(vec![0x60, 0x00].into()).hash_slow();
            format!("configurable account {account} has code at the requested state")
        }
        WitnessRejection::UnregisteredVersion => {
            db.0.remove(&account);
            "unregistered configuration version mismatch: expected 0, actual 1".to_owned()
        }
        WitnessRejection::WrongIdentity => {
            let wrong = Address::repeat_byte(9);
            request.inner.from = Some(wrong);
            format!(
                "initial configurable account mismatch at the requested state: expected {account}, actual {wrong}"
            )
        }
    };
    let Err(EthApiError::InvalidParams(message)) =
        prepare_configurable_account_simulation(&mut request, fork, &block(), &mut db)
    else {
        panic!("expected {expected}")
    };
    assert_eq!(message, expected);
}

#[test]
fn distinguishes_state_mismatch_from_corrupt_leaf() {
    let (account, spec) = spec(1, 0);
    let commitment = spec.config.commitment().unwrap();
    let mut request = TempoTransactionRequest {
        inner: TransactionRequest::default().from(account),
        configurable_account_simulation: Some(spec),
        ..Default::default()
    };
    let mut db = AccountDb::default();
    let stale = B256::repeat_byte(7);
    db.insert_commitment(account, stale);
    let Err(EthApiError::InvalidParams(message)) = prepare_configurable_account_simulation(
        &mut request.clone(),
        TempoHardfork::T14,
        &block(),
        &mut db,
    ) else {
        panic!("expected a state mismatch")
    };
    assert_eq!(
        message,
        format!(
            "{} for {account} at the requested state",
            ConfigurableAccountStateError::CommitmentMismatch {
                expected: stale,
                actual: commitment,
            }
        )
    );
    db.0.get_mut(&account).unwrap().extension = vec![1].into();
    assert!(matches!(
        prepare_configurable_account_simulation(
            &mut request,
            TempoHardfork::T14,
            &block(),
            &mut db
        ),
        Err(EthApiError::Internal(_))
    ));
}

#[test]
fn factory_is_required_and_registered_version_zero_is_valid() {
    let (account, spec) = spec(1, 0);
    let mut db = AccountDb::default();
    db.insert_commitment(account, spec.config.commitment().unwrap());
    let mut request = TempoTransactionRequest {
        inner: TransactionRequest::default().from(account),
        configurable_account_simulation: Some(spec),
        ..Default::default()
    };
    assert!(
        prepare_configurable_account_simulation(
            &mut request.clone(),
            TempoHardfork::T14,
            &TempoBlockExt::default(),
            &mut db
        )
        .is_err()
    );
    prepare_configurable_account_simulation(&mut request, TempoHardfork::T14, &block(), &mut db)
        .unwrap();
}

#[test]
fn fill_output_preserves_real_grant_and_removes_simulation_hints() {
    let (account, spec) = spec(1, 0);
    let real_grant =
        KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, Address::repeat_byte(5))
            .into_signed(PrimitiveSignature::default());
    let mut request = TempoTransactionRequest {
        inner: TransactionRequest {
            from: Some(account),
            to: Some(Address::repeat_byte(6).into()),
            chain_id: Some(4217),
            nonce: Some(0),
            gas: Some(100_000),
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            ..Default::default()
        },
        configurable_account_simulation: Some(spec.clone()),
        key_authorization: Some(real_grant.clone()),
        ..Default::default()
    };
    let mut mock_grant_request = request.clone();
    mock_grant_request.key_authorization_simulation = Some(spec);
    assert!(prepare_fill_output(&mut mock_grant_request).is_err());
    let saved = prepare_fill_output(&mut request).unwrap();
    assert!(!request.has_configurable_simulation());
    let tx = request
        .build_aa()
        .unwrap()
        .into_signed(TempoSignature::default())
        .into();
    let TempoTxEnvelope::AA(signed) = restore_fill_authorization(tx, saved).unwrap() else {
        panic!("AA expected")
    };
    assert_eq!(signed.tx().key_authorization, Some(real_grant));
    assert!(matches!(signed.signature(), TempoSignature::Primitive(_)));
}
