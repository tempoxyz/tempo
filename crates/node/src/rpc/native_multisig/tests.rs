use super::*;
use alloy_primitives::{B256, U256};
use reth_evm::revm::{bytecode::Bytecode, state::AccountInfo};
use std::collections::HashMap;
use tempo_alloy::rpc::{MultisigSimulationApproval, MultisigSimulationSpec};
use tempo_primitives::{
    SignatureType,
    account::encode_config_commitment,
    transaction::{KeyAuthorization, MultisigConfig, MultisigOwner, PrimitiveSignature},
};

const FACTORY: Address = Address::repeat_byte(0x99);
#[derive(Default)]
struct AccountDb(HashMap<Address, AccountInfo>);
impl AccountDb {
    fn insert_commitment(&mut self, account: Address, hash: B256) {
        self.0.entry(account).or_default().extension = encode_config_commitment(hash).into();
    }
}
impl Database for AccountDb {
    type Error = reth_errors::ProviderError;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.0.get(&address).cloned())
    }
    fn code_by_hash(&mut self, _: B256) -> Result<Bytecode, Self::Error> {
        panic!("metadata suffices")
    }
    fn storage(&mut self, _: Address, _: U256) -> Result<U256, Self::Error> {
        panic!("no storage fallback")
    }
    fn block_hash(&mut self, _: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}
fn spec(salt: u8, version: u64) -> (Address, MultisigSimulationSpec) {
    let owner = Address::repeat_byte(1);
    let config = MultisigConfig {
        salt: B256::repeat_byte(salt),
        version,
        threshold: 1,
        owners: vec![MultisigOwner { owner, weight: 1 }],
    };
    let account = config.derive_account(FACTORY).unwrap();
    (
        account,
        MultisigSimulationSpec {
            config,
            approvals: vec![MultisigSimulationApproval {
                owner,
                key_type: Some(SignatureType::Secp256k1),
                key_data: None,
            }],
        },
    )
}
fn block() -> TempoBlockEnv {
    TempoBlockEnv {
        multisig_recovery_factory: Some(FACTORY),
        ..Default::default()
    }
}

#[test_case::test_case(0; "initial")]
#[test_case::test_case(1; "registered")]
fn prepares_independent_delegate_and_parent_roles(version: u64) {
    let (parent, parent_spec) = spec(1, version);
    let (delegate, delegate_spec) = spec(2, version);
    let mut db = AccountDb::default();
    if version != 0 {
        db.insert_commitment(parent, parent_spec.config.commitment().unwrap());
        db.insert_commitment(delegate, delegate_spec.config.commitment().unwrap());
    }
    let mut request = TempoTransactionRequest {
        inner: alloy_rpc_types_eth::TransactionRequest {
            from: Some(parent),
            to: Some(Address::repeat_byte(8).into()),
            ..Default::default()
        },
        key_id: Some(delegate),
        key_type: Some(SignatureType::Multisig),
        multisig_simulation: Some(delegate_spec),
        key_authorization_simulation: Some(parent_spec),
        key_authorization: Some(
            KeyAuthorization::unrestricted(4217, SignatureType::Multisig, delegate)
                .into_signed(PrimitiveSignature::default()),
        ),
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
    let Err(EthApiError::InvalidParams(message)) = prepare_native_multisig_simulation(
        &mut wrong_metadata,
        TempoHardfork::T12,
        &block(),
        &mut db,
    ) else {
        panic!("expected grant metadata rejection")
    };
    assert_eq!(
        message,
        format!("key authorization account mismatch: expected {parent}, actual {wrong}")
    );
    prepare_native_multisig_simulation(&mut request, TempoHardfork::T12, &block(), &mut db)
        .unwrap();

    let mut wrong_metadata = request.clone();
    wrong_metadata
        .key_authorization
        .as_mut()
        .unwrap()
        .authorization
        .account = Some(wrong);
    let mut wrong_signer = request.clone();
    wrong_signer.key_authorization.as_mut().unwrap().signature =
        TempoSignature::Multisig(request.multisig_simulation_signature.clone().unwrap());
    let mut wrong_delegate = request.clone();
    wrong_delegate.key_id = Some(wrong);
    for (mut invalid, expected) in [
        (
            wrong_metadata,
            format!("key authorization account mismatch: expected {parent}, actual {wrong}"),
        ),
        (
            wrong_signer,
            format!("multisig signature account mismatch: expected {parent}, actual {delegate}"),
        ),
        (
            wrong_delegate,
            format!(
                "multisig simulation signature account mismatch: expected {wrong}, actual {delegate}"
            ),
        ),
    ] {
        let Err(EthApiError::InvalidParams(message)) =
            prepare_native_multisig_simulation(&mut invalid, TempoHardfork::T12, &block(), &mut db)
        else {
            panic!("expected {expected}")
        };
        assert_eq!(message, expected);
    }
    // Repeated preparation must retain both valid roles after the rejected alternatives.
    prepare_native_multisig_simulation(&mut request, TempoHardfork::T12, &block(), &mut db)
        .unwrap();
    let tx = request
        .try_into_tempo_tx_env(tempo_revm::TempoTxEnv::default(), true)
        .unwrap();
    let roles = tempo_revm::native_multisig::authorizations(&tx);
    assert_eq!(roles.len(), 2);
    assert_eq!(roles[0].signature.account(), delegate);
    assert_eq!(roles[1].signature.account(), parent);
    assert_eq!(
        tx.execution_context,
        tempo_revm::ExecutionContext::Simulation
    );
}

#[derive(Clone, Copy)]
enum WitnessRejection {
    BeforeT12,
    Code,
    UnregisteredVersion,
    WrongIdentity,
}

#[test_case::test_case(WitnessRejection::BeforeT12; "before_t12")]
#[test_case::test_case(WitnessRejection::Code; "account_has_code")]
#[test_case::test_case(WitnessRejection::UnregisteredVersion; "unregistered_positive_version")]
#[test_case::test_case(WitnessRejection::WrongIdentity; "wrong_initial_identity")]
fn rejects_invalid_witness_state(case: WitnessRejection) {
    let version = u64::from(matches!(case, WitnessRejection::UnregisteredVersion));
    let (account, spec) = spec(1, version);
    let mut request = TempoTransactionRequest {
        inner: alloy_rpc_types_eth::TransactionRequest {
            from: Some(account),
            ..Default::default()
        },
        multisig_simulation: Some(spec.clone()),
        ..Default::default()
    };
    let mut db = AccountDb::default();
    if version != 0 {
        db.insert_commitment(account, spec.config.commitment().unwrap());
    }
    prepare_native_multisig_simulation(&mut request.clone(), TempoHardfork::T12, &block(), &mut db)
        .unwrap();
    let mut fork = TempoHardfork::T12;
    let expected = match case {
        WitnessRejection::BeforeT12 => {
            fork = TempoHardfork::T11;
            "native multisig simulation requires T12 at the requested state".to_owned()
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
                "initial multisig account mismatch at the requested state: expected {account}, actual {wrong}"
            )
        }
    };
    let Err(EthApiError::InvalidParams(message)) =
        prepare_native_multisig_simulation(&mut request, fork, &block(), &mut db)
    else {
        panic!("expected {expected}")
    };
    assert_eq!(message, expected);
}

#[test]
fn distinguishes_state_mismatch_from_corrupt_leaf() {
    let (account, spec) = spec(1, 0);
    let mut request = TempoTransactionRequest {
        inner: alloy_rpc_types_eth::TransactionRequest {
            from: Some(account),
            ..Default::default()
        },
        multisig_simulation: Some(spec),
        ..Default::default()
    };
    let mut db = AccountDb::default();
    db.insert_commitment(account, B256::repeat_byte(7));
    let error = prepare_native_multisig_simulation(
        &mut request.clone(),
        TempoHardfork::T12,
        &block(),
        &mut db,
    )
    .unwrap_err();
    assert!(matches!(error, EthApiError::InvalidParams(_)));
    assert!(error.to_string().contains("requested state"));
    db.0.get_mut(&account).unwrap().extension = vec![1].into();
    assert!(matches!(
        prepare_native_multisig_simulation(&mut request, TempoHardfork::T12, &block(), &mut db),
        Err(EthApiError::Internal(_))
    ));
}

#[test]
fn factory_is_required_and_registered_version_zero_is_valid() {
    let (account, spec) = spec(1, 0);
    let mut db = AccountDb::default();
    db.insert_commitment(account, spec.config.commitment().unwrap());
    let mut request = TempoTransactionRequest {
        inner: alloy_rpc_types_eth::TransactionRequest {
            from: Some(account),
            ..Default::default()
        },
        multisig_simulation: Some(spec),
        ..Default::default()
    };
    assert!(
        prepare_native_multisig_simulation(
            &mut request.clone(),
            TempoHardfork::T12,
            &TempoBlockEnv::default(),
            &mut db
        )
        .is_err()
    );
    prepare_native_multisig_simulation(&mut request, TempoHardfork::T12, &block(), &mut db)
        .unwrap();
}

#[test]
fn fill_output_preserves_real_grant_and_removes_simulation_hints() {
    let (account, spec) = spec(1, 0);
    let real_grant =
        KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, Address::repeat_byte(5))
            .into_signed(PrimitiveSignature::Secp256k1(
                alloy_primitives::Signature::test_signature(),
            ));
    let mut request = TempoTransactionRequest {
        inner: alloy_rpc_types_eth::TransactionRequest {
            from: Some(account),
            to: Some(Address::repeat_byte(6).into()),
            chain_id: Some(4217),
            nonce: Some(0),
            gas: Some(100_000),
            max_fee_per_gas: Some(1),
            max_priority_fee_per_gas: Some(1),
            ..Default::default()
        },
        multisig_simulation: Some(spec.clone()),
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
    let tempo_primitives::TempoTxEnvelope::AA(signed) =
        restore_fill_authorization(tx, saved).unwrap()
    else {
        panic!("AA expected")
    };
    assert_eq!(signed.tx().key_authorization, Some(real_grant));
    assert!(matches!(signed.signature(), TempoSignature::Primitive(_)));
}
