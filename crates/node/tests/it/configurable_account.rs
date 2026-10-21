//! Configurable-account authorization guards of the T14 transaction handler.
//!
//! Each test runs signed transactions through the production [`TempoEvmConfig`] EVM for a T14
//! chain with the recovery factory configured.

use std::sync::Arc;

use alloy::{
    consensus::{Header, SignableTransaction, TxEip7702},
    eips::eip7702::Authorization,
    primitives::{Address, B256, Bytes, KECCAK256_EMPTY, TxKind, U256},
    rpc::types::TransactionRequest,
    signers::{SignerSync, local::PrivateKeySigner},
    sol_types::SolCall,
};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, InMemoryDB},
};
use reth_evm::{ConfigureEvm, EvmEnvFor, FromTxWithEncoded};
use reth_primitives_traits::{Recovered, SignedTransaction};
use reth_rpc_eth_api::{TryIntoSimTx, TryIntoTxEnv};
use serde_json::{Value, from_str, from_value, json};
use tempo_alloy::rpc::{
    ConfigurableAccountSimulationApproval, ConfigurableAccountSimulationSpec,
    TempoTransactionRequest,
};
use tempo_chainspec::TempoChainSpec;
use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount};
use tempo_evm::{
    ExecutionContext, TempoEvm, TempoEvmConfig, TempoInvalidTransaction, TempoTxEnv,
    transaction_error::{ConfigurableAccountError, RootKeyRole},
};
use tempo_precompiles::{PATH_USD_ADDRESS, storage::StorageCtx, test_util::TIP20Setup};
use tempo_primitives::{
    TempoHeader, TempoTxEnvelope,
    transaction::{
        Call, ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
        ConfigurableAccountStateError, PrimitiveSignature, SignatureType, TempoSignature,
        TempoSignedAuthorization, TempoTransaction, configurable_account_digest,
    },
};

const CHAIN_ID: u64 = 1337;
const FACTORY: Address = Address::repeat_byte(0x71);
const DELEGATE: Address = Address::repeat_byte(0x44);

fn evm_config() -> TempoEvmConfig {
    let mut genesis: Value = from_str(include_str!("../assets/test-genesis.json")).unwrap();
    genesis["config"]["configurableAccountRecoveryFactory"] = json!(FACTORY);
    TempoEvmConfig::new(Arc::new(TempoChainSpec::from_genesis(
        from_value(genesis).unwrap(),
    )))
}

fn evm_env(config: &TempoEvmConfig) -> EvmEnvFor<TempoEvmConfig> {
    let header = TempoHeader {
        inner: Header {
            number: 1,
            timestamp: 1,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(0),
            ..Default::default()
        },
        general_gas_limit: 30_000_000,
        shared_gas_limit: 30_000_000,
        ..Default::default()
    };
    let env = config.evm_env(&header).unwrap();
    assert!(env.spec.is_t14());
    env
}

fn evm(db: InMemoryDB) -> TempoEvm<'static> {
    let config = evm_config();
    let env = evm_env(&config);
    let mut evm = config.evm_with_env(db, env);
    StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
        TIP20Setup::path_usd(Address::repeat_byte(0x01)).apply()
    })
    .unwrap();
    evm
}

fn aa_tx(nonce: u64, calls: Vec<Call>) -> TempoTransaction {
    TempoTransaction {
        chain_id: CHAIN_ID,
        nonce,
        gas_limit: 5_000_000,
        fee_token: Some(PATH_USD_ADDRESS),
        calls,
        ..Default::default()
    }
}

fn call(to: Address, input: Bytes) -> Call {
    Call {
        to: TxKind::Call(to),
        value: U256::ZERO,
        input,
    }
}

fn primitive(signer: &PrivateKeySigner, hash: B256) -> PrimitiveSignature {
    PrimitiveSignature::Secp256k1(signer.sign_hash_sync(&hash).unwrap())
}

fn signed_by_root(tx: TempoTransaction, root: &PrivateKeySigner) -> Recovered<TempoTxEnv> {
    let signature = TempoSignature::Primitive(primitive(root, tx.signature_hash()));
    recovered(
        TempoTxEnvelope::AA(tx.into_signed(signature)),
        root.address(),
    )
}

fn recovered(envelope: TempoTxEnvelope, caller: Address) -> Recovered<TempoTxEnv> {
    let env: TempoTxEnv = envelope.with_signer(caller).into();
    Recovered::new_unchecked(env, caller)
}

/// A fresh one-owner configurable account and its derived address.
fn configurable_account(owner: &PrivateKeySigner) -> (ConfigurableAccountConfig, Address) {
    let config = ConfigurableAccountConfig {
        salt: B256::repeat_byte(0x5a),
        version: 0,
        threshold: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: owner.address(),
            weight: 1,
        }],
    };
    let account = config.derive_account(FACTORY).unwrap();
    (config, account)
}

fn signed_by_account(
    tx: TempoTransaction,
    owner: &PrivateKeySigner,
    config: ConfigurableAccountConfig,
    account: Address,
) -> TempoTxEnvelope {
    let digest = configurable_account_digest(tx.signature_hash(), account, config.version);
    let signature =
        ConfigurableAccountSignature::try_new(account, config, vec![primitive(owner, digest)])
            .unwrap();
    TempoTxEnvelope::AA(tx.into_signed(TempoSignature::ConfigurableAccount(signature)))
}

fn upgrade_call(owner: Address) -> Call {
    call(
        CONFIGURABLE_ACCOUNT_ADDRESS,
        IConfigurableAccount::upgradeAccountCall {
            threshold: 1,
            owners: vec![IConfigurableAccount::ConfigurableAccountOwner { owner, weight: 1 }],
        }
        .abi_encode()
        .into(),
    )
}

fn commitment(evm: &mut TempoEvm<'static>, account: Address) -> B256 {
    StorageCtx::enter_evm_without_tip1060_accounting(evm, || StorageCtx.config_commitment(account))
        .unwrap()
}

fn has_code(evm: &mut TempoEvm<'static>, account: Address) -> bool {
    evm.state_mut()
        .account_info_untracked(&account)
        .unwrap()
        .is_some_and(|info| info.code_hash != KECCAK256_EMPTY)
}

#[track_caller]
fn invalid(evm: &mut TempoEvm<'static>, tx: &Recovered<TempoTxEnv>) -> TempoInvalidTransaction {
    let error = evm.transact(tx).map(|_| ()).unwrap_err();
    error
        .external_ref::<TempoInvalidTransaction>()
        .unwrap_or_else(|| panic!("{error:?}"))
        .clone()
}

/// Upgrades `root` in place through a sole `upgradeAccount` call it signs.
fn upgraded_root(evm: &mut TempoEvm<'static>, root: &PrivateKeySigner) {
    let owner = PrivateKeySigner::random();
    let tx = signed_by_root(aa_tx(0, vec![upgrade_call(owner.address())]), root);
    let result = evm.transact(&tx).unwrap().commit();
    assert!(result.status, "{result:?}");
    assert!(!commitment(evm, root.address()).is_zero());
}

/// The handler seeds the precompile's transaction authority: without it `upgradeAccount` sees no
/// origin and reverts.
#[test]
fn upgrade_account_reads_the_seeded_authority() {
    let mut evm = evm(InMemoryDB::default());
    upgraded_root(&mut evm, &PrivateKeySigner::random());
}

/// A primitive root key retires once its account has a configuration commitment.
#[test]
fn retired_root_key_cannot_sign_transactions() {
    let mut evm = evm(InMemoryDB::default());
    let root = PrivateKeySigner::random();
    upgraded_root(&mut evm, &root);

    let tx = signed_by_root(aa_tx(1, vec![call(DELEGATE, Bytes::new())]), &root);
    assert_eq!(
        invalid(&mut evm, &tx),
        TempoInvalidTransaction::RootKeyRetired {
            account: root.address(),
            role: RootKeyRole::Sender,
        }
    );
}

/// A retired root key's EIP-7702 authorization in a Tempo transaction installs no delegation.
#[test]
fn retired_authority_is_skipped_in_tempo_authorization_lists() {
    let mut evm = evm(InMemoryDB::default());
    let root = PrivateKeySigner::random();
    upgraded_root(&mut evm, &root);

    let authorization = Authorization {
        chain_id: U256::from(CHAIN_ID),
        address: DELEGATE,
        nonce: 1,
    };
    let signature = primitive(&root, authorization.signature_hash());
    let mut tx = aa_tx(0, vec![call(DELEGATE, Bytes::new())]);
    tx.tempo_authorization_list = vec![TempoSignedAuthorization::new_unchecked(
        authorization,
        TempoSignature::Primitive(signature),
    )];
    let sender = PrivateKeySigner::random();
    let result = evm.transact(&signed_by_root(tx, &sender)).unwrap().commit();
    assert!(result.status, "{result:?}");
    assert!(!has_code(&mut evm, root.address()));
}

/// A retired root key's authorization in an EIP-7702 transaction installs no delegation.
#[test]
fn retired_authority_is_skipped_in_eip7702_transactions() {
    let mut evm = evm(InMemoryDB::default());
    let root = PrivateKeySigner::random();
    upgraded_root(&mut evm, &root);

    let authorization = Authorization {
        chain_id: U256::from(CHAIN_ID),
        address: DELEGATE,
        nonce: 1,
    };
    let signature = root
        .sign_hash_sync(&authorization.signature_hash())
        .unwrap();
    let tx = TxEip7702 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_limit: 5_000_000,
        to: DELEGATE,
        authorization_list: vec![authorization.into_signed(signature)],
        ..Default::default()
    };
    let sender = PrivateKeySigner::random();
    let signature = sender.sign_hash_sync(&tx.signature_hash()).unwrap();
    let result = evm
        .transact(&recovered(
            TempoTxEnvelope::Eip7702(tx.into_signed(signature)),
            sender.address(),
        ))
        .unwrap()
        .commit();
    assert!(result.status, "{result:?}");
    assert!(!has_code(&mut evm, root.address()));
}

/// The outer configurable-account signature must name the transaction's sender.
#[test]
fn configurable_account_signature_must_name_the_sender() {
    let mut evm = evm(InMemoryDB::default());
    let owner = PrivateKeySigner::random();
    let (config, account) = configurable_account(&owner);
    let other = Address::repeat_byte(0x55);
    let envelope = signed_by_account(
        aa_tx(0, vec![call(DELEGATE, Bytes::new())]),
        &owner,
        config,
        account,
    );
    assert_eq!(
        invalid(&mut evm, &recovered(envelope, other)),
        TempoInvalidTransaction::ConfigurableAccount(ConfigurableAccountError::AccountMismatch {
            expected: other,
            actual: account,
        })
    );
}

/// A simulated transaction whose outer configurable-account signature names an account other than
/// its sender is rejected like a real one, although RPC preprocessing never builds such a mock.
#[test]
fn simulated_configurable_account_signature_must_name_the_sender() {
    let mut evm = evm(InMemoryDB::default());
    let owner = PrivateKeySigner::random();
    let (config, account) = configurable_account(&owner);
    let other = Address::repeat_byte(0x55);
    let spec = ConfigurableAccountSimulationSpec {
        signer: None,
        config,
        approvals: vec![ConfigurableAccountSimulationApproval {
            owner: owner.address(),
            key_type: Some(SignatureType::Secp256k1),
            key_data: None,
        }],
    };
    // State-aware preprocessing binds the mock to `from`; install one for another account to
    // reach the handler guard.
    let request = TempoTransactionRequest {
        inner: TransactionRequest::default()
            .from(other)
            .to(DELEGATE)
            .gas_limit(5_000_000),
        fee_token: Some(PATH_USD_ADDRESS),
        key_type: Some(SignatureType::ConfigurableAccount),
        configurable_account_simulation: Some(spec.clone()),
        configurable_account_simulation_signature: Some(spec.mock_signature(account).unwrap()),
        configurable_account_simulation_prepared: true,
        ..Default::default()
    };
    let mut env = evm_env(&evm_config());
    env.version.chain_id = CHAIN_ID;
    let tx = request.try_into_tx_env(&env).unwrap();
    assert_eq!(tx.execution_context(), ExecutionContext::Simulation);
    assert_eq!(
        invalid(&mut evm, &tx),
        TempoInvalidTransaction::ConfigurableAccount(ConfigurableAccountError::AccountMismatch {
            expected: other,
            actual: account,
        })
    );
}

/// A simulated `WebAuthn` owner approval is charged its modeled data as nonzero calldata.
#[test]
fn simulated_webauthn_approvals_charge_worst_case_data() {
    let owner = PrivateKeySigner::random();
    let (config, account) = configurable_account(&owner);
    let gas_used = |key_type: SignatureType, key_data: Option<Bytes>| {
        let spec = ConfigurableAccountSimulationSpec {
            signer: None,
            config: config.clone(),
            approvals: vec![ConfigurableAccountSimulationApproval {
                owner: owner.address(),
                key_type: Some(key_type),
                key_data,
            }],
        };
        let request = TempoTransactionRequest {
            inner: TransactionRequest::default()
                .from(account)
                .to(DELEGATE)
                .gas_limit(5_000_000),
            fee_token: Some(PATH_USD_ADDRESS),
            key_type: Some(SignatureType::ConfigurableAccount),
            configurable_account_simulation_signature: Some(spec.mock_signature(account).unwrap()),
            configurable_account_simulation: Some(spec),
            configurable_account_simulation_prepared: true,
            ..Default::default()
        };
        let mut env = evm_env(&evm_config());
        env.version.chain_id = CHAIN_ID;
        let tx = request.try_into_tx_env(&env).unwrap();
        let result = evm(InMemoryDB::default()).transact(&tx).unwrap().commit();
        assert!(result.status, "{result:?}");
        result.tx_gas_used()
    };
    // Same witness with no WebAuthn data isolates the data charge.
    let empty = gas_used(SignatureType::P256, None);
    for size in [128u16, 800, 1920] {
        let webauthn = gas_used(
            SignatureType::WebAuthn,
            Some(Bytes::from(size.to_be_bytes())),
        );
        assert_eq!(webauthn - empty, u64::from(size) * 16, "size {size}");
    }
}

/// A configurable account with code, including a delegation, cannot sign.
#[test]
fn configurable_account_with_code_cannot_sign() {
    let owner = PrivateKeySigner::random();
    let (config, account) = configurable_account(&owner);
    let mut db = InMemoryDB::default();
    db.insert_account_info(
        &account,
        AccountInfo::default().with_code(Bytecode::new_eip7702(DELEGATE)),
    );
    let mut evm = evm(db);
    let envelope = signed_by_account(
        aa_tx(0, vec![call(DELEGATE, Bytes::new())]),
        &owner,
        config,
        account,
    );
    assert_eq!(
        invalid(&mut evm, &recovered(envelope, account)),
        TempoInvalidTransaction::ConfigurableAccount(ConfigurableAccountError::InvalidAccount {
            account
        })
    );
}

/// A configurable-account signature adds its TIP-1114 verification cost `V - 3,000` to intrinsic
/// gas, on top of the first-use account proof and the TIP-1108 registration write.
#[test]
fn configurable_account_signature_verification_is_intrinsic_gas() {
    let mut evm = evm(InMemoryDB::default());
    let calls = vec![call(DELEGATE, Bytes::new())];

    let root = PrivateKeySigner::random();
    let primitive = evm
        .transact(&signed_by_root(aa_tx(0, calls.clone()), &root))
        .unwrap()
        .commit();
    assert!(primitive.status, "{primitive:?}");

    let owner = PrivateKeySigner::random();
    let (config, account) = configurable_account(&owner);
    let witness = [alloy_rlp::encode(account), alloy_rlp::encode(&config)].concat();
    let envelope = signed_by_account(aa_tx(0, calls), &owner, config, account);
    let native = evm
        .transact(&recovered(envelope, account))
        .unwrap()
        .commit();
    assert!(native.status, "{native:?}");
    assert!(!commitment(&mut evm, account).is_zero());

    // K(n) = 30 + 6 * ceil(n / 32); one owner, one secp256k1 approval.
    let keccak = |len: u64| 30 + 6 * len.div_ceil(32);
    let calldata: u64 = witness
        .iter()
        .map(|byte| if *byte == 0 { 4 } else { 16 })
        .sum();
    // V - 3,000: witness calldata, commitment K(75 + 21), digest K(96), approval 3,000 - 3,000.
    let verification = calldata + keccak(75 + 21) + keccak(96);
    // First use: derivation K(68 + 21) + K(85), plus the 20,000 registration write.
    let first_use = keccak(68 + 21) + keccak(85) + 20_000;
    assert_eq!(
        native.tx_gas_used() - primitive.tx_gas_used(),
        verification + first_use
    );
}

/// A registered account signing with another configuration fails with the commitment mismatch
/// that the account state reports, worded as the state error is.
#[test]
fn configurable_account_commitment_mismatch_reads_as_the_state_error() {
    let mut evm = evm(InMemoryDB::default());
    let owner = PrivateKeySigner::random();
    let (config, account) = configurable_account(&owner);
    let calls = vec![call(DELEGATE, Bytes::new())];
    let envelope = signed_by_account(aa_tx(0, calls.clone()), &owner, config.clone(), account);
    let result = evm
        .transact(&recovered(envelope, account))
        .unwrap()
        .commit();
    assert!(result.status, "{result:?}");
    let registered = commitment(&mut evm, account);

    let stale = ConfigurableAccountConfig {
        salt: B256::repeat_byte(0x5b),
        ..config
    };
    let envelope = signed_by_account(aa_tx(1, calls), &owner, stale, account);
    let error = invalid(&mut evm, &recovered(envelope, account));
    let TempoInvalidTransaction::ConfigurableAccount(
        ConfigurableAccountError::ConfigurationCommitmentMismatch { expected, actual },
    ) = error
    else {
        panic!("{error:?}");
    };
    assert_eq!(expected, registered);
    assert_ne!(actual, registered);
    assert_eq!(
        error.to_string(),
        ConfigurableAccountStateError::CommitmentMismatch { expected, actual }.to_string()
    );
}

/// Each call of a simulated block is checked against the account state at its position: a
/// configuration rotated by one call is stale for the next call that still names it.
#[test]
fn block_simulation_checks_each_call_against_its_position() {
    let mut evm = evm(InMemoryDB::default());
    let owner = PrivateKeySigner::random();
    let rotated_owner = PrivateKeySigner::random();
    let (config, account) = configurable_account(&owner);
    let rotated = ConfigurableAccountConfig {
        version: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: rotated_owner.address(),
            weight: 1,
        }],
        ..config.clone()
    };
    // Builds the call as reth's simulation does: an empty encoding marks it as simulated.
    let sim =
        |nonce: u64, config: &ConfigurableAccountConfig, approver: &PrivateKeySigner, to: Call| {
            let request = TempoTransactionRequest {
                inner: TransactionRequest {
                    chain_id: Some(CHAIN_ID),
                    from: Some(account),
                    nonce: Some(nonce),
                    gas: Some(5_000_000),
                    max_fee_per_gas: Some(0),
                    max_priority_fee_per_gas: Some(0),
                    ..Default::default()
                },
                calls: vec![to],
                fee_token: Some(PATH_USD_ADDRESS),
                key_type: Some(SignatureType::ConfigurableAccount),
                configurable_account_simulation: Some(ConfigurableAccountSimulationSpec {
                    signer: None,
                    config: config.clone(),
                    approvals: vec![ConfigurableAccountSimulationApproval {
                        owner: approver.address(),
                        key_type: Some(SignatureType::Secp256k1),
                        key_data: None,
                    }],
                }),
                ..Default::default()
            };
            let tx = TryIntoSimTx::<TempoTxEnvelope>::try_into_sim_tx(request).unwrap();
            let env = TempoTxEnv::from_tx_with_encoded(
                tx.with_signer(account).into_encoded_with(Bytes::new()),
            );
            assert_eq!(env.execution_context(), ExecutionContext::Simulation);
            Recovered::new_unchecked(env, account)
        };

    let rotate = call(
        CONFIGURABLE_ACCOUNT_ADDRESS,
        IConfigurableAccount::updateConfigCall {
            current: IConfigurableAccount::ConfigurableAccountConfig {
                salt: config.salt,
                version: config.version,
                threshold: 1,
                owners: vec![IConfigurableAccount::ConfigurableAccountOwner {
                    owner: owner.address(),
                    weight: 1,
                }],
            },
            threshold: 1,
            owners: vec![IConfigurableAccount::ConfigurableAccountOwner {
                owner: rotated_owner.address(),
                weight: 1,
            }],
        }
        .abi_encode()
        .into(),
    );
    let result = evm
        .transact(&sim(0, &config, &owner, rotate))
        .unwrap()
        .commit();
    assert!(result.status, "{result:?}");
    let registered = commitment(&mut evm, account);
    assert_eq!(registered, rotated.commitment().unwrap());

    let noop = call(DELEGATE, Bytes::new());
    assert_eq!(
        invalid(&mut evm, &sim(1, &config, &owner, noop.clone())),
        TempoInvalidTransaction::ConfigurableAccount(
            ConfigurableAccountError::ConfigurationCommitmentMismatch {
                expected: registered,
                actual: config.commitment().unwrap(),
            }
        )
    );
    let result = evm
        .transact(&sim(1, &rotated, &rotated_owner, noop))
        .unwrap()
        .commit();
    assert!(result.status, "{result:?}");
}
