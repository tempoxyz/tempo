//! Deterministic capture/consume coverage for the marked Engine factory.

use super::*;
use crate::{
    TempoBlockEnv, TempoBlockExecutionCtx, TempoEvmConfig,
    evm::{TempoEvm, TempoEvmFactory},
    parallel::SpeculativeExecutor,
};
use alloy_consensus::{Signed, TxLegacy};
use alloy_evm::{
    Evm, EvmFactory, FromRecoveredTx,
    block::{BlockExecutor, BlockExecutorFactory, TxResult},
};
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
use alloy_sol_types::SolCall;
use alloy_trie::{
    TrieAccount,
    root::{state_root_unhashed, storage_root_unhashed},
};
use reth_primitives_traits::Recovered;
use revm::{
    Database, DatabaseCommit,
    context::{CfgEnv, JournalTr, TxEnv},
    database::{CacheDB, EmptyDB},
    inspector::NoOpInspector,
    state::{AccountInfo, Bytecode},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    storage::{StorageActions, StorageCtx},
    test_util::TIP20Setup,
    tip20::ITIP20,
};
use tempo_primitives::{TempoSignature, TempoTransaction, TempoTxEnvelope, transaction::Call};

type TestDB = CacheDB<EmptyDB>;

fn address(index: u64) -> Address {
    Address::from_word(B256::from(U256::from(index + 0x1_0000)))
}

fn env(spec: TempoHardfork) -> Env {
    Env {
        cfg_env: CfgEnv::new_with_spec_and_gas_params(
            spec,
            tempo_revm::gas_params::tempo_gas_params(spec),
        ),
        block_env: TempoBlockEnv {
            inner: revm::context::BlockEnv {
                basefee: 0,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            ..Default::default()
        },
    }
}

fn relaxed(env: &Env) -> Env {
    let mut env = env.clone();
    env.cfg_env.disable_nonce_check = true;
    env.cfg_env.disable_balance_check = true;
    env
}

fn tx(index: u64) -> TempoTxEnv {
    TempoTxEnv {
        inner: TxEnv {
            caller: address(index),
            kind: TxKind::Call(address(900)),
            gas_limit: 1_000_000,
            data: U256::from(index).to_be_bytes::<32>().into(),
            ..Default::default()
        },
        execution_context: ExecutionContext::Transaction {
            tx_hash: B256::from(U256::from(index)),
        },
        ..Default::default()
    }
}

fn factory(
    env: &Env,
    transactions: &[TempoTxEnv],
) -> (TempoEvmFactory, Arc<EnginePrewarmingSession>) {
    let cache = EnginePrewarmingCache::default();
    let session = cache
        .begin(
            env.clone(),
            transactions.iter().map(|tx| {
                let ExecutionContext::Transaction { tx_hash } = tx.execution_context else {
                    unreachable!()
                };
                tx_hash
            }),
        )
        .unwrap();
    (
        TempoEvmFactory {
            engine_prewarming: Some(cache),
        },
        session,
    )
}

fn contract(code: &'static [u8]) -> TestDB {
    let mut db = TestDB::default();
    db.insert_account_info(
        address(900),
        AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(code))),
    );
    db
}

fn root(db: &TestDB) -> B256 {
    state_root_unhashed(db.cache.accounts.iter().filter_map(|(address, account)| {
        account.info().map(|info| {
            (
                *address,
                TrieAccount {
                    nonce: info.nonce,
                    balance: info.balance,
                    code_hash: info.code_hash,
                    storage_root: storage_root_unhashed(
                        account
                            .storage
                            .iter()
                            .filter(|(_, value)| !value.is_zero())
                            .map(|(slot, value)| (B256::from(*slot), *value)),
                    ),
                },
            )
        })
    }))
}

fn ordered(factory: &TempoEvmFactory, db: TestDB, env: Env) -> TempoEvm<TestDB> {
    let mut evm = factory.create_evm(db, env);
    evm.set_speculative_executor(Some(SpeculativeExecutor::new(1, 128).unwrap()));
    assert!(evm.has_engine_prewarming());
    evm
}

#[test]
fn captured_results_match_sequential_outcomes_and_roots() {
    // Store one in a distinct calldata-selected slot for each transaction.
    let db = contract(&[0x60, 1, 0x60, 0, 0x35, 0x55, 0]);
    let env = env(TempoHardfork::T0);
    let transactions = (0..8).map(tx).collect::<Vec<_>>();
    let (factory, _) = factory(&env, &transactions);
    let mut worker = factory.create_evm(db.clone(), relaxed(&env));
    let parent_root = root(&db);
    for tx in &transactions {
        worker.transact_raw(tx.clone()).unwrap();
    }
    assert_eq!(
        root(worker.db()),
        parent_root,
        "capture must never commit parent writes"
    );
    let mut canonical = TempoEvm::new(db.clone(), env.clone());
    let mut actual = ordered(&factory, db, env);
    for tx in transactions {
        let expected = canonical.transact_raw(tx.clone()).unwrap();
        let result = actual.transact_raw(tx).unwrap();
        assert_eq!(result, expected);
        canonical.db_mut().commit(expected.state);
        actual.db_mut().commit(result.state);
    }
    assert_eq!(actual.execution_stats().reused, 8);
    assert_eq!(actual.execution_stats().conflicts, 0);
    assert_eq!(root(actual.db()), root(canonical.db()));
}

#[test]
fn changed_reads_replay_after_engine_capture() {
    // Increment slot zero: the second candidate must replay after the first commit.
    let db = contract(&[0x60, 0, 0x54, 0x60, 1, 0x01, 0x60, 0, 0x55, 0]);
    let env = env(TempoHardfork::T0);
    let transactions = [tx(0), tx(1)];
    let (factory, _) = factory(&env, &transactions);
    let mut worker = factory.create_evm(db.clone(), relaxed(&env));
    for tx in &transactions {
        worker.transact_raw(tx.clone()).unwrap();
    }
    let mut canonical = TempoEvm::new(db.clone(), env.clone());
    let mut actual = ordered(&factory, db, env);
    for tx in transactions {
        let expected = canonical.transact_raw(tx.clone()).unwrap();
        let result = actual.transact_raw(tx).unwrap();
        assert_eq!(result, expected);
        canonical.db_mut().commit(expected.state);
        actual.db_mut().commit(result.state);
    }
    assert_eq!(actual.execution_stats().reused, 1);
    assert_eq!(actual.execution_stats().storage_conflicts, 1);
    assert_eq!(root(actual.db()), root(canonical.db()));
}

#[test]
fn strict_failure_preserves_relaxed_fallback_and_canonical_error() {
    let env = env(TempoHardfork::T0);
    let mut tx = tx(0);
    tx.inner.nonce = 7;
    let (factory, session) = factory(&env, std::slice::from_ref(&tx));
    let mut worker = factory.create_evm(TestDB::default(), relaxed(&env));
    let mut legacy = TempoEvm::new(TestDB::default(), relaxed(&env));
    assert_eq!(
        worker.transact_raw(tx.clone()).unwrap(),
        legacy.transact_raw(tx.clone()).unwrap()
    );
    assert!(session.take(&tx).is_none());
    let mut canonical = TempoEvm::new(TestDB::default(), env.clone());
    let mut actual = ordered(&factory, TestDB::default(), env);
    assert_eq!(
        actual.transact_raw(tx.clone()).unwrap_err().to_string(),
        canonical.transact_raw(tx).unwrap_err().to_string()
    );
    assert_eq!(actual.execution_stats().reused, 0);
}

#[test]
fn canonical_miss_does_not_accept_late_capture() {
    let env = env(TempoHardfork::T0);
    let tx = tx(0);
    let (factory, session) = factory(&env, std::slice::from_ref(&tx));
    let mut actual = ordered(&factory, TestDB::default(), env.clone());
    actual.transact_raw(tx.clone()).unwrap();
    let mut worker = factory.create_evm(TestDB::default(), relaxed(&env));
    worker.transact_raw(tx.clone()).unwrap();
    assert!(session.take(&tx).is_none());
    assert_eq!(actual.execution_stats().reused, 0);
}

#[test]
fn unmarked_simulation_system_and_txpool_paths_do_not_capture() {
    for excluded in ["unmarked", "simulation", "system", "txpool"] {
        let env = env(TempoHardfork::T0);
        let mut tx = tx(0);
        let (mut factory, session) = factory(&env, std::slice::from_ref(&tx));
        let mut worker_env = relaxed(&env);
        match excluded {
            "unmarked" => factory = TempoEvmFactory::default(),
            "simulation" => tx.execution_context = ExecutionContext::Simulation,
            "system" => tx.is_system_tx = true,
            "txpool" => worker_env.cfg_env.disable_base_fee = true,
            _ => unreachable!(),
        }
        let mut worker = factory.create_evm(TestDB::default(), worker_env.clone());
        let mut legacy = TempoEvm::new(TestDB::default(), worker_env);
        assert_eq!(
            worker.transact_raw(tx.clone()).unwrap(),
            legacy.transact_raw(tx.clone()).unwrap(),
            "{excluded}"
        );
        assert!(session.take(&tx).is_none(), "{excluded}");
    }
}

#[test]
fn inspector_paths_do_not_capture() {
    for attach_after_construction in [false, true] {
        let env = env(TempoHardfork::T0);
        let tx = tx(0);
        let (factory, session) = factory(&env, std::slice::from_ref(&tx));
        let mut worker = if attach_after_construction {
            factory
                .create_evm(TestDB::default(), relaxed(&env))
                .with_inspector(NoOpInspector)
        } else {
            factory.create_evm_with_inspector(TestDB::default(), relaxed(&env), NoOpInspector)
        };
        let mut legacy =
            TempoEvm::new(TestDB::default(), relaxed(&env)).with_inspector(NoOpInspector);
        assert!(!worker.has_engine_prewarming());
        assert_eq!(
            worker.transact_raw(tx.clone()).unwrap(),
            legacy.transact_raw(tx.clone()).unwrap()
        );
        assert!(session.take(&tx).is_none());
    }
}

#[test]
fn modified_execution_configuration_and_journal_do_not_capture() {
    for excluded in [
        "cfg",
        "block",
        "precompiles",
        "inner",
        "actions",
        "state",
        "transient",
        "logs",
    ] {
        let env = env(TempoHardfork::T0);
        let tx = tx(0);
        let (factory, session) = factory(&env, std::slice::from_ref(&tx));
        let mut worker = factory.create_evm(TestDB::default(), relaxed(&env));
        let mut legacy = TempoEvm::new(TestDB::default(), relaxed(&env));
        if excluded == "actions" {
            worker = worker.with_actions();
            legacy = legacy.with_actions();
        } else {
            for evm in [&mut worker, &mut legacy] {
                match excluded {
                    "cfg" => evm.ctx_mut().cfg.disable_nonce_check = false,
                    "block" => evm.ctx_mut().block.inner.number += U256::ONE,
                    "precompiles" => {
                        let _ = evm.precompiles_mut();
                    }
                    "inner" => {
                        let _ = evm.inner_mut();
                    }
                    "state" => {
                        evm.ctx_mut()
                            .journaled_state
                            .state
                            .insert(address(1000), AccountInfo::default().into());
                    }
                    "transient" => {
                        evm.ctx_mut()
                            .journaled_state
                            .transient_storage
                            .entry(address(1000))
                            .or_default()
                            .insert(U256::ZERO, U256::ONE);
                    }
                    "logs" => evm.ctx_mut().journaled_state.logs.push(Default::default()),
                    _ => unreachable!(),
                }
            }
        }
        assert_eq!(
            worker.transact_raw(tx.clone()).unwrap(),
            legacy.transact_raw(tx.clone()).unwrap(),
            "{excluded}"
        );
        assert!(session.take(&tx).is_none(), "{excluded}");
        if excluded == "actions" {
            assert_eq!(worker.take_actions(), legacy.take_actions());
        }
    }
}

#[test]
fn creating_a_block_executor_disarms_relaxed_capture() {
    let env = env(TempoHardfork::T0);
    let tx = tx(0);
    let (factory, session) = factory(&env, std::slice::from_ref(&tx));
    let worker = factory.create_evm(TestDB::default(), relaxed(&env));
    let config = TempoEvmConfig::new(crate::test_utils::test_chainspec())
        .with_speculative_executor(SpeculativeExecutor::new(1, 128).unwrap());
    let ctx = TempoBlockExecutionCtx {
        transactions: &[],
        senders: &[],
        inner: alloy_evm::eth::EthBlockExecutionCtx {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: None,
            ommers: &[],
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: None,
            slot_number: None,
        },
        general_gas_limit: 30_000_000,
        shared_gas_limit: 0,
        consensus_context: None,
    };
    let mut executor = config.create_executor(worker, ctx);
    assert!(!executor.evm_mut().has_engine_prewarming());
    let mut legacy = TempoEvm::new(TestDB::default(), relaxed(&env));
    assert_eq!(
        executor.evm_mut().transact_raw(tx.clone()).unwrap(),
        legacy.transact_raw(tx.clone()).unwrap()
    );
    assert!(session.take(&tx).is_none());
}

#[test]
fn expiring_aa_offsets_are_applied_once_and_candidates_remain_canonical() {
    let caller = address(0);
    let mut setup = crate::test_utils::test_evm_with_basefee(TestDB::default(), 0);
    StorageCtx::enter_ctx(setup.ctx_mut(), StorageActions::disabled(), || {
        let mut setup = TIP20Setup::path_usd(address(999)).with_issuer(address(999));
        for i in 0..3 {
            setup = setup.with_mint(address(i), U256::from(1_000_000_000u64));
        }
        setup.apply().unwrap();
    });
    let state = setup.ctx_mut().journaled_state.finalize();
    setup.db_mut().commit(state);
    let mut db = setup.finish().0;
    for address in [NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS] {
        db.insert_account_info(
            address,
            AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[0]))),
        );
    }
    assert!(db.basic(caller).unwrap().is_none());
    let transactions = (0..3)
        .map(|index| {
            let signed = TempoTransaction {
                chain_id: 1,
                gas_limit: 1_000_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 1,
                fee_token: Some(PATH_USD_ADDRESS),
                nonce_key: U256::MAX,
                valid_before: std::num::NonZeroU64::new(25),
                calls: vec![Call {
                    to: PATH_USD_ADDRESS.into(),
                    value: U256::ZERO,
                    input: ITIP20::transferCall {
                        to: address(100 + index),
                        amount: U256::from(index + 1),
                    }
                    .abi_encode()
                    .into(),
                }],
                ..Default::default()
            }
            .into_signed(TempoSignature::default());
            TempoTxEnv::from_recovered_tx(&signed, address(index))
        })
        .collect::<Vec<_>>();
    let env = env(TempoHardfork::T14);
    let (factory, _) = factory(&env, &transactions);
    let mut worker = factory.create_evm(db.clone(), relaxed(&env));
    for (index, tx) in transactions.iter().enumerate() {
        let mut prewarm_tx = tx.clone();
        prewarm_tx.tempo_tx_env.as_mut().unwrap().expiring_nonce_idx = Some(index);
        worker.transact_raw(prewarm_tx).unwrap();
    }
    let mut canonical = TempoEvm::new(db.clone(), env.clone());
    let mut actual = ordered(&factory, db, env);
    for tx in transactions {
        let expected = canonical.transact_raw(tx.clone()).unwrap();
        let result = actual.transact_raw(tx).unwrap();
        assert_eq!(result, expected);
        canonical.db_mut().commit(expected.state);
        actual.db_mut().commit(result.state);
    }
    assert_eq!(actual.execution_stats().reused, 3);
    assert!(actual.execution_stats().fees_rebased > 0);
    assert_eq!(root(actual.db()), root(canonical.db()));
}

fn block_context() -> TempoBlockExecutionCtx<'static> {
    TempoBlockExecutionCtx {
        transactions: &[],
        senders: &[],
        inner: alloy_evm::eth::EthBlockExecutionCtx {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: None,
            ommers: &[],
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: None,
            slot_number: None,
        },
        general_gas_limit: 30_000_000,
        shared_gas_limit: 0,
        consensus_context: None,
    }
}

fn legacy_transaction(nonce: u64) -> Recovered<TempoTxEnvelope> {
    Recovered::new_unchecked(
        TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                nonce,
                gas_limit: 1_000_000,
                to: address(900).into(),
                ..Default::default()
            },
            Signature::test_signature(),
        )),
        address(0),
    )
}

#[test]
fn only_block_commits_publish_engine_prefix_after_misses_and_discarded_results() {
    let env = env(TempoHardfork::T0);
    // Every accepted transaction changes both the sender nonce and shared storage.
    let db = contract(&[0x60, 0, 0x54, 0x60, 1, 0x01, 0x60, 0, 0x55, 0]);
    let recovered = (0..3).map(legacy_transaction).collect::<Vec<_>>();
    let transactions = recovered
        .iter()
        .map(|tx| TempoTxEnv::from_recovered_tx(tx.inner(), tx.signer()))
        .collect::<Vec<_>>();
    for capture_first in [false, true] {
        let (factory, session) = factory(&env, &transactions);
        let config = TempoEvmConfig::new(crate::test_utils::test_chainspec())
            .with_speculative_executor(SpeculativeExecutor::new(1, 128).unwrap());
        let mut actual =
            config.create_executor(factory.create_evm(db.clone(), env.clone()), block_context());
        let mut canonical =
            config.create_executor(TempoEvm::new(db.clone(), env.clone()), block_context());
        let mut worker = factory.create_evm(db.clone(), relaxed(&env));
        if capture_first {
            worker.transact_raw(transactions[0].clone()).unwrap();
        }
        // A capture is a proof hint only. It cannot make the next nonce valid.
        worker.transact_raw(transactions[1].clone()).unwrap();
        assert!(!session.retained.lock().unwrap().results.contains_key(&1));
        let discarded = actual
            .execute_transaction_without_commit(&recovered[0])
            .unwrap();
        assert!(discarded.result().result.is_success());
        drop(discarded);
        // Executing an output without committing it must not publish its nonce
        // or storage either, even when that output came from a reusable capture.
        worker.transact_raw(transactions[1].clone()).unwrap();
        assert!(!session.retained.lock().unwrap().results.contains_key(&1));
        for (index, tx) in recovered.iter().enumerate() {
            if index > 0 {
                // A fresh parent-owned provider must see the shared session hints.
                worker = factory.create_evm(db.clone(), relaxed(&env));
                worker.transact_raw(transactions[index].clone()).unwrap();
                assert!(
                    session
                        .retained
                        .lock()
                        .unwrap()
                        .results
                        .contains_key(&index)
                );
            }
            let expected = canonical.execute_transaction_without_commit(tx).unwrap();
            let output = actual.execute_transaction_without_commit(tx).unwrap();
            assert_eq!(output.result(), expected.result());
            canonical.commit_transaction(expected);
            actual.commit_transaction(output);
        }
        assert_eq!(actual.evm().execution_stats().conflicts, 0);
        assert_eq!(
            actual.evm().execution_stats().reused,
            2 + u64::from(capture_first)
        );
        assert_eq!(actual.receipts(), canonical.receipts());
        assert_eq!(root(actual.evm().db()), root(canonical.evm().db()));
        assert_eq!(
            root(worker.db()),
            root(&db),
            "workers never commit the prefix"
        );
    }
}

#[test]
fn engine_prefix_publication_honors_execution_guards() {
    let env = env(TempoHardfork::T0);
    let db = contract(&[0]);
    let recovered = [legacy_transaction(0), legacy_transaction(1)];
    let transactions = recovered
        .iter()
        .map(|tx| TempoTxEnv::from_recovered_tx(tx.inner(), tx.signer()))
        .collect::<Vec<_>>();
    for excluded in [
        "capture",
        "inspector",
        "custom",
        "actions",
        "cfg",
        "block",
        "journal",
    ] {
        let (factory, session) = factory(&env, &transactions);
        let config = TempoEvmConfig::new(crate::test_utils::test_chainspec())
            .with_speculative_executor(SpeculativeExecutor::new(1, 128).unwrap());
        let mut evm = factory.create_evm(
            db.clone(),
            if excluded == "capture" {
                relaxed(&env)
            } else {
                env.clone()
            },
        );
        if excluded == "actions" {
            evm = evm.with_actions();
        }
        let mut actual = config.create_executor(evm, block_context());
        let output = actual
            .execute_transaction_without_commit(&recovered[0])
            .unwrap();
        match excluded {
            "inspector" => actual.evm_mut().set_inspector_enabled(true),
            "custom" => {
                let _ = actual.evm_mut().inner_mut();
            }
            "cfg" => actual.evm_mut().ctx_mut().cfg.disable_fee_charge = true,
            "block" => actual.evm_mut().ctx_mut().block.inner.beneficiary = address(800),
            "journal" => {
                actual
                    .evm_mut()
                    .ctx_mut()
                    .journaled_state
                    .state
                    .insert(address(801), revm::state::Account::default());
            }
            _ => {}
        }
        actual.commit_transaction(output);
        let mut worker = factory.create_evm(db.clone(), relaxed(&env));
        worker.transact_raw(transactions[1].clone()).unwrap();
        assert!(
            !session.retained.lock().unwrap().results.contains_key(&1),
            "{excluded} must not publish the committed sender nonce"
        );
    }
}

#[test]
fn committed_engine_prefix_preserves_parent_relative_expiring_offsets() {
    let spec = TempoHardfork::T14;
    let caller = address(0);
    let mut setup = crate::test_utils::test_evm_with_basefee(TestDB::default(), 0);
    StorageCtx::enter_ctx(setup.ctx_mut(), StorageActions::disabled(), || {
        TIP20Setup::path_usd(address(999))
            .with_issuer(address(999))
            .with_mint(caller, U256::from(1_000_000_000u64))
            .apply()
            .unwrap();
    });
    let state = setup.ctx_mut().journaled_state.finalize();
    setup.db_mut().commit(state);
    let mut db = setup.finish().0;
    for &(address, activation) in tempo_precompiles::SYSTEM_PRECOMPILES {
        if spec >= activation {
            db.insert_account_info(
                address,
                AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[0xef]))),
            );
        }
    }
    // Keep the fixture's CacheDB account lifecycle identical to revm State for
    // this focused pointer test; node tests cover empty AA caller deletion.
    db.insert_account_info(
        caller,
        AccountInfo {
            nonce: 1,
            ..Default::default()
        },
    );
    let parent_ptr = spec.expiring_nonce_set_capacity() - 2;
    db.insert_account_storage(
        NONCE_PRECOMPILE_ADDRESS,
        crate::parallel::nonce_slots::EXPIRING_NONCE_RING_PTR,
        U256::from(parent_ptr),
    )
    .unwrap();
    let recovered = (0..5)
        .map(|index| {
            let signed = TempoTransaction {
                chain_id: 1,
                gas_limit: 1_000_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 1,
                fee_token: Some(PATH_USD_ADDRESS),
                nonce: index,
                nonce_key: U256::MAX,
                valid_before: std::num::NonZeroU64::new(25),
                calls: vec![Call {
                    to: PATH_USD_ADDRESS.into(),
                    value: U256::ZERO,
                    input: ITIP20::transferCall {
                        to: address(100),
                        amount: U256::from(index + 1),
                    }
                    .abi_encode()
                    .into(),
                }],
                ..Default::default()
            }
            .into_signed(TempoSignature::default());
            Recovered::new_unchecked(TempoTxEnvelope::AA(signed), caller)
        })
        .collect::<Vec<_>>();
    let transactions = recovered
        .iter()
        .map(|tx| TempoTxEnv::from_recovered_tx(tx.inner(), tx.signer()))
        .collect::<Vec<_>>();
    let env = env(spec);
    let (factory, session) = factory(&env, &transactions);
    let config = TempoEvmConfig::new(crate::test_utils::test_chainspec())
        .with_speculative_executor(SpeculativeExecutor::new(1, 128).unwrap());
    let mut actual =
        config.create_executor(factory.create_evm(db.clone(), env.clone()), block_context());
    let mut canonical =
        config.create_executor(TempoEvm::new(db.clone(), env.clone()), block_context());
    let mut worker = factory.create_evm(db.clone(), relaxed(&env));
    for (index, tx) in recovered.iter().enumerate() {
        let mut prewarm = transactions[index].clone();
        prewarm.tempo_tx_env.as_mut().unwrap().expiring_nonce_idx = Some(index);
        worker.transact_raw(prewarm).unwrap();
        assert!(
            session
                .retained
                .lock()
                .unwrap()
                .results
                .contains_key(&index)
        );
        let expected = canonical.execute_transaction_without_commit(tx).unwrap();
        let output = actual.execute_transaction_without_commit(tx).unwrap();
        assert_eq!(output.result(), expected.result());
        canonical.commit_transaction(expected);
        actual.commit_transaction(output);
    }
    assert_eq!(actual.evm().execution_stats().reused, 5);
    assert_eq!(actual.evm().execution_stats().conflicts, 0);
    assert_eq!(actual.receipts(), canonical.receipts());
    assert_eq!(root(actual.evm().db()), root(canonical.evm().db()));
    assert_eq!(
        worker
            .db_mut()
            .storage(
                NONCE_PRECOMPILE_ADDRESS,
                crate::parallel::nonce_slots::EXPIRING_NONCE_RING_PTR
            )
            .unwrap(),
        U256::from(parent_ptr),
    );
}

#[test]
fn typed_state_executors_preserve_reused_outputs_and_bal_builder() {
    use revm::{database::State, state::bal::Bal};

    let env = env(TempoHardfork::T0);
    let parent = contract(&[0x60, 0, 0x54, 0x60, 1, 0x01, 0x60, 0, 0x55, 0]);
    let recovered = (0..3).map(legacy_transaction).collect::<Vec<_>>();
    let transactions = recovered
        .iter()
        .map(|tx| TempoTxEnv::from_recovered_tx(tx.inner(), tx.signer()))
        .collect::<Vec<_>>();
    let config = TempoEvmConfig::new(crate::test_utils::test_chainspec())
        .with_speculative_executor(SpeculativeExecutor::new(1, 128).unwrap());
    let context = block_context();
    for short_borrow in [false, true] {
        for build_bal in [false, true] {
            let (factory, _) = factory(&env, &transactions);
            let mut expected_state = State::builder().with_database(parent.clone()).build();
            let mut actual_state = State::builder().with_database(parent.clone()).build();
            if build_bal {
                expected_state.bal_state.bal_builder = Some(Bal::new());
                actual_state.bal_state.bal_builder = Some(Bal::new());
            }
            // Both typed hooks must preserve generic executor semantics. The
            // context and config outlive these successive State borrows.
            let evm = factory.create_evm(&mut actual_state, env.clone());
            let mut actual = if short_borrow {
                reth_evm::ConfigureEvm::create_executor_with_state(&config, evm, context.clone())
            } else {
                reth_evm::ConfigureEvm::create_executor(&config, evm, context.clone())
            };
            let mut expected = BlockExecutorFactory::create_executor(
                &config,
                TempoEvm::new(&mut expected_state, env.clone()),
                context.clone(),
            );
            let mut worker = factory.create_evm(parent.clone(), relaxed(&env));
            for (index, tx) in recovered.iter().enumerate() {
                worker.transact_raw(transactions[index].clone()).unwrap();
                actual.evm_mut().db_mut().bump_bal_index();
                expected.evm_mut().db_mut().bump_bal_index();
                let expected_output = expected.execute_transaction_without_commit(tx).unwrap();
                let actual_output = actual.execute_transaction_without_commit(tx).unwrap();
                assert_eq!(actual_output.result(), expected_output.result());
                actual.commit_transaction(actual_output);
                expected.commit_transaction(expected_output);
            }
            assert_eq!(actual.evm().execution_stats().reused, 3);
            assert_eq!(actual.evm().execution_stats().conflicts, 0);
            assert_eq!(actual.receipts(), expected.receipts());
            assert_eq!(actual.evm().db().cache, expected.evm().db().cache);
            assert_eq!(
                actual.evm().db().bal_state.bal_builder,
                expected.evm().db().bal_state.bal_builder,
                "read validation must preserve the complete generated BAL"
            );
        }
    }
}

#[test]
fn typed_state_executors_honor_bal_attached_after_construction() {
    use revm::{database::State, state::bal::Bal};

    let env = env(TempoHardfork::T0);
    let parent = contract(&[0x60, 0, 0x54, 0]);
    let tx = legacy_transaction(0);
    let tx_env = TempoTxEnv::from_recovered_tx(tx.inner(), tx.signer());
    let config = TempoEvmConfig::new(crate::test_utils::test_chainspec())
        .with_speculative_executor(SpeculativeExecutor::new(1, 128).unwrap());
    for short_borrow in [false, true] {
        let mut actual_state = State::builder().with_database(parent.clone()).build();
        let mut expected_state = State::builder().with_database(parent.clone()).build();
        for state in [&mut actual_state, &mut expected_state] {
            state.basic(address(0)).unwrap();
            state.basic(address(900)).unwrap();
            state.storage(address(900), U256::ZERO).unwrap();
        }
        let evm = TempoEvm::new(&mut actual_state, env.clone());
        let mut actual = if short_borrow {
            reth_evm::ConfigureEvm::create_executor_with_state(&config, evm, block_context())
        } else {
            reth_evm::ConfigureEvm::create_executor(&config, evm, block_context())
        };
        let mut expected = BlockExecutorFactory::create_executor(
            &config,
            TempoEvm::new(&mut expected_state, env.clone()),
            block_context(),
        );
        let candidate = crate::parallel::PrewarmingExecutor::new(parent.clone(), env.clone())
            .execute(tx_env.clone(), None)
            .unwrap();
        actual.evm_mut().set_preexecuted_transaction(candidate);
        for state in [actual.evm_mut().db_mut(), expected.evm_mut().db_mut()] {
            state.set_bal(Some(Arc::new(Bal::new())));
            state.bump_bal_index();
        }
        // An empty received BAL cannot be bypassed by values already warmed in
        // State, even when the BAL was attached after installing the validator.
        let actual_error = actual.execute_transaction_without_commit(&tx).unwrap_err();
        let expected_error = expected
            .execute_transaction_without_commit(&tx)
            .unwrap_err();
        assert_eq!(actual_error.to_string(), expected_error.to_string());
        assert_eq!(actual.evm().execution_stats().reused, 0);
        assert!(actual.receipts().is_empty());
    }
}
