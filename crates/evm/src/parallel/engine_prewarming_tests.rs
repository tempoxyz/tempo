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
    factory_with_diagnostics(env, transactions, false)
}

fn factory_with_diagnostics(
    env: &Env,
    transactions: &[TempoTxEnv],
    diagnostics: bool,
) -> (TempoEvmFactory, Arc<EnginePrewarmingSession>) {
    factory_with_window(
        env,
        transactions,
        diagnostics,
        EngineCaptureWindow::default(),
    )
}

fn factory_with_window(
    env: &Env,
    transactions: &[TempoTxEnv],
    diagnostics: bool,
    window: EngineCaptureWindow,
) -> (TempoEvmFactory, Arc<EnginePrewarmingSession>) {
    let cache = EnginePrewarmingCache::new(diagnostics).with_window(window);
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
fn capture_diagnostics_classify_strict_outcomes_and_short_circuit_guards() {
    for enabled in [false, true] {
        for outcome in ["success", "strict_failure", "guard", "journal"] {
            let env = env(TempoHardfork::T0);
            let mut transaction = tx(0);
            if outcome == "strict_failure" {
                transaction.inner.nonce = 7;
            }
            let (factory, session) =
                factory_with_diagnostics(&env, std::slice::from_ref(&transaction), enabled);
            let mut worker = factory.create_evm(TestDB::default(), relaxed(&env));
            let mut legacy = TempoEvm::new(TestDB::default(), relaxed(&env));
            for evm in [&mut worker, &mut legacy] {
                if outcome == "guard" {
                    evm.ctx_mut().block.inner.number += U256::ONE;
                } else if outcome == "journal" {
                    let mut access_list = alloy_primitives::map::AddressMap::default();
                    access_list.insert(address(1000), [U256::ZERO].into_iter().collect());
                    evm.ctx_mut().journaled_state.warm_access_list(access_list);
                }
            }
            assert_eq!(
                worker.transact_raw(transaction.clone()).unwrap(),
                legacy.transact_raw(transaction.clone()).unwrap(),
                "{outcome}"
            );
            assert_eq!(session.take(&transaction).is_some(), outcome == "success");
            if let Some(diagnostics) = &session.diagnostics {
                let counts = diagnostics.snapshot();
                let count = |event: CaptureEvent| counts.0[event as usize];
                assert_eq!(count(CaptureEvent::WorkerEntries), 1);
                assert_eq!(count(CaptureEvent::WorkerFinished), 1);
                assert_eq!(count(CaptureEvent::WorkerUnwound), 0);
                assert_eq!(
                    count(CaptureEvent::GuardRejected),
                    u64::from(outcome == "guard")
                );
                assert_eq!(
                    count(CaptureEvent::AdmissionInWindow),
                    u64::from(outcome != "guard")
                );
                assert_eq!(
                    count(CaptureEvent::JournalRejected),
                    u64::from(outcome == "journal")
                );
                assert_eq!(
                    count(CaptureEvent::StrictAttempts),
                    u64::from(matches!(outcome, "success" | "strict_failure"))
                );
                assert_eq!(
                    count(CaptureEvent::StrictSucceeded),
                    u64::from(outcome == "success")
                );
                assert_eq!(
                    count(CaptureEvent::StrictFailed),
                    u64::from(outcome == "strict_failure")
                );
                assert_eq!(
                    count(CaptureEvent::PublishAttempts),
                    u64::from(outcome == "success")
                );
                assert_eq!(
                    count(CaptureEvent::Published),
                    u64::from(outcome == "success")
                );
                assert_eq!(
                    count(CaptureEvent::WorkerEntries),
                    count(CaptureEvent::GuardRejected)
                        + count(CaptureEvent::AdmissionSystem)
                        + count(CaptureEvent::AdmissionUnindexed)
                        + count(CaptureEvent::AdmissionStale)
                        + count(CaptureEvent::AdmissionFuture)
                        + count(CaptureEvent::JournalRejected)
                        + count(CaptureEvent::StrictSucceeded)
                        + count(CaptureEvent::StrictFailed)
                );
                assert_eq!(
                    count(CaptureEvent::AdmissionInWindow),
                    count(CaptureEvent::JournalRejected) + count(CaptureEvent::StrictAttempts)
                );
                assert_eq!(
                    count(CaptureEvent::StrictAttempts),
                    count(CaptureEvent::StrictSucceeded) + count(CaptureEvent::StrictFailed)
                );
            } else {
                assert!(!enabled);
            }
        }
    }
}

#[test]
fn diagnostic_configuration_reaches_only_the_engine_cache() {
    for enabled in [false, true] {
        let executor = SpeculativeExecutor::new(1, 128).unwrap();
        assert!(!executor.capture_diagnostics());
        let original = TempoEvmConfig::moderato()
            .with_speculative_executor(executor.with_capture_diagnostics(enabled));
        let engine = original.clone().with_engine_prewarming();
        assert!(
            original
                .inner
                .executor_factory
                .evm_factory()
                .engine_prewarming
                .is_none()
        );
        let cache = engine
            .inner
            .executor_factory
            .evm_factory()
            .engine_prewarming
            .as_ref()
            .unwrap();
        assert_eq!(cache.capture_diagnostics, enabled);
        let payload_hash = B256::with_last_byte(42);
        let session = cache
            .begin_payload(env(TempoHardfork::T0), payload_hash, [B256::ZERO])
            .unwrap();
        assert_eq!(session.diagnostics.is_some(), enabled);
        if let Some(diagnostics) = &session.diagnostics {
            assert_eq!(diagnostics.payload_hash, payload_hash);
        }
    }
}

#[test]
fn selected_window_reaches_only_marked_engine_sessions() {
    assert!(
        TempoEvmConfig::moderato()
            .with_engine_prewarming()
            .inner
            .executor_factory
            .evm_factory()
            .engine_prewarming
            .is_none()
    );
    for window in [
        EngineCaptureWindow::Transactions128,
        EngineCaptureWindow::Transactions256,
        EngineCaptureWindow::Transactions512,
    ] {
        let pool = SpeculativeExecutor::new(1, 17).unwrap();
        assert_eq!(pool.capture_window(), EngineCaptureWindow::Transactions128);
        let pool = pool.with_capture_window(window);
        assert_eq!(pool.batch_size(), 17);
        let original = TempoEvmConfig::moderato().with_speculative_executor(pool);
        let engine = original.clone().with_engine_prewarming();
        assert!(
            original
                .inner
                .executor_factory
                .evm_factory()
                .engine_prewarming
                .is_none()
        );
        let cache = engine
            .inner
            .executor_factory
            .evm_factory()
            .engine_prewarming
            .as_ref()
            .unwrap();
        let session = cache.begin(env(TempoHardfork::T0), [B256::ZERO]).unwrap();
        assert_eq!(session.window, window);
        assert!(session.diagnostics.is_none());
    }
}

#[test]
fn selected_windows_reuse_strict_results_beyond_the_default_boundary() {
    for window in [
        EngineCaptureWindow::Transactions256,
        EngineCaptureWindow::Transactions512,
    ] {
        let db = contract(&[0x60, 1, 0x60, 0, 0x35, 0x55, 0]);
        let env = env(TempoHardfork::T0);
        let transactions = (0..520).map(tx).collect::<Vec<_>>();
        let (factory, _) = factory_with_window(&env, &transactions, false, window);
        let mut worker = factory.create_evm(db.clone(), relaxed(&env));
        let mut canonical = TempoEvm::new(db.clone(), env.clone());
        let mut actual = ordered(&factory, db.clone(), env);
        for chunk in transactions.chunks(window.transactions()) {
            for tx in chunk {
                worker.transact_raw(tx.clone()).unwrap();
            }
            for tx in chunk {
                let expected = canonical.transact_raw(tx.clone()).unwrap();
                let result = actual.transact_raw(tx.clone()).unwrap();
                assert_eq!(result, expected);
                canonical.db_mut().commit(expected.state);
                actual.db_mut().commit(result.state);
            }
        }
        assert_eq!(actual.execution_stats().reused, 520);
        assert_eq!(actual.execution_stats().conflicts, 0);
        assert_eq!(root(actual.db()), root(canonical.db()));
        assert_eq!(
            root(worker.db()),
            root(&db),
            "strict capture cannot commit parent state"
        );
    }
}

#[test]
fn warming_beyond_capture_window_does_not_create_strict_candidates() {
    // A wider dispatcher can warm these inputs once before they enter capture range.
    let db = contract(&[0x60, 1, 0x60, 0, 0x35, 0x55, 0]);
    let env = env(TempoHardfork::T0);
    let transactions = (0..520).map(tx).collect::<Vec<_>>();
    let (factory, session) = factory_with_diagnostics(&env, &transactions, true);
    let mut worker = factory.create_evm(db.clone(), relaxed(&env));
    let mut legacy = TempoEvm::new(db.clone(), relaxed(&env));
    for transaction in &transactions[127..512] {
        assert_eq!(
            worker.transact_raw(transaction.clone()).unwrap(),
            legacy.transact_raw(transaction.clone()).unwrap()
        );
    }
    let counts = session.diagnostics.as_ref().unwrap().snapshot();
    let count = |event: CaptureEvent| counts.0[event as usize];
    assert_eq!(count(CaptureEvent::WorkerEntries), 385);
    assert_eq!(count(CaptureEvent::WorkerFinished), 385);
    assert_eq!(count(CaptureEvent::AdmissionFuture), 384);
    assert_eq!(count(CaptureEvent::Future128To255), 128);
    assert_eq!(count(CaptureEvent::Future256To511), 256);
    assert_eq!(count(CaptureEvent::StrictAttempts), 1);
    assert_eq!(count(CaptureEvent::Published), 1);
    assert_eq!(root(worker.db()), root(&db));

    let mut canonical = TempoEvm::new(db.clone(), env.clone());
    let mut actual = ordered(&factory, db, env);
    for transaction in transactions {
        let expected = canonical.transact_raw(transaction.clone()).unwrap();
        let result = actual.transact_raw(transaction).unwrap();
        assert_eq!(result, expected);
        canonical.db_mut().commit(expected.state);
        actual.db_mut().commit(result.state);
    }
    assert_eq!(actual.execution_stats().speculated, 1);
    assert_eq!(actual.execution_stats().reused, 1);
    assert_eq!(root(actual.db()), root(canonical.db()));
    let final_counts = session.diagnostics.as_ref().unwrap().snapshot();
    assert_eq!(final_counts.0[CaptureEvent::StrictAttempts as usize], 1);
    assert_eq!(final_counts.0[CaptureEvent::WorkerEntries as usize], 385);
}

#[test]
fn enlarged_window_changed_reads_replay_against_the_ordered_prefix() {
    for window in [
        EngineCaptureWindow::Transactions256,
        EngineCaptureWindow::Transactions512,
    ] {
        let db = contract(&[0x60, 0, 0x54, 0x60, 1, 0x01, 0x60, 0, 0x55, 0]);
        let env = env(TempoHardfork::T0);
        let transactions = (0..520).map(tx).collect::<Vec<_>>();
        let (factory, _) = factory_with_window(&env, &transactions, false, window);
        let mut worker = factory.create_evm(db.clone(), relaxed(&env));
        worker
            .transact_raw(transactions[window.transactions() - 1].clone())
            .unwrap();
        let mut canonical = TempoEvm::new(db.clone(), env.clone());
        let mut actual = ordered(&factory, db, env);
        for tx in transactions {
            let expected = canonical.transact_raw(tx.clone()).unwrap();
            let result = actual.transact_raw(tx).unwrap();
            assert_eq!(result, expected);
            canonical.db_mut().commit(expected.state);
            actual.db_mut().commit(result.state);
        }
        assert_eq!(actual.execution_stats().speculated, 1);
        assert_eq!(actual.execution_stats().reused, 0);
        assert_eq!(actual.execution_stats().storage_conflicts, 1);
        assert_eq!(root(actual.db()), root(canonical.db()));
    }
}

#[test]
fn enlarged_window_validation_does_not_hide_provider_failure() {
    #[derive(Debug, thiserror::Error)]
    #[error("capture window test provider failure")]
    struct Unavailable;
    impl reth_revm::database_interface::DBErrorMarker for Unavailable {}
    #[derive(Debug)]
    struct FailingStorage(TestDB);
    impl Database for FailingStorage {
        type Error = Unavailable;
        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(self.0.basic(address).unwrap())
        }
        fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(self.0.code_by_hash(hash).unwrap())
        }
        fn storage(&mut self, _: Address, _: U256) -> Result<U256, Self::Error> {
            Err(Unavailable)
        }
        fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
            Ok(self.0.block_hash(number).unwrap())
        }
    }
    for window in [
        EngineCaptureWindow::Transactions256,
        EngineCaptureWindow::Transactions512,
    ] {
        let db = contract(&[0x60, 0, 0x54, 0]);
        let env = env(TempoHardfork::T0);
        let transactions = (0..520).map(tx).collect::<Vec<_>>();
        let (factory, _) = factory_with_window(&env, &transactions, false, window);
        let tx = transactions[window.transactions() - 1].clone();
        let mut worker = factory.create_evm(db.clone(), relaxed(&env));
        worker.transact_raw(tx.clone()).unwrap();
        let mut canonical = TempoEvm::new(FailingStorage(db.clone()), env.clone());
        let mut actual = factory.create_evm(FailingStorage(db), env);
        actual.set_speculative_executor(Some(SpeculativeExecutor::new(1, 128).unwrap()));
        assert_eq!(
            actual.transact_raw(tx.clone()).unwrap_err().to_string(),
            canonical.transact_raw(tx).unwrap_err().to_string()
        );
        assert_eq!(actual.execution_stats().speculated, 1);
        assert_eq!(actual.execution_stats().reused, 0);
        assert_eq!(actual.execution_stats().validation_errors, 1);
    }
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
        "warm_precompiles",
        "warm_access_list",
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
                    "warm_precompiles" => {
                        evm.ctx_mut()
                            .journaled_state
                            .warm_precompiles(&[address(1000)].into_iter().collect());
                    }
                    "warm_access_list" => {
                        let mut access_list = alloy_primitives::map::AddressMap::default();
                        access_list.insert(address(1000), [U256::ZERO].into_iter().collect());
                        evm.ctx_mut().journaled_state.warm_access_list(access_list);
                    }
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

#[test]
fn engine_handoff_preserves_certified_native_increment() {
    let (mut parent, env, tx, token, slot) =
        crate::parallel::tests::native_increment_tests::fixture();
    let (factory, _) = factory(&env, std::slice::from_ref(&tx));
    let mut worker = factory.create_evm(parent.clone(), relaxed(&env));
    let mut prewarm_tx = tx.clone();
    prewarm_tx.tempo_tx_env.as_mut().unwrap().expiring_nonce_idx = Some(0);
    let hint = worker.transact_raw(prewarm_tx).unwrap();
    assert!(hint.result.is_success());
    // A predecessor changed custody after the worker finished. The published
    // certificate must survive the Engine queue and ordered validation.
    parent
        .insert_account_storage(token, slot, U256::from(20))
        .unwrap();
    let mut expected = TempoEvm::new(parent.clone(), env.clone());
    let mut actual = ordered(&factory, parent, env);
    let expected_result = expected.transact_raw(tx.clone()).unwrap();
    let actual_result = actual.transact_raw(tx).unwrap();
    assert_eq!(actual_result, expected_result);
    assert_eq!(actual.validator_fee(), expected.validator_fee());
    assert_eq!(actual.execution_stats().reused, 1);
    assert_eq!(actual.execution_stats().native_rebased, 1);
    expected.db_mut().commit(expected_result.state);
    actual.db_mut().commit(actual_result.state);
    assert_eq!(root(actual.db()), root(expected.db()));
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

fn nonce_prefix_parent(spec: TempoHardfork) -> TestDB {
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
    db
}

fn nonce_prefix_transaction(
    nonce_key: U256,
    nonce: u64,
    amount: u64,
    signature: TempoSignature,
) -> Recovered<TempoTxEnvelope> {
    let signed = TempoTransaction {
        chain_id: 1,
        gas_limit: 1_000_000,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        fee_token: Some(PATH_USD_ADDRESS),
        nonce,
        nonce_key,
        valid_before: std::num::NonZeroU64::new(25),
        calls: vec![Call {
            to: PATH_USD_ADDRESS.into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: address(100),
                amount: U256::from(amount),
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    }
    .into_signed(signature);
    Recovered::new_unchecked(TempoTxEnvelope::AA(signed), address(0))
}

#[test]
fn committed_engine_prefix_preserves_parent_relative_expiring_offsets() {
    use tempo_precompiles::storage::StorageKey;

    let spec = TempoHardfork::T14;
    let parent_ptr = spec.expiring_nonce_set_capacity() - 2;
    let old_hash = B256::repeat_byte(0xf1);
    // Empty, occupied-but-expired, and occupied-live slot zero. The first two
    // accepted transactions wrap the pointer; the third must inspect that slot.
    for old_expiry in [None, Some(5), Some(15)] {
        let mut db = nonce_prefix_parent(spec);
        db.insert_account_storage(
            NONCE_PRECOMPILE_ADDRESS,
            crate::parallel::nonce_slots::EXPIRING_NONCE_RING_PTR,
            U256::from(parent_ptr),
        )
        .unwrap();
        if let Some(expiry) = old_expiry {
            for (slot, value) in [
                (
                    0u32.mapping_slot(crate::parallel::nonce_slots::EXPIRING_NONCE_RING),
                    U256::from_be_bytes(old_hash.0),
                ),
                (
                    old_hash.mapping_slot(crate::parallel::nonce_slots::EXPIRING_NONCE_SEEN),
                    U256::from(expiry),
                ),
            ] {
                db.insert_account_storage(NONCE_PRECOMPILE_ADDRESS, slot, value)
                    .unwrap();
            }
        }
        let recovered = (0..5)
            .map(|index| {
                nonce_prefix_transaction(U256::MAX, index, index + 1, TempoSignature::default())
            })
            .collect::<Vec<_>>();
        let transactions = recovered
            .iter()
            .map(|tx| TempoTxEnv::from_recovered_tx(tx.inner(), tx.signer()))
            .collect::<Vec<_>>();
        let mut env = env(spec);
        env.block_env.inner.timestamp = U256::from(10);
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
            let hint = worker.transact_raw(prewarm);
            let expected = canonical.execute_transaction_without_commit(tx);
            if old_expiry == Some(15) && index == 2 {
                assert!(
                    hint.is_err(),
                    "strict and relaxed workers must reject the full ring"
                );
                assert!(
                    !session
                        .retained
                        .lock()
                        .unwrap()
                        .results
                        .contains_key(&index)
                );
                let expected = expected.unwrap_err();
                let error = actual.execute_transaction_without_commit(tx).unwrap_err();
                assert_eq!(error.to_string(), expected.to_string());
                break;
            }
            assert!(hint.unwrap().result.is_success());
            assert!(
                session
                    .retained
                    .lock()
                    .unwrap()
                    .results
                    .contains_key(&index)
            );
            let expected = expected.unwrap();
            let output = actual.execute_transaction_without_commit(tx).unwrap();
            assert_eq!(output.result(), expected.result());
            canonical.commit_transaction(expected);
            actual.commit_transaction(output);
        }
        assert_eq!(
            actual.evm().execution_stats().reused,
            if old_expiry == Some(15) { 2 } else { 5 }
        );
        assert_eq!(actual.evm().execution_stats().conflicts, 0);
        assert_eq!(actual.receipts(), canonical.receipts());
        assert_eq!(root(actual.evm().db()), root(canonical.evm().db()));
        assert_eq!(
            root(worker.db()),
            root(&db),
            "workers never commit ring changes"
        );
        if old_expiry == Some(5) {
            assert_eq!(
                actual
                    .evm_mut()
                    .db_mut()
                    .storage(
                        NONCE_PRECOMPILE_ADDRESS,
                        old_hash.mapping_slot(crate::parallel::nonce_slots::EXPIRING_NONCE_SEEN)
                    )
                    .unwrap(),
                U256::ZERO
            );
        }
    }
}

#[test]
fn delayed_engine_nonce_outputs_preserve_keyed_hints_and_reject_expiring_replay() {
    use revm::database::State;
    use tempo_primitives::transaction::tt_signature::PrimitiveSignature;

    for typed_validation in [false, true] {
        // T0 treats MAX as an ordinary keyed nonce. Keep its hints too.
        for (spec, committed_expiring) in [
            (TempoHardfork::T14, false),
            (TempoHardfork::T14, true),
            (TempoHardfork::T0, false),
        ] {
            let db = nonce_prefix_parent(spec);
            let env = env(spec);
            let key = if committed_expiring || !spec.is_t1() {
                U256::MAX
            } else {
                U256::from(7)
            };
            let first = nonce_prefix_transaction(key, 0, 1, TempoSignature::default());
            let discarded = nonce_prefix_transaction(
                if committed_expiring || !spec.is_t1() {
                    U256::from(8)
                } else {
                    U256::MAX
                },
                0,
                2,
                TempoSignature::default(),
            );
            let next = if committed_expiring {
                // Different envelope signature/hash, identical sender-scoped
                // replay identifier. Duplicate envelope hashes disable capture.
                nonce_prefix_transaction(
                    key,
                    0,
                    1,
                    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::new(
                        U256::from(3),
                        U256::from(4),
                        true,
                    ))),
                )
            } else {
                nonce_prefix_transaction(key, 1, 3, TempoSignature::default())
            };
            let txs =
                [&first, &next].map(|tx| TempoTxEnv::from_recovered_tx(tx.inner(), tx.signer()));
            assert_ne!(txs[0].execution_context, txs[1].execution_context);
            if committed_expiring {
                assert_eq!(txs[0].unique_tx_identifier(), txs[1].unique_tx_identifier());
            }
            let (factory, session) = factory(&env, &txs);
            let config = TempoEvmConfig::new(crate::test_utils::test_chainspec())
                .with_speculative_executor(SpeculativeExecutor::new(1, 128).unwrap());
            let mut actual_state = State::builder().with_database(db.clone()).build();
            let mut expected_state = State::builder().with_database(db.clone()).build();
            let mut evm = factory.create_evm(&mut actual_state, env.clone());
            if typed_validation {
                evm.enable_state_cache_validation();
            }
            let mut actual = config.create_executor(evm, block_context());
            let mut canonical = config.create_executor(
                TempoEvm::new(&mut expected_state, env.clone()),
                block_context(),
            );
            let mut worker = factory.create_evm(db.clone(), relaxed(&env));
            let mut prewarm = txs[0].clone();
            if committed_expiring {
                prewarm.tempo_tx_env.as_mut().unwrap().expiring_nonce_idx = Some(0);
            }
            assert!(worker.transact_raw(prewarm).unwrap().result.is_success());
            assert!(session.retained.lock().unwrap().results.contains_key(&0));
            let expected = canonical
                .execute_transaction_without_commit(&first)
                .unwrap();
            let output = actual.execute_transaction_without_commit(&first).unwrap();
            assert_eq!(output.result(), expected.result());
            assert_eq!(actual.evm().execution_stats().reused, 1);

            // The latest ctx.tx now has the opposite nonce mode; neither of
            // these later outputs is committed. Clone the earlier output too.
            let expected_discarded = canonical
                .execute_transaction_without_commit(&discarded)
                .unwrap();
            let actual_discarded = actual
                .execute_transaction_without_commit(&discarded)
                .unwrap();
            assert_eq!(actual_discarded.result(), expected_discarded.result());
            drop((expected_discarded, actual_discarded));
            canonical.commit_transaction(expected);
            actual.commit_transaction(output.clone());
            drop(output);
            assert_eq!(actual.receipts(), canonical.receipts());

            // Capture AFTER the commit with a fresh parent-owned provider. An
            // expiring duplicate sees parent SEEN=0 because that hint was omitted;
            // keyed nonce1 must see the published ordinary keyed nonce update.
            let mut worker = factory.create_evm(db.clone(), relaxed(&env));
            let mut prewarm = txs[1].clone();
            if committed_expiring {
                prewarm.tempo_tx_env.as_mut().unwrap().expiring_nonce_idx = Some(1);
            }
            assert!(worker.transact_raw(prewarm).unwrap().result.is_success());
            assert!(session.retained.lock().unwrap().results.contains_key(&1));
            if committed_expiring {
                let expected = canonical
                    .execute_transaction_without_commit(&next)
                    .unwrap_err();
                let error = actual
                    .execute_transaction_without_commit(&next)
                    .unwrap_err();
                assert_eq!(error.to_string(), expected.to_string());
                assert_eq!(actual.evm().execution_stats().nonce_conflicts, 1);
                assert_eq!(actual.evm().execution_stats().reused, 1);
                assert_eq!(actual.receipts().len(), 1);
            } else {
                let expected = canonical.execute_transaction_without_commit(&next).unwrap();
                let output = actual.execute_transaction_without_commit(&next).unwrap();
                assert_eq!(output.result(), expected.result());
                canonical.commit_transaction(expected);
                actual.commit_transaction(output);
                assert_eq!(actual.evm().execution_stats().reused, 2);
                assert_eq!(actual.evm().execution_stats().conflicts, 0);
            }
            assert_eq!(actual.receipts(), canonical.receipts());
            assert_eq!(actual.evm().db().cache, canonical.evm().db().cache);
            assert_eq!(
                actual.evm().db().transition_state,
                canonical.evm().db().transition_state
            );
            assert_eq!(root(worker.db()), root(&db));
        }
    }
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
        for (build_bal, observe_state) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let (factory, _) = factory(&env, &transactions);
            let mut expected_state = State::builder().with_database(parent.clone()).build();
            let mut actual_state = State::builder().with_database(parent.clone()).build();
            if build_bal {
                expected_state.bal_state.bal_builder = Some(Bal::new());
                actual_state.bal_state.bal_builder = Some(Bal::new());
            }
            if observe_state {
                for state in [&mut expected_state, &mut actual_state] {
                    state.transition_state = Some(Default::default());
                    state.state_hook = Some(Box::new(|_: revm::state::EvmState| {}));
                }
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
                actual.evm().db().transition_state,
                expected.evm().db().transition_state
            );
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
