use super::*;
use alloy_primitives::{Bytes, TxKind};
use revm::{
    Database as _,
    context::{CfgEnv, TxEnv},
    database::{CacheDB, EmptyDB},
};

#[test]
fn prewarmed_results_preserve_components_after_context_configuration_changes() {
    let target = Address::with_last_byte(100);
    let caller = Address::with_last_byte(101);
    let mut db = CacheDB::<EmptyDB>::default();
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[
            0x60, 1, 0x60, 0, 0x55, 0,
        ]))),
    );
    let original_env = Env {
        cfg_env: CfgEnv::new_with_spec_and_gas_params(
            TempoHardfork::T0,
            tempo_revm::gas_params::tempo_gas_params(TempoHardfork::T0),
        ),
        block_env: TempoBlockEnv {
            inner: revm::context::BlockEnv {
                basefee: 0,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let mut changed_env = original_env.clone();
    changed_env.cfg_env = CfgEnv::new_with_spec_and_gas_params(
        TempoHardfork::T7,
        tempo_revm::gas_params::tempo_gas_params(TempoHardfork::T7),
    );
    let tx = TempoTxEnv {
        inner: TxEnv {
            caller,
            kind: TxKind::Call(target),
            gas_limit: 1_000_000,
            gas_price: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    for mutate_before_injection in [true, false] {
        let mut canonical = TempoEvm::new(db.clone(), original_env.clone());
        canonical.ctx_mut().cfg = changed_env.cfg_env.clone();
        let expected = canonical.transact_raw(tx.clone()).unwrap();
        // T7 installs an SSTORE storage-credit hook at construction. Merely
        // changing ctx.cfg on the original T0 EVM does not install that hook.
        let mut rebuilt = TempoEvm::new(db.clone(), changed_env.clone());
        assert_ne!(rebuilt.transact_raw(tx.clone()).unwrap(), expected);

        let mut recorder = PrewarmingExecutor::new(db.clone(), changed_env.clone());
        let candidate = recorder.execute(tx.clone(), None).unwrap();
        let mut parallel = TempoEvm::new(db.clone(), original_env.clone());
        let pool = SpeculativeExecutor::new(1, 1).unwrap();
        parallel.set_speculative_executor(Some(pool.clone()));
        if mutate_before_injection {
            parallel.ctx_mut().cfg = changed_env.cfg_env.clone();
        }
        parallel.set_preexecuted_transaction(candidate);
        parallel.ctx_mut().cfg = changed_env.cfg_env.clone();
        assert_eq!(parallel.transact_raw(tx.clone()).unwrap(), expected);
        assert_eq!(pool.prewarmed_reuses(), 0);
    }
}

type JournalGuardDB = CacheDB<EmptyDB>;

fn journal_guard_fixture(code: Bytes) -> (JournalGuardDB, Env, TempoTxEnv) {
    let target = Address::with_last_byte(100);
    let mut db = JournalGuardDB::default();
    db.insert_account_info(
        target,
        AccountInfo::default().with_code(Bytecode::new_raw(code)),
    );
    let env = Env {
        cfg_env: CfgEnv::new_with_spec_and_gas_params(
            TempoHardfork::T0,
            tempo_revm::gas_params::tempo_gas_params(TempoHardfork::T0),
        ),
        block_env: TempoBlockEnv {
            inner: revm::context::BlockEnv {
                basefee: 0,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let tx = TempoTxEnv {
        inner: TxEnv {
            caller: Address::with_last_byte(101),
            kind: TxKind::Call(target),
            gas_limit: 1_000_000,
            gas_price: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    (db, env, tx)
}

fn warm_balance_address(ctx: &mut tempo_revm::evm::TempoContext<JournalGuardDB>, address: Address) {
    let mut addresses = ctx.journaled_state.warm_addresses.precompiles().clone();
    addresses.insert(address);
    ctx.journaled_state
        .warm_addresses
        .set_precompile_addresses(&addresses);
}

fn balance_code(address: Address) -> Bytes {
    let mut code = vec![0x73]; // PUSH20 address; BALANCE; POP; STOP.
    code.extend_from_slice(address.as_slice());
    code.extend_from_slice(&[0x31, 0x50, 0x00]);
    code.into()
}

#[test]
fn custom_precompile_warming_invalidates_preexecuted_results_after_prior_reuse() {
    let address = Address::with_last_byte(102);
    let (db, env, tx) = journal_guard_fixture(balance_code(address));
    let mut worker = PrewarmingExecutor::new(db.clone(), env.clone());
    let cold = worker
        .execute(tx.clone(), None)
        .unwrap()
        .prewarming_result();
    let mut sequential = TempoEvm::new(db.clone(), env.clone());
    warm_balance_address(sequential.ctx_mut(), address);
    let expected = sequential.transact_raw(tx.clone()).unwrap();
    assert_ne!(cold.result.tx_gas_used(), expected.result.tx_gas_used());

    for prior_reuse in [false, true] {
        let mut parallel = TempoEvm::new(db.clone(), env.clone());
        parallel.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
        if prior_reuse {
            // Unchanged mutable access must permit ordinary reuse and clear the memo.
            let _ = parallel.ctx_mut();
            parallel.set_preexecuted_transaction(worker.execute(tx.clone(), None).unwrap());
            assert_eq!(parallel.transact_raw(tx.clone()).unwrap(), cold);
            assert_eq!(parallel.execution_stats().reused, 1);
        }
        parallel.set_preexecuted_transaction(worker.execute(tx.clone(), None).unwrap());
        warm_balance_address(parallel.ctx_mut(), address);
        assert_eq!(parallel.transact_raw(tx.clone()).unwrap(), expected);
        assert_eq!(parallel.execution_stats().reused, u64::from(prior_reuse));

        // The custom warm set persists across ordinary execution. A failed
        // check must not mark it standard for the following candidate.
        parallel.set_preexecuted_transaction(worker.execute(tx.clone(), None).unwrap());
        assert_eq!(parallel.transact_raw(tx.clone()).unwrap(), expected);
        assert_eq!(parallel.execution_stats().reused, u64::from(prior_reuse));
    }
}

#[test]
fn custom_legacy_access_list_preserves_sload_gas_and_full_result() {
    let (mut db, env, tx) = journal_guard_fixture(Bytes::from_static(&[
        0x60, 0x00, 0x54, 0x50, 0x00, // PUSH1 0; SLOAD; POP; STOP.
    ]));
    let target = Address::with_last_byte(100);
    db.insert_account_storage(target, U256::ZERO, U256::from(42))
        .unwrap();
    assert_eq!(tx.inner.tx_type, 0);
    let mut worker = PrewarmingExecutor::new(db.clone(), env.clone());
    let candidate = worker.execute(tx.clone(), None).unwrap();
    let cold_gas = candidate.prewarming_result().result.tx_gas_used();
    let mut sequential = TempoEvm::new(db.clone(), env.clone());
    let mut parallel = TempoEvm::new(db, env);
    parallel.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
    parallel.set_preexecuted_transaction(candidate);
    for evm in [&mut sequential, &mut parallel] {
        let mut access_list = alloy_primitives::map::AddressMap::default();
        access_list.insert(target, [U256::ZERO].into_iter().collect());
        // Exercise DerefMut as well as the explicit ctx_mut entry point.
        evm.journaled_state
            .warm_addresses
            .set_access_list(access_list);
    }
    let expected = sequential.transact_raw(tx.clone()).unwrap();
    assert_ne!(cold_gas, expected.result.tx_gas_used());
    assert_eq!(parallel.transact_raw(tx.clone()).unwrap(), expected);
    assert_eq!(parallel.execution_stats().reused, 0);

    // Legacy access-list warming is cleared by finalize; standard reuse recovers.
    parallel.set_preexecuted_transaction(worker.execute(tx.clone(), None).unwrap());
    assert_eq!(
        parallel.transact_raw(tx.clone()).unwrap(),
        sequential.transact_raw(tx).unwrap()
    );
    assert_eq!(parallel.execution_stats().reused, 1);
}

#[derive(Clone, Copy)]
struct WarmBalanceInspector(Address);

impl revm::Inspector<tempo_revm::evm::TempoContext<JournalGuardDB>> for WarmBalanceInspector {
    fn initialize_interp(
        &mut self,
        _interp: &mut revm::interpreter::Interpreter,
        context: &mut tempo_revm::evm::TempoContext<JournalGuardDB>,
    ) {
        warm_balance_address(context, self.0);
    }
}

#[test]
fn disabling_inspection_rechecks_persistent_journal_warming() {
    let address = Address::with_last_byte(102);
    let (db, env, tx) = journal_guard_fixture(balance_code(address));
    let mut worker = PrewarmingExecutor::new(db.clone(), env.clone());
    let cold_gas = worker
        .execute(tx.clone(), None)
        .unwrap()
        .prewarming_result()
        .result
        .tx_gas_used();
    let mut sequential =
        TempoEvm::new(db.clone(), env.clone()).with_inspector(WarmBalanceInspector(address));
    let mut parallel = TempoEvm::new(db, env).with_inspector(WarmBalanceInspector(address));
    parallel.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
    assert_eq!(
        parallel.transact_raw(tx.clone()).unwrap(),
        sequential.transact_raw(tx.clone()).unwrap()
    );
    assert_eq!(parallel.execution_stats().reused, 0);
    sequential.set_inspector_enabled(false);
    parallel.set_inspector_enabled(false);
    let expected = sequential.transact_raw(tx.clone()).unwrap();
    assert_ne!(cold_gas, expected.result.tx_gas_used());
    parallel.set_preexecuted_transaction(worker.execute(tx.clone(), None).unwrap());
    assert_eq!(parallel.transact_raw(tx).unwrap(), expected);
    assert_eq!(parallel.execution_stats().reused, 0);
}

fn check_changed_code_representation(inline: bool, cached: bool) {
    let target = Address::with_last_byte(100);
    let delegate = Address::with_last_byte(102);
    let delegation = Bytecode::new_eip7702(delegate);
    let legacy = Bytecode::new_legacy(delegation.original_bytes());
    // Byte equality and content hashes omit the execution kind.
    assert_eq!(legacy, delegation);
    assert_eq!(legacy.hash_slow(), delegation.hash_slow());
    assert_ne!(legacy.kind(), delegation.kind());
    for (before, after) in [(legacy.clone(), delegation.clone()), (delegation, legacy)] {
        let (mut db, env, tx) = journal_guard_fixture(Bytes::new());
        db.insert_account_info(
            delegate,
            AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[
                0x60, 1, 0x60, 0, 0x55, 0, // Store one in the authority's slot zero.
            ]))),
        );
        let install = |db: &mut JournalGuardDB, code: Bytecode| {
            let hash = code.hash_slow();
            let mut info = AccountInfo::default().with_code(code.clone());
            if !inline {
                info.code = None;
            }
            db.insert_account_info(target, info);
            db.cache.contracts.insert(hash, code);
        };
        install(&mut db, before);
        let candidate = PrewarmingExecutor::new(db.clone(), env.clone())
            .execute(tx.clone(), None)
            .unwrap();
        let old_result = candidate.prewarming_result();
        install(&mut db, after.clone());
        let expected = TempoEvm::new(db.clone(), env.clone())
            .transact_raw(tx.clone())
            .unwrap();
        assert_eq!(expected.result.is_success(), after.is_eip7702());
        assert_ne!(old_result.result, expected.result);

        let mut state = revm::database::State::builder().with_database(db).build();
        // Exercise borrowed warm-cache comparisons, not only cold DB fallback.
        state.basic(target).unwrap();
        state.code_by_hash(after.hash_slow()).unwrap();
        let mut parallel = TempoEvm::new(&mut state, env);
        if cached {
            parallel.enable_state_cache_validation();
        }
        parallel.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
        parallel.set_preexecuted_transaction(candidate);
        let actual = parallel.transact_raw(tx).unwrap();
        assert_eq!(actual, expected, "inline={inline}, cached={cached}");
        assert_eq!(parallel.execution_stats().reused, 0);
        assert_eq!(parallel.execution_stats().metadata_conflicts, 1);
    }
}

#[test]
fn changed_inline_code_representation_generic() {
    check_changed_code_representation(true, false);
}

#[test]
fn changed_inline_code_representation_cached() {
    check_changed_code_representation(true, true);
}

#[test]
fn changed_hashed_code_representation_generic() {
    check_changed_code_representation(false, false);
}

#[test]
fn changed_hashed_code_representation_cached() {
    check_changed_code_representation(false, true);
}

#[test]
fn empty_code_availability_preserves_state_hook_metadata() {
    use revm::DatabaseCommit as _;

    let observed = Address::with_last_byte(103);
    for cached in [false, true] {
        for worker_has_code in [false, true] {
            let (mut db, env, tx) = journal_guard_fixture(balance_code(observed));
            db.insert_account_info(
                observed,
                AccountInfo {
                    nonce: 1,
                    balance: U256::from(7),
                    code: worker_has_code.then(Bytecode::default),
                    ..Default::default()
                },
            );
            let candidate = PrewarmingExecutor::new(db.clone(), env.clone())
                .execute(tx.clone(), None)
                .unwrap();
            db.cache.accounts.get_mut(&observed).unwrap().info.code =
                (!worker_has_code).then(Bytecode::default);
            let expected = TempoEvm::new(db.clone(), env.clone())
                .transact_raw(tx.clone())
                .unwrap();
            // BALANCE observes metadata without loading inline code. Ordinary
            // Account/Result equality ignores this hook-visible Option field.
            assert!(!expected.state[&observed].is_touched());
            assert_eq!(
                expected.state[&observed].info.code.is_some(),
                !worker_has_code
            );
            let hooks = Arc::new(std::sync::Mutex::new(Vec::new()));
            let captured = Arc::clone(&hooks);
            let mut state = revm::database::State::builder()
                .with_database(db)
                .with_bundle_update()
                .build()
                .with_state_hook(Some(Box::new(move |state: revm::state::EvmState| {
                    captured.lock().unwrap().push(state);
                })));
            state.basic(observed).unwrap();
            let mut parallel = TempoEvm::new(&mut state, env);
            if cached {
                parallel.enable_state_cache_validation();
            }
            parallel.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
            parallel.set_preexecuted_transaction(candidate);
            let actual = parallel.transact_raw(tx).unwrap();
            assert_eq!(actual, expected);
            parallel.db_mut().commit(actual.state);
            let hooks = hooks.lock().unwrap();
            assert_eq!(hooks.len(), 1);
            let actual = &hooks[0][&observed];
            let expected = &expected.state[&observed];
            assert_eq!(actual.info.code.is_some(), expected.info.code.is_some());
            assert_eq!(
                actual.original_info().code.is_some(),
                expected.original_info().code.is_some(),
            );
            assert_eq!(parallel.execution_stats().reused, 0);
        }
    }
}

#[test]
fn empty_code_availability_preserves_subsequent_code_loads() {
    use revm::DatabaseCommit as _;

    let target = Address::with_last_byte(100);
    let beneficiary = Address::with_last_byte(103);
    let later_code = Bytecode::new_legacy(Bytes::from_static(&[
        0x60, 42, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3,
    ]));
    let mut code = vec![0x73]; // PUSH20 beneficiary; SELFDESTRUCT.
    code.extend_from_slice(beneficiary.as_slice());
    code.push(0xff);
    for cached in [false, true] {
        let (mut db, env, tx) = journal_guard_fixture(code.clone().into());
        db.cache.accounts.get_mut(&target).unwrap().info.balance = U256::from(777);
        db.insert_account_info(
            beneficiary,
            AccountInfo {
                nonce: 1,
                balance: U256::from(7),
                ..Default::default()
            },
        );
        db.cache
            .contracts
            .insert(later_code.hash_slow(), later_code.clone());
        let candidate = PrewarmingExecutor::new(db.clone(), env.clone())
            .execute(tx.clone(), None)
            .unwrap();
        // SELFDESTRUCT touches its beneficiary without loading its code. Reusing
        // Some(empty) here would persist it over the authoritative absent code.
        db.cache.accounts.get_mut(&beneficiary).unwrap().info.code = None;
        let mut expected_state = revm::database::State::builder()
            .with_database(db.clone())
            .build();
        let mut actual_state = revm::database::State::builder().with_database(db).build();
        actual_state.basic(beneficiary).unwrap();
        let mut expected = TempoEvm::new(&mut expected_state, env.clone());
        let mut actual = TempoEvm::new(&mut actual_state, env);
        if cached {
            actual.enable_state_cache_validation();
        }
        actual.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
        actual.set_preexecuted_transaction(candidate);
        let expected_output = expected.transact_raw(tx.clone()).unwrap();
        let actual_output = actual.transact_raw(tx.clone()).unwrap();
        assert_eq!(actual_output, expected_output);
        assert!(expected_output.state[&beneficiary].is_touched());
        assert!(expected_output.state[&beneficiary].info.code.is_none());
        expected.db_mut().commit(expected_output.state);
        actual.db_mut().commit(actual_output.state);

        // Public cache mutation must remain observable to subsequent execution.
        // Changing only the hash makes None load the new code, whereas a stale
        // Some(empty) would override the lookup and silently skip the contract.
        for evm in [&mut expected, &mut actual] {
            evm.db_mut()
                .cache
                .accounts
                .get_mut(&beneficiary)
                .unwrap()
                .account
                .as_mut()
                .unwrap()
                .info
                .code_hash = later_code.hash_slow();
        }
        let mut next = tx;
        next.inner.nonce = 1;
        next.inner.kind = beneficiary.into();
        let expected_output = expected.transact_raw(next.clone()).unwrap();
        let actual_output = actual.transact_raw(next).unwrap();
        assert_eq!(
            expected_output.result.output().unwrap().as_ref(),
            U256::from(42).to_be_bytes::<32>(),
        );
        assert_eq!(actual_output, expected_output);
        assert_eq!(actual.execution_stats().reused, 0);
    }
}

#[derive(Clone, Debug)]
struct IndexedStorageDb {
    inner: JournalGuardDB,
    indexed_reads: Arc<AtomicUsize>,
}

#[derive(Debug, thiserror::Error)]
#[error("indexed storage unavailable")]
struct IndexedStorageError;
impl DBErrorMarker for IndexedStorageError {}

impl revm::Database for IndexedStorageDb {
    type Error = IndexedStorageError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.inner.basic(address).unwrap())
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        Ok(self.inner.storage(address, slot).unwrap())
    }

    fn storage_by_account_id(
        &mut self,
        _: Address,
        _: revm::state::AccountId,
        _: U256,
    ) -> Result<U256, Self::Error> {
        self.indexed_reads.fetch_add(1, Ordering::Relaxed);
        Err(IndexedStorageError)
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.inner.code_by_hash(hash).unwrap())
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.inner.block_hash(number).unwrap())
    }
}

#[test]
fn indexed_storage_errors_require_authoritative_execution_even_with_unchanged_ids() {
    let target = Address::with_last_byte(100);
    let (mut db, env, tx) = journal_guard_fixture(Bytes::from_static(&[0x60, 0, 0x54, 0]));
    db.cache.accounts.get_mut(&target).unwrap().info.account_id = revm::state::AccountId::new(0);
    let db = IndexedStorageDb {
        inner: db,
        indexed_reads: Arc::new(AtomicUsize::new(0)),
    };
    let expected = TempoEvm::new(db.clone(), env.clone())
        .transact_raw(tx.clone())
        .unwrap_err()
        .to_string();
    for prewarmed in [false, true] {
        let mut actual = TempoEvm::new(db.clone(), env.clone());
        actual.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
        if prewarmed {
            let candidate = PrewarmingExecutor::new(db.clone(), env.clone())
                .execute(tx.clone(), None)
                .unwrap();
            // Address storage succeeds; the indexed method has its own error.
            assert!(candidate.prewarming_result().result.is_success());
            actual.set_preexecuted_transaction(candidate);
        } else {
            actual.prepare_transactions([(tx.clone(), Address::ZERO)]);
        }
        db.indexed_reads.store(0, Ordering::Relaxed);
        assert_eq!(
            actual.transact_raw(tx.clone()).unwrap_err().to_string(),
            expected
        );
        assert_eq!(db.indexed_reads.load(Ordering::Relaxed), 1);
        assert_eq!(actual.execution_stats().reused, 0);
        assert_eq!(actual.execution_stats().bodies_reused, 0);
        assert_eq!(actual.execution_stats().metadata_conflicts, 1);
    }
}

#[test]
fn account_ids_preserve_raw_state_hook_metadata_without_storage_reads() {
    use revm::{DatabaseCommit as _, state::AccountId};

    let observed = Address::with_last_byte(103);
    let ids = [None, AccountId::new(0), AccountId::new(1)];
    for cached in [false, true] {
        for before in ids {
            for after in ids {
                let (mut db, env, tx) = journal_guard_fixture(balance_code(observed));
                db.insert_account_info(
                    observed,
                    AccountInfo {
                        nonce: 1,
                        balance: U256::from(7),
                        account_id: before,
                        ..Default::default()
                    },
                );
                let candidate = PrewarmingExecutor::new(db.clone(), env.clone())
                    .execute(tx.clone(), None)
                    .unwrap();
                db.cache
                    .accounts
                    .get_mut(&observed)
                    .unwrap()
                    .info
                    .account_id = after;
                let expected = TempoEvm::new(db.clone(), env.clone())
                    .transact_raw(tx.clone())
                    .unwrap();
                let hooks = Arc::new(std::sync::Mutex::new(Vec::new()));
                let captured = Arc::clone(&hooks);
                let mut state = revm::database::State::builder()
                    .with_database(db)
                    .build()
                    .with_state_hook(Some(Box::new(move |state: revm::state::EvmState| {
                        captured.lock().unwrap().push(state);
                    })));
                state.basic(observed).unwrap();
                let mut actual = TempoEvm::new(&mut state, env.clone());
                if cached {
                    actual.enable_state_cache_validation();
                }
                actual.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
                actual.set_preexecuted_transaction(candidate);
                let output = actual.transact_raw(tx).unwrap();
                assert_eq!(output, expected);
                actual.db_mut().commit(output.state);
                let hooks = hooks.lock().unwrap();
                assert_eq!(hooks.len(), 1);
                let account = &hooks[0][&observed];
                // Ordinary Account/Result equality deliberately omits the ID.
                assert_eq!(account.info.account_id, after);
                assert_eq!(account.original_info().account_id, after);
                assert_eq!(
                    actual.execution_stats().reused,
                    u64::from(before.is_none() && after.is_none()),
                );
            }
        }
    }
}

#[test]
fn indexed_accounts_cannot_enter_or_bypass_call_body_reuse() {
    use revm::{DatabaseCommit as _, ExecuteEvm as _, context_interface::JournalTr};
    use tempo_precompiles::{
        TIP_FEE_MANAGER_ADDRESS,
        storage::{StorageActions, StorageCtx},
        test_util::TIP20Setup,
    };

    let target = Address::with_last_byte(100);
    let (db, env, mut tx) = journal_guard_fixture(Bytes::from_static(&[0x60, 0, 0x54, 0]));
    let caller = tx.inner.caller;
    let mut setup = TempoEvm::new(db, env.clone());
    StorageCtx::enter_ctx(setup.ctx_mut(), StorageActions::disabled(), || {
        TIP20Setup::path_usd(caller)
            .with_issuer(caller)
            .with_mint(caller, U256::from(1_000_000_000u64))
            .apply()
            .unwrap();
    });
    let state = setup.ctx_mut().journaled_state.finalize();
    setup.db_mut().commit(state);
    let (mut parent, _) = setup.finish();
    parent.insert_account_info(
        TIP_FEE_MANAGER_ADDRESS,
        AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from_static(&[0]))),
    );
    parent.insert_account_info(caller, AccountInfo::default().with_nonce(1));
    tx.inner.nonce = 1;
    tx.inner.gas_price = 1;
    let pool = SpeculativeExecutor::new(1, 1)
        .unwrap()
        .with_minimum_body_duration(Duration::ZERO);

    for indexed in [None, Some(caller), Some(target)] {
        let mut db = IndexedStorageDb {
            inner: parent.clone(),
            indexed_reads: Arc::new(AtomicUsize::new(0)),
        };
        if let Some(indexed) = indexed {
            db.inner
                .cache
                .accounts
                .get_mut(&indexed)
                .unwrap()
                .info
                .account_id = revm::state::AccountId::new(0);
        }
        let mut batch =
            pool.speculate(&mut db, vec![(tx.clone(), env.clone())], HashMap::default());
        let mut candidate = batch.take(&tx, &mut db).unwrap();
        drop(batch);
        assert!(candidate.result.as_ref().unwrap().result.is_success());
        assert_eq!(candidate.body.is_none(), indexed.is_some());
        let Some(body) = candidate.body.take() else {
            continue;
        };

        // A previously ordinary account becomes indexed only on the canonical
        // provider. Its body must perform the failing indexed read itself.
        db.inner
            .cache
            .accounts
            .get_mut(&target)
            .unwrap()
            .info
            .account_id = revm::state::AccountId::new(1);
        let expected = TempoEvm::new(db.clone(), env.clone())
            .transact_raw(tx.clone())
            .unwrap_err()
            .to_string();
        let mut actual = TempoEvm::new(db, env.clone());
        let inner = actual.inner_mut();
        inner.set_body_replay(Some(body));
        assert_eq!(
            inner.transact(tx.clone()).unwrap_err().to_string(),
            expected
        );
        assert!(!inner.body_was_reused());
    }
}
