use super::*;
use alloy_primitives::{Bytes, TxKind};
use revm::{
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
