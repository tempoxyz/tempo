//! Owned Engine runners must preserve the existing capture and canonical paths.

use super::*;
use alloy_evm::precompiles::{DynPrecompile, PrecompilesMap};
use revm::precompile::{PrecompileId, PrecompileOutput};
use std::{cell::Cell, rc::Rc};

fn assert_retained_equal(left: &EnginePrewarmingSession, right: &EnginePrewarmingSession) {
    let left = left.retained.lock().unwrap();
    let right = right.retained.lock().unwrap();
    assert_eq!(
        left.results.keys().collect::<Vec<_>>(),
        right.results.keys().collect::<Vec<_>>()
    );
    for (index, (left, _)) in &left.results {
        let right = &right.results[index].0;
        assert_eq!(left.tx, right.tx);
        assert_eq!(left.env, right.env);
        assert_eq!(left.result, right.result);
        assert_eq!(left.validator_fee, right.validator_fee);
        let ordered_reads = |candidate: &PreexecutedTransaction| {
            let mut reads = candidate.reads.clone();
            reads.sort_by_key(|(key, _)| format!("{key:?}"));
            reads
        };
        assert_eq!(ordered_reads(left), ordered_reads(right));
        // Also preserve raw account/code representation, beyond ReadValue's
        // semantic equality (including account IDs and inline code metadata).
        let raw_reads = |candidate: &PreexecutedTransaction| {
            ordered_reads(candidate)
                .iter()
                .map(|read| format!("{read:?}"))
                .collect::<Vec<_>>()
        };
        assert_eq!(raw_reads(left), raw_reads(right));
        // FeeUpdate intentionally hides operations. Sort entries, preserving
        // each entry's complete ordered arithmetic operation representation.
        let ordered_fees = |candidate: &PreexecutedTransaction| {
            let mut fees = candidate
                .fee_updates
                .iter()
                .map(|fee| ((fee.address, fee.slot), format!("{fee:?}")))
                .collect::<Vec<_>>();
            fees.sort_by_key(|(key, _)| *key);
            fees
        };
        assert_eq!(ordered_fees(left), ordered_fees(right));
        assert_eq!(left.native_increment, right.native_increment);
    }
}

fn assert_canonical(factory: &TempoEvmFactory, db: TestDB, env: Env, txs: &[TempoTxEnv]) -> u64 {
    let mut expected = TempoEvm::new(db.clone(), env.clone());
    let mut actual = ordered(factory, db, env);
    for tx in txs {
        let left = actual.transact_raw(tx.clone());
        let right = expected.transact_raw(tx.clone());
        match (left, right) {
            (Ok(left), Ok(right)) => {
                assert_eq!(left, right);
                assert_eq!(actual.validator_fee(), expected.validator_fee());
                actual.db_mut().commit(left.state);
                expected.db_mut().commit(right.state);
                assert_eq!(root(actual.db()), root(expected.db()));
            }
            (Err(left), Err(right)) => assert_eq!(left.to_string(), right.to_string()),
            (left, right) => panic!("canonical outcome mismatch: {left:?} / {right:?}"),
        }
    }
    actual.execution_stats().reused
}

#[test]
fn owned_runner_resets_after_success_revert_halt_and_strict_error() {
    // Write and emit a log; revert/halt must discard both before the next call.
    let mut db = contract(&[
        0x60, 0, 0x54, 0x60, 1, 0x01, 0x60, 0, 0x55, 0x60, 0, 0x60, 0, 0xa0, 0,
    ]);
    for (index, code) in [
        (
            901,
            &[
                0x60, 2, 0x60, 0, 0x55, 0x60, 0, 0x60, 0, 0xa0, 0x60, 0, 0x60, 0, 0xfd,
            ][..],
        ),
        (
            902,
            &[0x60, 2, 0x60, 0, 0x55, 0x60, 0, 0x60, 0, 0xa0, 0xfe][..],
        ),
        // Return the previous transient value, then store one for this call.
        (
            903,
            &[
                0x60, 0, 0x5c, 0x60, 0, 0x52, 0x60, 1, 0x60, 0, 0x5d, 0x60, 32, 0x60, 0, 0xf3,
            ][..],
        ),
    ] {
        db.insert_account_info(
            address(index),
            AccountInfo::default().with_code(Bytecode::new_raw(Bytes::copy_from_slice(code))),
        );
    }
    let env = env(TempoHardfork::T0);
    let mut txs = (0..8).map(tx).collect::<Vec<_>>();
    txs[1].inner.kind = TxKind::Call(address(901));
    txs[2].inner.kind = TxKind::Call(address(902));
    txs[3].inner.nonce = 7;
    txs[6].inner.kind = TxKind::Call(address(903));
    txs[7].inner.kind = TxKind::Call(address(903));
    let (old_factory, old_session) = factory_with_diagnostics(&env, &txs, true);
    let (new_factory, new_session) = factory_with_diagnostics(&env, &txs, true);
    let mut old = old_factory.create_evm(db.clone(), relaxed(&env));
    let mut new = new_factory.prewarm_runner(db.clone(), relaxed(&env));
    for (index, tx) in txs.iter().enumerate() {
        let expected = old.transact(tx.clone()).unwrap();
        let actual = new.transact(tx.clone()).unwrap();
        assert_eq!(actual, expected);
        match index {
            1 => assert!(matches!(
                actual.result,
                revm::context::result::ExecutionResult::Revert { .. }
            )),
            2 => assert!(matches!(
                actual.result,
                revm::context::result::ExecutionResult::Halt { .. }
            )),
            _ => assert!(actual.result.is_success()),
        }
        if index >= 6 {
            assert_eq!(actual.result.output().unwrap().as_ref(), &[0; 32]);
        }
        assert_retained_equal(&old_session, &new_session);
    }
    assert_eq!(root(old.db()), root(&db), "prewarming does not commit");
    let counts = new_session.diagnostics.as_ref().unwrap().snapshot();
    assert_eq!(counts.0[CaptureEvent::StrictSucceeded as usize], 7);
    assert_eq!(counts.0[CaptureEvent::StrictFailed as usize], 1);
    assert!(
        !new_session
            .retained
            .lock()
            .unwrap()
            .results
            .contains_key(&3)
    );
    assert!(assert_canonical(&new_factory, db.clone(), env.clone(), &txs) > 0);
    assert!(assert_canonical(&old_factory, db, env, &txs) > 0);
}

fn paid_aa_fixture() -> (TestDB, Env, Vec<TempoTxEnv>) {
    let mut setup = crate::test_utils::test_evm_with_basefee(TestDB::default(), 0);
    StorageCtx::enter_ctx(setup.ctx_mut(), StorageActions::disabled(), || {
        let mut setup = TIP20Setup::path_usd(address(999)).with_issuer(address(999));
        for i in 0..4 {
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
    let txs = (0..4)
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
    (db, env(TempoHardfork::T14), txs)
}

#[test]
fn owned_runner_preserves_paid_expiring_aa_offsets_and_fee_certificates() {
    let (db, env, txs) = paid_aa_fixture();
    let (old_factory, old_session) = factory(&env, &txs);
    let (new_factory, new_session) = factory(&env, &txs);
    let mut old = old_factory.create_evm(db.clone(), relaxed(&env));
    let mut new = new_factory.prewarm_runner(db.clone(), relaxed(&env));
    for (index, tx) in txs.iter().enumerate() {
        let mut worker_tx = tx.clone();
        worker_tx.tempo_tx_env.as_mut().unwrap().expiring_nonce_idx = Some(index);
        let actual = new.transact(worker_tx.clone()).unwrap();
        assert!(actual.result.is_success());
        assert_eq!(actual, old.transact(worker_tx).unwrap());
        assert_retained_equal(&old_session, &new_session);
    }
    assert!(
        new_session
            .retained
            .lock()
            .unwrap()
            .results
            .values()
            .all(|(candidate, _)| {
                candidate.validator_fee > U256::ZERO
                    && !candidate.fee_updates.is_empty()
                    && candidate
                        .tx
                        .tempo_tx_env
                        .as_ref()
                        .unwrap()
                        .expiring_nonce_idx
                        .is_none()
            })
    );
    assert_eq!(
        assert_canonical(&new_factory, db.clone(), env.clone(), &txs),
        4
    );
    assert_eq!(assert_canonical(&old_factory, db, env, &txs), 4);
}

fn decorate(precompiles: &mut PrecompilesMap) {
    let identity = Address::with_last_byte(4);
    precompiles.map_precompile(&identity, |_| {
        DynPrecompile::new(PrecompileId::Identity, |_| {
            Ok(PrecompileOutput::new(
                15,
                Bytes::from_static(b"decorated"),
                0,
            ))
        })
    });
}

#[test]
fn owned_runner_precompile_decoration_permanently_disables_capture() {
    let env = env(TempoHardfork::T0);
    let mut txs = (0..3).map(tx).collect::<Vec<_>>();
    for tx in &mut txs {
        tx.inner.kind = TxKind::Call(Address::with_last_byte(4));
    }
    let (old_factory, old_session) = factory(&env, &txs);
    let (new_factory, new_session) = factory(&env, &txs);
    let mut old = old_factory.create_evm(TestDB::default(), relaxed(&env));
    let mut new = new_factory.prewarm_runner(TestDB::default(), relaxed(&env));
    assert_eq!(
        new.transact(txs[0].clone()).unwrap(),
        old.transact(txs[0].clone()).unwrap()
    );
    assert!(new_session.take(&txs[0]).is_some());
    assert!(old_session.take(&txs[0]).is_some());
    decorate(new.precompiles_mut());
    decorate(old.precompiles_mut());
    for tx in &txs[1..] {
        let result = new.transact(tx.clone()).unwrap();
        assert_eq!(result.result.output().unwrap().as_ref(), b"decorated");
        assert_eq!(result, old.transact(tx.clone()).unwrap());
        assert!(new_session.take(tx).is_none());
        assert!(old_session.take(tx).is_none());
    }
}

#[test]
fn owned_runner_initial_pure_precompile_decoration_uses_legacy_path() {
    let env = env(TempoHardfork::T0);
    let mut txs = [tx(0), tx(1)];
    for tx in &mut txs {
        tx.inner.kind = TxKind::Call(Address::with_last_byte(2));
    }
    let (factory, session) = factory(&env, &txs);
    let mut old = factory.create_evm(TestDB::default(), relaxed(&env));
    let mut new = factory.prewarm_runner(TestDB::default(), relaxed(&env));
    // Reth's optional pure-precompile cache uses this same access/mapping
    // path. A transparent decorator must still disable strict capture.
    old.precompiles_mut()
        .map_cacheable_precompiles(|_, precompile| precompile);
    new.precompiles_mut()
        .map_cacheable_precompiles(|_, precompile| precompile);
    for tx in txs {
        assert_eq!(new.transact(tx.clone()).unwrap(), old.transact(tx).unwrap());
        assert!(session.retained.lock().unwrap().results.is_empty());
    }
}

#[test]
fn owned_runner_preserves_factory_and_transaction_admission_exclusions() {
    for excluded in [
        "unmarked",
        "cleared",
        "wrong_block",
        "strict",
        "nonce_only",
        "balance_only",
        "txpool",
        "free_fees",
        "simulation",
        "system",
        "unindexed",
    ] {
        let env = env(TempoHardfork::T0);
        let original = tx(0);
        let (mut factory, session) = factory(&env, std::slice::from_ref(&original));
        let mut worker_env = relaxed(&env);
        let mut transaction = original.clone();
        match excluded {
            "unmarked" => factory = TempoEvmFactory::default(),
            "cleared" => factory.engine_prewarming.as_ref().unwrap().clear(),
            "wrong_block" => worker_env.block_env.inner.number += U256::ONE,
            "strict" => worker_env = env.clone(),
            "nonce_only" => worker_env.cfg_env.disable_balance_check = false,
            "balance_only" => worker_env.cfg_env.disable_nonce_check = false,
            "txpool" => worker_env.cfg_env.disable_base_fee = true,
            "free_fees" => worker_env.cfg_env.disable_fee_charge = true,
            "simulation" => transaction.execution_context = ExecutionContext::Simulation,
            "system" => transaction.is_system_tx = true,
            "unindexed" => transaction = tx(1),
            _ => unreachable!(),
        }
        let mut old = factory.create_evm(TestDB::default(), worker_env.clone());
        let mut new = factory.prewarm_runner(TestDB::default(), worker_env);
        assert_eq!(
            new.transact(transaction.clone()).map_err(|e| e.to_string()),
            old.transact(transaction).map_err(|e| e.to_string()),
            "{excluded}"
        );
        assert!(
            session.retained.lock().unwrap().results.is_empty(),
            "{excluded}"
        );
    }
}

#[derive(Debug, thiserror::Error)]
#[error("owned runner test provider failure")]
struct ProviderFailure;
impl reth_revm::database_interface::DBErrorMarker for ProviderFailure {}

// Rc intentionally makes the provider !Send: construction/use/drop are local.
#[derive(Debug)]
struct LocalProvider {
    db: TestDB,
    fault: Rc<Cell<u8>>,
    calls: Rc<Cell<usize>>,
    failed_key: Rc<Cell<Option<(Address, U256)>>>,
    drops: Rc<Cell<usize>>,
    owner: std::thread::ThreadId,
}
impl LocalProvider {
    fn new(db: TestDB) -> Self {
        Self {
            db,
            fault: Rc::default(),
            calls: Rc::default(),
            failed_key: Rc::default(),
            drops: Rc::default(),
            owner: std::thread::current().id(),
        }
    }
}
impl Drop for LocalProvider {
    fn drop(&mut self) {
        assert_eq!(self.owner, std::thread::current().id());
        self.drops.set(self.drops.get() + 1);
    }
}
impl Database for LocalProvider {
    type Error = ProviderFailure;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.db.basic(address).unwrap())
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.db.code_by_hash(hash).unwrap())
    }
    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        match self.fault.get() {
            1 => Err(ProviderFailure),
            2 => panic!("owned runner provider panic"),
            3 => {
                self.failed_key.set(Some((address, slot)));
                self.fault.set(0);
                Err(ProviderFailure)
            }
            _ => Ok(self.db.storage(address, slot).unwrap()),
        }
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.db.block_hash(number).unwrap())
    }
}

#[test]
fn owned_runner_provider_error_then_success_matches_fresh_capture() {
    let env = env(TempoHardfork::T0);
    let txs = [tx(0), tx(1)];
    let db = contract(&[0x60, 0, 0x54, 0x50, 0]);
    let (old_factory, old_session) = factory(&env, &txs);
    let (new_factory, new_session) = factory(&env, &txs);
    let old_db = LocalProvider::new(db.clone());
    let new_db = LocalProvider::new(db);
    let (old_fault, new_fault) = (old_db.fault.clone(), new_db.fault.clone());
    let (old_calls, new_calls) = (old_db.calls.clone(), new_db.calls.clone());
    old_fault.set(1);
    new_fault.set(1);
    let mut old = old_factory.create_evm(old_db, relaxed(&env));
    let mut new = new_factory.prewarm_runner(new_db, relaxed(&env));
    assert_eq!(
        new.transact(txs[0].clone()).unwrap_err().to_string(),
        old.transact(txs[0].clone()).unwrap_err().to_string()
    );
    assert_eq!(
        new_calls.get(),
        2,
        "strict and relaxed fallback both reach the failed provider"
    );
    assert_eq!(old_calls.get(), new_calls.get());
    assert_retained_equal(&old_session, &new_session);
    assert!(new_session.retained.lock().unwrap().results.is_empty());
    old_fault.set(0);
    new_fault.set(0);
    assert_eq!(
        new.transact(txs[1].clone()).unwrap(),
        old.transact(txs[1].clone()).unwrap()
    );
    assert_retained_equal(&old_session, &new_session);
    assert!(new_session.take(&txs[1]).is_some());
}

#[test]
fn owned_runner_nonce_pointer_error_then_success_clears_prediction() {
    let (db, env, txs) = paid_aa_fixture();
    let (old_factory, old_session) = factory_with_diagnostics(&env, &txs, true);
    let (new_factory, new_session) = factory_with_diagnostics(&env, &txs, true);
    let old_db = LocalProvider::new(db.clone());
    let new_db = LocalProvider::new(db.clone());
    let (old_fault, new_fault) = (old_db.fault.clone(), new_db.fault.clone());
    let (old_failed_key, new_failed_key) = (old_db.failed_key.clone(), new_db.failed_key.clone());
    // The first storage request is execute()'s parent-relative nonce pointer
    // read, before entering the strict EVM. Only that request fails; the
    // original relaxed AA transaction, including its offset, must still run.
    old_fault.set(3);
    new_fault.set(3);
    let mut old = old_factory.create_evm(old_db, relaxed(&env));
    let mut new = new_factory.prewarm_runner(new_db, relaxed(&env));
    for (index, tx) in txs.iter().enumerate() {
        let mut worker_tx = tx.clone();
        worker_tx.tempo_tx_env.as_mut().unwrap().expiring_nonce_idx = Some(index);
        let result = new.transact(worker_tx.clone()).unwrap();
        assert!(result.result.is_success());
        assert_eq!(result, old.transact(worker_tx).unwrap());
        assert_retained_equal(&old_session, &new_session);
    }
    let counts = new_session.diagnostics.as_ref().unwrap().snapshot();
    let pointer_key = Some((
        NONCE_PRECOMPILE_ADDRESS,
        tempo_precompiles::nonce::slots::EXPIRING_NONCE_RING_PTR,
    ));
    assert_eq!(old_failed_key.get(), pointer_key);
    assert_eq!(new_failed_key.get(), pointer_key);
    assert_eq!(counts.0[CaptureEvent::StrictFailed as usize], 1);
    assert_eq!(counts.0[CaptureEvent::StrictSucceeded as usize], 3);
    assert!(
        !new_session
            .retained
            .lock()
            .unwrap()
            .results
            .contains_key(&0)
    );
    assert_eq!(assert_canonical(&new_factory, db, env, &txs), 3);
}

#[test]
fn owned_runner_unwind_drops_provider_and_poisons_reentry() {
    let env = env(TempoHardfork::T0);
    let transaction = tx(0);
    let (factory, session) =
        factory_with_diagnostics(&env, std::slice::from_ref(&transaction), true);
    let db = LocalProvider::new(contract(&[0x60, 0, 0x54, 0]));
    db.fault.set(2);
    let drops = db.drops.clone();
    let weak_session = Arc::downgrade(&session);
    let mut runner = factory.prewarm_runner(db, relaxed(&env));
    drop(factory);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || runner.transact(transaction.clone())
        ))
        .is_err()
    );
    assert_eq!(drops.get(), 1);
    assert!(
        runner
            .transact(transaction)
            .unwrap_err()
            .to_string()
            .contains("prewarming worker panicked")
    );
    let counts = session.diagnostics.as_ref().unwrap().snapshot();
    assert_eq!(counts.0[CaptureEvent::WorkerUnwound as usize], 1);
    assert!(session.retained.lock().unwrap().results.is_empty());
    drop(session);
    assert!(weak_session.upgrade().is_none());
    drop(runner);
    assert_eq!(drops.get(), 1);
}

#[test]
fn owned_runner_retains_only_its_session_and_releases_local_provider() {
    let env = env(TempoHardfork::T0);
    let txs = [tx(0), tx(1)];
    let (factory, old_session) = factory(&env, &txs);
    let db = LocalProvider::new(contract(&[0x60, 0, 0x54, 0x60, 1, 0x01, 0x60, 0, 0x55, 0]));
    let drops = db.drops.clone();
    let mut old = factory.prewarm_runner(db, relaxed(&env));
    let new_session = factory
        .engine_prewarming
        .as_ref()
        .unwrap()
        .begin(
            env.clone(),
            txs.iter().map(|tx| {
                let ExecutionContext::Transaction { tx_hash } = tx.execution_context else {
                    unreachable!()
                };
                tx_hash
            }),
        )
        .unwrap();
    let first = old.transact(txs[0].clone()).unwrap();
    assert_eq!(old_session.retained.lock().unwrap().results.len(), 1);
    assert!(new_session.retained.lock().unwrap().results.is_empty());
    // The existing runner reads new accepted hints in its original session.
    old_session.prefix().record(&first.state, None);
    let second = old.transact(txs[1].clone()).unwrap();
    assert_eq!(
        second.state[&address(900)].storage[&U256::ZERO].present_value,
        U256::from(2)
    );
    assert!(new_session.retained.lock().unwrap().results.is_empty());
    let mut replacement = factory.prewarm_runner(
        contract(&[0x60, 0, 0x54, 0x60, 1, 0x01, 0x60, 0, 0x55, 0]),
        relaxed(&env),
    );
    assert_eq!(replacement.transact(txs[0].clone()).unwrap(), first);
    assert_eq!(new_session.retained.lock().unwrap().results.len(), 1);
    let weak_old = Arc::downgrade(&old_session);
    drop(old_session);
    drop(factory);
    assert!(weak_old.upgrade().is_some());
    assert_eq!(drops.get(), 0);
    drop(old);
    assert_eq!(drops.get(), 1);
    assert!(weak_old.upgrade().is_none());
}
