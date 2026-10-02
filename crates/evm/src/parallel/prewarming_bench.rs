//! In-memory diagnostic for the builder's provider-owned prewarming path.
//! Worker setup is separate from dispatch so execution timing includes all jobs.

use super::*;
use revm::{Database, database::State, database_interface::WrapDatabaseRef};
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        mpsc::{Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
};

struct Job {
    index: usize,
    result: SyncSender<Option<PreexecutedTransaction>>,
}

pub(super) struct Pipeline {
    jobs: Option<SyncSender<Job>>,
    pending: VecDeque<(usize, Receiver<Option<PreexecutedTransaction>>)>,
    workers: Vec<JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
    offsets: Arc<Vec<Option<usize>>>,
    prefix: Option<PrewarmingState>,
    next_input: usize,
    window: usize,
    last_offset: Option<usize>,
}

impl Pipeline {
    pub(super) fn new(
        parent: Arc<TestDB>,
        transactions: Arc<Vec<TempoTxEnv>>,
        env: Env,
        threads: usize,
        publish_prefix: bool,
    ) -> Self {
        assert!(threads > 0);
        let window = threads.checked_mul(2).unwrap();
        let (jobs, receiver) = mpsc::sync_channel::<Job>(window);
        let receiver = Arc::new(Mutex::new(receiver));
        let cancelled = Arc::new(AtomicBool::new(false));
        let prefix = publish_prefix.then(PrewarmingState::default);
        let mut expiring_offset = 0;
        let offsets = Arc::new(
            transactions
                .iter()
                .map(|tx| {
                    tx.tempo_tx_env
                        .as_ref()
                        .filter(|aa| aa.nonce_key == U256::MAX)
                        .map(|_| {
                            let offset = expiring_offset;
                            expiring_offset += 1;
                            offset
                        })
                })
                .collect::<Vec<_>>(),
        );
        let (ready_tx, ready_rx) = mpsc::sync_channel(threads);
        let workers = (0..threads)
            .map(|index| {
                let (parent, transactions, offsets) =
                    (parent.clone(), transactions.clone(), offsets.clone());
                let (receiver, cancelled, prefix) =
                    (receiver.clone(), cancelled.clone(), prefix.clone());
                let (env, ready_tx) = (env.clone(), ready_tx.clone());
                thread::Builder::new()
                    .name(format!("bench-prewarm-{index}"))
                    .spawn(move || {
                        let mut executor = PrewarmingExecutor::new(WrapDatabaseRef(parent), env);
                        if let Some(prefix) = prefix {
                            executor = executor.with_state(prefix);
                        }
                        ready_tx.send(()).unwrap();
                        loop {
                            let job = receiver.lock().unwrap().recv();
                            let Ok(job) = job else { break };
                            if cancelled.load(Ordering::Relaxed) {
                                break;
                            }
                            let result = executor
                                .execute(transactions[job.index].clone(), offsets[job.index])
                                .ok();
                            // Exactly one result fits without waiting for the consumer.
                            let _ = job.result.send(result);
                        }
                    })
                    .unwrap()
            })
            .collect::<Vec<_>>();
        drop(ready_tx);
        for _ in 0..threads {
            ready_rx.recv().expect("worker initialization");
        }
        Self {
            jobs: Some(jobs),
            pending: VecDeque::with_capacity(window),
            workers,
            cancelled,
            offsets,
            prefix,
            next_input: 0,
            window,
            last_offset: None,
        }
    }

    fn fill(&mut self) {
        while self.pending.len() < self.window && self.next_input < self.offsets.len() {
            let index = self.next_input;
            let (result, receiver) = mpsc::sync_channel(1);
            self.jobs
                .as_ref()
                .unwrap()
                .send(Job { index, result })
                .expect("live workers");
            self.pending.push_back((index, receiver));
            self.next_input += 1;
        }
    }

    /// Receives the next source candidate, then admits its replacement as the
    /// builder does when consuming the result handle before ordered execution.
    pub(super) fn take_next(&mut self) -> Option<PreexecutedTransaction> {
        self.fill();
        let (index, receiver) = self.pending.pop_front().expect("source candidate");
        let result = receiver.recv().expect("worker result");
        self.last_offset = self.offsets[index];
        self.fill();
        result
    }

    pub(super) fn record(&self, state: &revm::state::EvmState) {
        if let Some(prefix) = &self.prefix {
            prefix.record(state, self.last_offset);
        }
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        self.jobs.take();
        self.pending.clear();
        for worker in self.workers.drain(..) {
            // The ordered receiver reports a worker panic; never double-panic
            // while draining outstanding jobs during assertion unwinding.
            let _ = worker.join();
        }
    }
}

pub(super) fn assert_matches(db: TestDB, transactions: Vec<TempoTxEnv>, spec: TempoHardfork) {
    let mut env = test_evm_with_basefee(TestDB::default(), 0).finish().1;
    env.cfg_env = revm::context::CfgEnv::new_with_spec_and_gas_params(
        spec,
        tempo_revm::gas_params::tempo_gas_params(spec),
    );
    let transactions = Arc::new(transactions);
    for publish_prefix in [false, true] {
        let mut canonical = TempoEvm::new(
            State::builder().with_database(db.clone()).build(),
            env.clone(),
        );
        let mut ordered = TempoEvm::new(
            State::builder().with_database(db.clone()).build(),
            env.clone(),
        );
        ordered.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
        let mut pipeline = Pipeline::new(
            Arc::new(db.clone()),
            transactions.clone(),
            env.clone(),
            2,
            publish_prefix,
        );
        for (index, tx) in transactions.iter().enumerate() {
            let candidate = pipeline.take_next();
            assert!(pipeline.pending.len() <= pipeline.window);
            assert!(pipeline.next_input <= index + 1 + pipeline.window);
            // A skipped source candidate must retain its expiring offset; it
            // must not publish state or shift later transaction identities.
            if index == 1 {
                continue;
            }
            if let Some(candidate) = candidate {
                ordered.set_preexecuted_transaction(candidate);
            }
            match (
                canonical.transact_raw(tx.clone()),
                ordered.transact_raw(tx.clone()),
            ) {
                (Ok(expected), Ok(actual)) => {
                    assert_eq!(actual, expected);
                    pipeline.record(&actual.state);
                    canonical.db_mut().commit(expected.state);
                    ordered.db_mut().commit(actual.state);
                }
                (Err(expected), Err(actual)) => {
                    assert_eq!(actual.to_string(), expected.to_string())
                }
                results => panic!("different validity: {results:?}"),
            }
        }
        assert_eq!(state_root(canonical.db()), state_root(ordered.db()));
        assert!(ordered.execution_stats().reused > 0);
    }
}

/// Merge the node's committed cache over the fixture's complete parent state.
/// Root calculation is outside execution timing and includes untouched storage.
pub(super) fn state_root(state: &State<TestDB>) -> B256 {
    let mut merged = state.database.clone();
    for (&address, account) in &state.cache.accounts {
        let Some(plain) = &account.account else {
            merged.cache.accounts.remove(&address);
            continue;
        };
        merged.insert_account_info(address, plain.info.clone());
        let storage = &mut merged.cache.accounts.get_mut(&address).unwrap().storage;
        if account.status.is_storage_known() {
            storage.clear();
        }
        storage.extend(plain.storage.iter().map(|(&key, &value)| (key, value)));
    }
    root(&merged)
}

#[test]
fn committed_root_preserves_unread_storage_and_clears_recreated_accounts() {
    use revm::state::{Account, EvmState, EvmStorageSlot};

    let target = address(901);
    let untouched = address(902);
    let (slot_a, slot_b, slot_c) = (U256::from(1), U256::from(2), U256::from(3));
    let mut expected = TestDB::default();
    contract(&mut expected, target, &[0]);
    contract(&mut expected, untouched, &[0x60, 0]);
    expected
        .insert_account_storage(target, slot_a, U256::from(7))
        .unwrap();
    expected
        .insert_account_storage(target, slot_b, U256::from(9))
        .unwrap();
    let mut state = State::builder().with_database(expected.clone()).build();
    assert_eq!(state_root(&state), root(&expected));

    let mut changed = Account::from(state.basic(target).unwrap().unwrap());
    assert_eq!(state.storage(target, slot_a).unwrap(), U256::from(7));
    assert_eq!(state_root(&state), root(&expected));
    changed.mark_touch();
    changed.storage.insert(
        slot_a,
        EvmStorageSlot::new_changed(U256::from(7), U256::ZERO, Default::default()),
    );
    state.commit(EvmState::from_iter([(target, changed)]));
    expected
        .cache
        .accounts
        .get_mut(&target)
        .unwrap()
        .storage
        .remove(&slot_a);
    // The untouched slot exists only in the parent, so hashing just State's
    // loaded storage would produce a different root from this explicit oracle.
    assert!(
        !state.cache.accounts[&target]
            .account
            .as_ref()
            .unwrap()
            .storage
            .contains_key(&slot_b)
    );
    assert_eq!(state_root(&state), root(&expected));

    let mut destroyed = Account::from(state.basic(target).unwrap().unwrap());
    destroyed.mark_touch();
    destroyed.mark_selfdestruct();
    state.commit(EvmState::from_iter([(target, destroyed)]));
    expected.cache.accounts.remove(&target);
    assert_eq!(state_root(&state), root(&expected));

    let info = AccountInfo {
        nonce: 1,
        ..Default::default()
    }
    .with_code(Bytecode::new_raw(Bytes::from_static(&[0x60, 1])));
    let mut created = Account::from(info.clone());
    created.mark_touch();
    created.mark_created();
    created.storage.insert(
        slot_c,
        EvmStorageSlot::new_changed(U256::ZERO, U256::from(11), Default::default()),
    );
    state.commit(EvmState::from_iter([(target, created)]));
    expected.insert_account_info(target, info);
    expected
        .insert_account_storage(target, slot_c, U256::from(11))
        .unwrap();
    // Recreation must not resurrect either original parent slot.
    assert_eq!(state_root(&state), root(&expected));

    let mut empty = Account::from(AccountInfo::default());
    empty.mark_touch();
    state.commit(EvmState::from_iter([(target, empty)]));
    expected.cache.accounts.remove(&target);
    assert_eq!(state_root(&state), root(&expected));
}

#[test]
fn pipeline_matches_ordered_execution_and_drops_with_pending_jobs() {
    let mut db = TestDB::default();
    let target = address(900);
    contract(&mut db, target, &[0x60, 1, 0x60, 0, 0x55, 0]);
    let transactions = (0..32)
        .map(|i| transaction(i, target, 0, &[]))
        .collect::<Vec<_>>();
    assert_matches(db.clone(), transactions.clone(), TempoHardfork::T14);
    let env = test_evm_with_basefee(TestDB::default(), 0).finish().1;
    let mut pipeline = Pipeline::new(Arc::new(db), Arc::new(transactions), env, 2, true);
    let _ = pipeline.take_next();
    assert_eq!(pipeline.pending.len(), pipeline.window);
    drop(pipeline);
}
