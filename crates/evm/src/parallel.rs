//! Ordered optimistic execution for Tempo transactions.
//!
//! Workers execute against cached values while the owner advances the committed prefix.
//! The database stays on its owning thread: cache misses are served by the coordinator,
//! so even providers that are neither `Send` nor `Sync` are supported without unsafe code.
//! Every database read (including reads in reverted calls and transaction validation) is
//! recorded. A result may be reused only after validating those reads against the state
//! produced by the committed prefix. Otherwise the ordinary EVM replays the transaction,
//! optionally reusing a separately validated call body while rerunning fee processing.
//!
//! Explicit unmetered fee arithmetic can be rebased only when no ordinary access
//! observes its slot. Each intermediate arithmetic check is repeated at commit.
//! A restricted T14 native custody increment has a separate journal witness;
//! rebasing it also requires identical storage gas classes and no other access.

use crate::{TempoBlockEnv, evm::TempoEvm};
use alloy_evm::{Database, Evm, EvmEnv};
use alloy_primitives::{Address, B256, U256, map::HashMap};
use rayon::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use reth_revm::{
    DatabaseCommit, DatabaseRef,
    context::result::{EVMError, ResultAndState},
    database_interface::DBErrorMarker,
    db::CacheDB,
    state::{AccountInfo, Bytecode},
};
use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS,
    nonce::slots as nonce_slots,
    storage::{
        StorageKey,
        fee_updates::{self, FeeUpdate},
        native_increment::{self, NativeIncrementWitness},
    },
};
use tempo_revm::{
    TempoInvalidTransaction, TempoTxEnv,
    replay::{BodyCache, ReadKey, ReadValue, read},
};

use reth_revm::context::result::HaltReason as TempoHaltReason;

mod engine_prewarming;
mod forwarding;
mod native_rebase;
pub(crate) use engine_prewarming::{CaptureEvent, EnginePrewarmingCache, EnginePrewarmingSession};
mod prewarming;
#[cfg(test)]
mod prewarming_guard_tests;
mod state_validation;
#[cfg(test)]
mod state_validation_tests;
pub use prewarming::{PreexecutedTransaction, PrewarmingExecutor, PrewarmingState};

type Env = EvmEnv<TempoHardfork, TempoBlockEnv>;
type Outcome<E> = Result<ResultAndState<TempoHaltReason>, EVMError<E, TempoInvalidTransaction>>;

/// Bounded Engine capture distance and completed-result count, independent of generic batches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EngineCaptureWindow {
    /// Retain the default 128-transaction capture window.
    #[default]
    Transactions128,
    /// Use a 256-transaction capture window.
    Transactions256,
    /// Use a 512-transaction capture window.
    Transactions512,
}

impl EngineCaptureWindow {
    /// Maximum forward distance and number of retained candidates.
    pub const fn transactions(self) -> usize {
        match self {
            Self::Transactions128 => 128,
            Self::Transactions256 => 256,
            Self::Transactions512 => 512,
        }
    }
}

impl std::fmt::Display for EngineCaptureWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.transactions())
    }
}

impl std::str::FromStr for EngineCaptureWindow {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "128" => Ok(Self::Transactions128),
            "256" => Ok(Self::Transactions256),
            "512" => Ok(Self::Transactions512),
            _ => Err("Engine capture window must be 128, 256, or 512"),
        }
    }
}

/// A bounded worker pool shared by block executors and the payload builder.
#[derive(Clone, Debug)]
pub struct SpeculativeExecutor {
    pool: Arc<ThreadPool>,
    batch_size: usize,
    adaptive_backoff: bool,
    minimum_body_duration: Duration,
    streaming: bool,
    fee_rebasing: bool,
    chained_workers: bool,
    state_forwarding: bool,
    nonce_prediction: bool,
    capture_diagnostics: bool,
    capture_window: EngineCaptureWindow,
    scheduled_transactions: Arc<AtomicU64>,
    prewarmed_reuses: Arc<AtomicU64>,
}

impl SpeculativeExecutor {
    /// Creates a pool. Both limits must be nonzero.
    pub fn new(threads: usize, batch_size: usize) -> Result<Self, ThreadPoolBuildError> {
        assert!(
            threads > 0,
            "speculative execution needs at least one worker"
        );
        assert!(
            batch_size > 0,
            "speculative execution needs a nonempty batch"
        );
        Ok(Self {
            pool: Arc::new(
                ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .thread_name(|i| format!("tempo-execution-{i}"))
                    .build()?,
            ),
            batch_size,
            adaptive_backoff: true,
            minimum_body_duration: Duration::from_micros(20),
            streaming: true,
            fee_rebasing: true,
            chained_workers: true,
            state_forwarding: false,
            nonce_prediction: true,
            capture_diagnostics: false,
            capture_window: EngineCaptureWindow::default(),
            scheduled_transactions: Arc::default(),
            prewarmed_reuses: Arc::default(),
        })
    }

    /// Enables opt-in Engine capture accounting without changing scheduling.
    pub fn with_capture_diagnostics(mut self, enabled: bool) -> Self {
        self.capture_diagnostics = enabled;
        self
    }

    pub(crate) const fn capture_diagnostics(&self) -> bool {
        self.capture_diagnostics
    }

    /// Selects only the Engine capture window; generic and builder batches are unchanged.
    pub fn with_capture_window(mut self, window: EngineCaptureWindow) -> Self {
        self.capture_window = window;
        self
    }

    /// Selected Engine capture window.
    pub const fn capture_window(&self) -> EngineCaptureWindow {
        self.capture_window
    }

    /// Predicts expiring-nonce ring positions in input order. Every predicted read
    /// still requires exact validation against the committed transaction prefix.
    pub fn with_nonce_prediction(mut self, enabled: bool) -> Self {
        self.nonce_prediction = enabled;
        self
    }

    /// Controls periodic sequential backoff when fewer than half of a window's
    /// candidates are useful. Disable for experiments that need forced speculation.
    pub fn with_adaptive_backoff(mut self, enabled: bool) -> Self {
        self.adaptive_backoff = enabled;
        self
    }

    /// Skip partial replay for bodies cheaper than its bookkeeping. This affects
    /// scheduling only; use zero to exercise all reuse paths in differential tests.
    pub fn with_minimum_body_duration(mut self, duration: Duration) -> Self {
        self.minimum_body_duration = duration;
        self
    }

    /// Allow ordered execution to overlap workers. Disabling this keeps a frozen
    /// batch for differential coverage of maximal conflicts and scheduling comparisons.
    pub fn with_streaming(mut self, enabled: bool) -> Self {
        self.streaming = enabled;
        self
    }

    /// Rebase explicitly recorded, unobserved fee updates. Disable for comparisons
    /// that require all fee conflicts to use ordinary replay.
    pub fn with_fee_rebasing(mut self, enabled: bool) -> Self {
        self.fee_rebasing = enabled;
        self
    }

    /// Let each worker carry earlier speculative writes into later transactions
    /// from the same payer. Every resulting read still requires ordered validation.
    pub fn with_chained_workers(mut self, enabled: bool) -> Self {
        self.chained_workers = enabled;
        self
    }

    /// Forward completed predecessor predictions for likely native dependencies.
    /// Every actual read still requires validation against the ordered prefix.
    pub fn with_state_forwarding(mut self, enabled: bool) -> Self {
        self.state_forwarding = enabled;
        self
    }

    pub(crate) const fn adaptive_backoff(&self) -> bool {
        self.adaptive_backoff
    }

    pub(crate) fn thread_pool(&self) -> Arc<ThreadPool> {
        self.pool.clone()
    }

    /// Maximum speculative lookahead. Memory usage is bounded by this window.
    pub const fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Candidates dispatched across all EVMs sharing this pool, including work
    /// later cancelled or replayed. Useful for checking that an integration is
    /// actually exercising workers rather than falling back to sequential EVMs.
    pub fn scheduled_transactions(&self) -> u64 {
        self.scheduled_transactions.load(Ordering::Relaxed)
    }

    /// Successful ordered reuses of results produced by builder prewarming.
    pub fn prewarmed_reuses(&self) -> u64 {
        self.prewarmed_reuses.load(Ordering::Relaxed)
    }

    pub(crate) fn record_prewarmed_reuse(&self) {
        self.prewarmed_reuses.fetch_add(1, Ordering::Relaxed);
    }

    /// Starts a bounded batch without committing any writes to `db`.
    ///
    /// Each input has its own block context and fee recipient.
    /// The owner retrieves results in input order and serves worker reads while waiting.
    pub(crate) fn speculate<DB: Database>(
        &self,
        db: &mut DB,
        inputs: Vec<(TempoTxEnv, Env)>,
        mut prefetched: HashMap<ReadKey, ReadValue>,
    ) -> SpeculativeBatch<DB::Error> {
        assert!(inputs.len() <= self.batch_size);
        // Accounts named by the transaction can be loaded without waiting for a
        // worker round trip. This is only a cache hint: errors are observed by the
        // actual read, and accesses are recorded even when they hit this map.
        let mut plan = tempo_revm::replay::PrefetchPlan::default();
        for (tx, env) in &inputs {
            for key in std::iter::once(tx.inner.caller)
                .chain(tx.calls().filter_map(|(kind, _)| kind.to().copied()))
                .map(ReadKey::Account)
            {
                prefetch(db, &mut prefetched, key);
            }
            plan.visit(tx, env.block_env.beneficiary, env.cfg_env.spec, |key| {
                prefetch(db, &mut prefetched, key);
            });
        }
        let count = inputs.len();
        self.scheduled_transactions
            .fetch_add(count as u64, Ordering::Relaxed);
        let mut nonce_ptrs = vec![None; count];
        if self.nonce_prediction {
            let mut next_ptr = None;
            for (index, (tx, env)) in inputs.iter().enumerate() {
                if !env.cfg_env.spec.is_t1()
                    || !tx
                        .tempo_tx_env
                        .as_ref()
                        .is_some_and(|aa| aa.nonce_key == U256::MAX)
                {
                    continue;
                }
                let ptr = match next_ptr {
                    Some(ptr) => ptr,
                    None => {
                        prefetch(
                            db,
                            &mut prefetched,
                            ReadKey::Account(NONCE_PRECOMPILE_ADDRESS),
                        );
                        let Some(ReadValue::Storage(value)) =
                            prefetch(db, &mut prefetched, nonce_ptr_key())
                        else {
                            continue;
                        };
                        let Ok(ptr) = u32::try_from(*value) else {
                            continue;
                        };
                        ptr
                    }
                };
                let capacity = env.cfg_env.spec.expiring_nonce_set_capacity();
                if ptr >= capacity {
                    continue;
                }
                // The predicted slot is cheap to prefetch and otherwise requires
                // a coordinator round trip for nearly every expiring transaction.
                if let Some(ReadValue::Storage(old_hash)) = prefetch(
                    db,
                    &mut prefetched,
                    ReadKey::Storage(
                        NONCE_PRECOMPILE_ADDRESS,
                        ptr.mapping_slot(nonce_slots::EXPIRING_NONCE_RING),
                    ),
                ) && !old_hash.is_zero()
                {
                    let old_hash = B256::from(*old_hash);
                    prefetch(
                        db,
                        &mut prefetched,
                        ReadKey::Storage(
                            NONCE_PRECOMPILE_ADDRESS,
                            old_hash.mapping_slot(nonce_slots::EXPIRING_NONCE_SEEN),
                        ),
                    );
                }
                nonce_ptrs[index] = Some(U256::from(ptr));
                next_ptr = Some(if ptr + 1 == capacity { 0 } else { ptr + 1 });
            }
        }
        let forwarding = self
            .state_forwarding
            .then(|| forwarding::Forwarding::new(&inputs));
        let shared = Arc::new(Work {
            inputs,
            nonce_ptrs,
            prefetched,
            cache: RwLock::new(HashMap::default()),
            next: AtomicUsize::new(0),
            cancelled: AtomicBool::new(false),
            forwarding,
        });
        let (sender, receiver) = mpsc::channel();
        let workers = count.min(self.pool.current_num_threads());
        let mut lanes = vec![Vec::new(); workers];
        let mut chained_workers = false;
        if self.chained_workers && shared.forwarding.is_none() {
            let mut payers: HashMap<Address, usize> = HashMap::default();
            for (index, (tx, _)) in shared.inputs.iter().enumerate() {
                let next_lane = payers.len() % workers;
                let lane = *payers
                    .entry(tx.fee_payer().unwrap_or(tx.inner.caller))
                    .or_insert(next_lane);
                lanes[lane].push(index);
            }
            // Independent payers need neither a private write overlay nor fixed
            // assignment. Preserve dynamic worker balancing for those windows.
            chained_workers = payers.len() < count;
        }
        let mut batch = SpeculativeBatch {
            shared: shared.clone(),
            receiver,
            outputs: (0..count).map(|_| None).collect(),
            cursor: 0,
            workers,
        };
        for lane in lanes {
            let sender = sender.clone();
            let shared = shared.clone();
            let minimum_body_duration = self.minimum_body_duration;
            let fee_rebasing = self.fee_rebasing;
            let indices = chained_workers.then_some(lane);
            self.pool.spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_worker(
                        &shared,
                        &sender,
                        minimum_body_duration,
                        fee_rebasing,
                        indices,
                    );
                }));
                drop(shared);
                // Catch worker panics before leaving Rayon. The owning coordinator
                // propagates them after releasing other workers, including on unwind.
                let _ = sender.send(Message::Stopped(result.err()));
            });
        }
        drop(sender);
        if !self.streaming {
            batch.complete(db);
        }
        batch
    }
}

pub(crate) fn nonce_is_stale<DB: Database>(
    db: &mut DB,
    cache: &mut HashMap<ReadKey, ReadValue>,
    hint: Option<(ReadKey, u64)>,
    disable_nonce_check: bool,
) -> bool {
    let Some((key, bound)) = hint else {
        return false;
    };
    if let ReadKey::Storage(address, _) = key {
        prefetch(db, cache, ReadKey::Account(address));
    }
    // Do not synthesize an error or change authoritative selection. The ordinary
    // EVM still validates omitted candidates, even if their nonce changes later.
    // Malformed uint64 words and provider errors must not panic or be truncated.
    matches!(prefetch(db, cache, key), Some(ReadValue::Storage(value))
        if !disable_nonce_check && u64::try_from(*value).is_ok_and(|value| value > bound))
}

fn prefetch<'a, DB: Database>(
    db: &mut DB,
    cache: &'a mut HashMap<ReadKey, ReadValue>,
    key: ReadKey,
) -> Option<&'a ReadValue> {
    use std::collections::hash_map::Entry;
    match cache.entry(key) {
        Entry::Occupied(entry) => Some(entry.into_mut()),
        Entry::Vacant(entry) => read(db, key).ok().map(|value| &*entry.insert(value)),
    }
}

#[derive(Debug)]
struct Work {
    inputs: Vec<(TempoTxEnv, Env)>,
    nonce_ptrs: Vec<Option<U256>>,
    prefetched: HashMap<ReadKey, ReadValue>,
    cache: RwLock<HashMap<ReadKey, ReadValue>>,
    next: AtomicUsize,
    cancelled: AtomicBool,
    forwarding: Option<forwarding::Forwarding>,
}

/// Account removal after journal finalization, matching revm `State` commits.
/// Pre-EIP-161 journals preserve empty accounts through their status flags.
fn account_is_removed(account: &reth_revm::state::Account) -> bool {
    account.is_touched()
        && (account.is_selfdestructed() || (!account.is_created() && account.is_empty()))
}

fn commit_prediction<DB>(overlay: &mut CacheDB<DB>, state: &reth_revm::state::EvmState) {
    overlay.commit_iter(&mut state.iter().filter_map(|(&address, account)| {
        if !account.is_touched() {
            return None;
        }
        let mut prediction = account.clone();
        // CacheDB does not implement EIP-161 clearing. Its selfdestruct path
        // has the required account/storage removal semantics for this private
        // copy; the actual execution result retains its original status flags.
        if account_is_removed(account) {
            prediction.mark_selfdestruct();
        } else if account.is_loaded_as_not_existing() {
            // A balance transfer can revive a previously deleted account
            // without CREATE. CacheDB would forget that its parent storage is
            // gone; preserve that known-zero storage using its created path.
            prediction.mark_created();
        }
        Some((address, prediction))
    }));
}

fn run_worker<E: DBErrorMarker>(
    shared: &Work,
    sender: &mpsc::Sender<Message<E>>,
    minimum_body_duration: Duration,
    fee_rebasing: bool,
    indices: Option<Vec<usize>>,
) {
    let db = RecordingDatabase {
        remote: RemoteDatabase {
            sender: sender.clone(),
            shared,
        },
        overlay: indices.as_ref().map(|_| {
            CacheDB::new(RemoteDatabase {
                sender: sender.clone(),
                shared,
            })
        }),
        reads: Vec::new(),
        body_reads: Vec::new(),
        forwarded: None,
        predicted_nonce_ptr: None,
    };
    let mut indices = indices.map(Vec::into_iter);
    let mut evm = TempoEvm::new(db, shared.inputs[0].1.clone());
    evm.inner_mut().enable_body_recording(minimum_body_duration);
    let mut standard_fee_gas = fee_rebasing
        && evm.ctx().cfg.gas_params == tempo_revm::gas_params::tempo_gas_params(evm.ctx().cfg.spec);
    while !shared.cancelled.load(Ordering::Relaxed) {
        let index = if let Some(forwarding) = &shared.forwarding {
            let Some(index) = forwarding.next(&shared.cancelled) else {
                break;
            };
            evm.ctx_mut().journaled_state.database.forwarded =
                Some(forwarding.seed(index, &shared.prefetched));
            index
        } else {
            match &mut indices {
                Some(indices) => match indices.next() {
                    Some(index) => index,
                    None => break,
                },
                None => shared.next.fetch_add(1, Ordering::Relaxed),
            }
        };
        let Some((tx, env)) = shared.inputs.get(index) else {
            break;
        };
        evm.ctx_mut().journaled_state.database.predicted_nonce_ptr = shared.nonce_ptrs[index];
        if evm.ctx().cfg != env.cfg_env {
            let (db, _) = evm.finish();
            evm = TempoEvm::new(db, env.clone());
            evm.inner_mut().enable_body_recording(minimum_body_duration);
            standard_fee_gas = fee_rebasing
                && env.cfg_env.gas_params
                    == tempo_revm::gas_params::tempo_gas_params(env.cfg_env.spec);
        } else {
            evm.ctx_mut().block = env.block_env.clone();
        }
        // Standard protocol fee hooks use maximum gas, discard gas/refunds,
        // and explicitly disable T7 storage-credit accounting. Their annotated
        // arithmetic can be rebased when the body never observes those slots.
        // Keep state-gas splitting on ordinary replay until separately proven.
        let record_fees = standard_fee_gas
            && !env.cfg_env.enable_amsterdam_eip8037
            && tx.calls().all(|(kind, _)| kind.is_call());
        let native_target = native_rebase::target(tx, env);
        let execute = || {
            if record_fees {
                fee_updates::record(|| evm.transact_raw(tx.clone()))
            } else {
                (evm.transact_raw(tx.clone()), Vec::new())
            }
        };
        let ((result, fee_updates), native_increment) = if let Some(target) = native_target {
            native_increment::record(target, execute)
        } else {
            let mut execute = execute;
            (execute(), None)
        };
        let result = match result {
            Err(EVMError::Database(ProxyError::Cancelled)) => break,
            result => result.map_err(|error| {
                error.map_db_err(|error| match error {
                    ProxyError::Provider(error) => error,
                    ProxyError::Cancelled => unreachable!("handled cancellation"),
                })
            }),
        };
        let reads = std::mem::take(&mut evm.ctx_mut().journaled_state.database.reads);
        let native_increment =
            native_rebase::certify(native_increment, result.as_ref().ok(), &reads, &fee_updates);
        let body_reads = std::mem::take(&mut evm.ctx_mut().journaled_state.database.body_reads);
        let mut body = evm.inner_mut().take_recorded_body();
        if let Some(body) = &mut body {
            body.set_database_reads(body_reads);
        }
        if let Ok(result) = &result
            && let Some(overlay) = &mut evm.ctx_mut().journaled_state.database.overlay
        {
            // This is a private prediction, not an authoritative commit. Reads
            // served from it are recorded by the outer database just like remote
            // reads, so any skipped, failed or conflicting predecessor is checked
            // against the real committed prefix before a later result is reused.
            commit_prediction(overlay, &result.state);
        }
        if let Some(forwarding) = &shared.forwarding {
            forwarding.complete(
                index,
                result.as_ref().ok().map(|result| &result.state),
                evm.ctx()
                    .journaled_state
                    .database
                    .forwarded
                    .as_ref()
                    .expect("forwarded seed"),
            );
        }
        let _ = sender.send(Message::Finished(
            index,
            Box::new(SpeculativeResult {
                env: env.clone(),
                validator_fee: evm.validator_fee(),
                reads,
                result,
                body,
                fee_updates,
                fees_rebased: false,
                native_increment,
                native_rebased: false,
                conflict: None,
            }),
        ));
    }
}

fn transactions_match(candidate: &TempoTxEnv, tx: &TempoTxEnv) -> bool {
    candidate == tx
        && candidate
            .tempo_tx_env
            .as_ref()
            .zip(tx.tempo_tx_env.as_ref())
            .is_none_or(|(a, b)| {
                a.tempo_authorization_list
                    .iter()
                    .zip(&b.tempo_authorization_list)
                    .all(|(a, b)| a.authority_status() == b.authority_status())
            })
}

/// Bounded in-flight work. Only this owner accesses the database. Reads served
/// after a commit may see a newer prefix than prefetched values; every recorded
/// value must still match the actual transaction's prefix before reuse.
/// An inconsistent speculative view therefore causes replay, never a commit.
pub(crate) struct SpeculativeBatch<E> {
    shared: Arc<Work>,
    receiver: mpsc::Receiver<Message<E>>,
    outputs: Vec<Option<SpeculativeResult<E>>>,
    cursor: usize,
    workers: usize,
}

impl<E> std::fmt::Debug for SpeculativeBatch<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpeculativeBatch")
            .field("candidates", &self.outputs.len())
            .field("cursor", &self.cursor)
            .field("workers", &self.workers)
            .finish()
    }
}

impl<E: DBErrorMarker> SpeculativeBatch<E> {
    pub(crate) fn is_empty(&self) -> bool {
        self.cursor == self.shared.inputs.len()
    }

    fn receive<DB: Database<Error = E>>(&mut self, db: &mut DB) {
        match self
            .receiver
            .recv()
            .expect("workers stopped without reporting completion")
        {
            Message::Read(key, response) => {
                let cached = self
                    .shared
                    .cache
                    .read()
                    .expect("read cache poisoned")
                    .get(&key)
                    .cloned();
                let value = cached.map(Ok).unwrap_or_else(|| read(db, key));
                if let Ok(value) = &value {
                    self.shared
                        .cache
                        .write()
                        .expect("read cache poisoned")
                        .insert(key, value.clone());
                }
                let _ = response.send(value);
            }
            Message::Finished(index, result) => {
                if index >= self.cursor {
                    self.outputs[index] = Some(*result);
                }
            }
            Message::Stopped(panic) => {
                self.workers -= 1;
                if let Some(panic) = panic {
                    std::panic::resume_unwind(panic);
                }
            }
        }
    }

    fn complete<DB: Database<Error = E>>(&mut self, db: &mut DB) {
        while self.workers > 0 {
            self.receive(db);
        }
    }

    pub(crate) fn take<DB: Database<Error = E>>(
        &mut self,
        tx: &TempoTxEnv,
        db: &mut DB,
    ) -> Option<SpeculativeResult<E>> {
        let index = self.shared.inputs[self.cursor..]
            .iter()
            .position(|(candidate, _)| transactions_match(candidate, tx))?
            + self.cursor;
        for skipped in self.cursor..index {
            self.outputs[skipped] = None;
        }
        self.cursor = index;
        while self.outputs[index].is_none() {
            assert!(self.workers > 0, "worker did not return a result");
            self.receive(db);
        }
        self.cursor = index + 1;
        self.outputs[index].take()
    }
}

impl<E> Drop for SpeculativeBatch<E> {
    fn drop(&mut self) {
        self.shared.cancelled.store(true, Ordering::Relaxed);
        if let Some(forwarding) = &self.shared.forwarding {
            forwarding.cancel();
        }
        // Closing replies wakes workers waiting for DB reads. Join even on unwind,
        // so replacing or abandoning batches cannot accumulate background work.
        while self.workers > 0 {
            match self.receiver.recv() {
                Ok(Message::Stopped(_)) => self.workers -= 1,
                Ok(message) => drop(message),
                Err(_) => break,
            }
        }
    }
}

/// Per-EVM counters. Speculation is never reported as committed work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutionStats {
    /// Candidates scheduled on workers, including speculative failures and cancelled work.
    pub speculated: u64,
    /// Candidates left for ordinary execution because the nonce hint was stale.
    pub nonce_filtered: u64,
    /// Successful speculative results reused after validating their reads.
    pub reused: u64,
    /// Call bodies reused after rerunning validation and pre-execution in order.
    pub bodies_reused: u64,
    /// Full results reused after rebasing explicit fee-only arithmetic.
    pub fees_rebased: u64,
    /// Full results reused after rebasing a certified native custody increment.
    pub native_rebased: u64,
    /// Candidates replayed after their state dependencies changed.
    pub conflicts: u64,
    /// Conflicts on account metadata, bytecode, or block hashes.
    pub metadata_conflicts: u64,
    /// Conflicts on the expiring-nonce ring pointer prediction.
    pub nonce_pointer_conflicts: u64,
    /// Conflicts on other nonce-precompile storage.
    pub nonce_conflicts: u64,
    /// Conflicts on ordinary storage outside the nonce precompile.
    pub storage_conflicts: u64,
    /// Fee patches rejected by journal or arithmetic checks.
    pub fee_conflicts: u64,
    /// Provider errors during read validation, retried by ordinary execution.
    pub validation_errors: u64,
    /// Speculative errors retried against the committed prefix.
    pub retries: u64,
    /// Transactions executed sequentially while the scheduler backs off.
    pub backoff: u64,
}

#[derive(Debug)]
pub(crate) struct SpeculativeResult<E> {
    pub(crate) env: Env,
    reads: Vec<(ReadKey, ReadValue)>,
    pub(crate) result: Outcome<E>,
    pub(crate) validator_fee: U256,
    pub(crate) body: Option<BodyCache>,
    fee_updates: Vec<FeeUpdate>,
    pub(crate) fees_rebased: bool,
    native_increment: Option<NativeIncrementWitness>,
    pub(crate) native_rebased: bool,
    pub(crate) conflict: Option<ConflictKind>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ConflictKind {
    Metadata,
    NoncePointer,
    Nonce,
    Storage,
    Fee,
}

impl<E: DBErrorMarker> SpeculativeResult<E> {
    fn conflict(
        conflict: &mut Option<ConflictKind>,
        key: &ReadKey,
        reason: &'static str,
        fee: bool,
    ) -> bool {
        *conflict = Some(if fee {
            ConflictKind::Fee
        } else {
            match key {
                ReadKey::Storage(address, slot) if *address == NONCE_PRECOMPILE_ADDRESS => {
                    if *slot == nonce_slots::EXPIRING_NONCE_RING_PTR {
                        ConflictKind::NoncePointer
                    } else {
                        ConflictKind::Nonce
                    }
                }
                ReadKey::Storage(..) => ConflictKind::Storage,
                _ => ConflictKind::Metadata,
            }
        });
        tracing::trace!(target: "tempo::execution::conflicts", ?key, reason, "Replaying state conflict");
        false
    }

    /// Read values, rather than touched addresses, determine dependencies. Two transfers
    /// touching distinct balances in the same TIP-20 therefore need not conflict.
    pub(crate) fn validate<DB: Database<Error = E>>(&mut self, db: &mut DB) -> Result<bool, E> {
        self.validate_with(|reads| {
            for (offset, (key, expected)) in reads.iter().enumerate() {
                let actual = read(db, *key)?;
                if matches!((key, expected), (ReadKey::Account(_), ReadValue::Account(Some(info))) if info.account_id.is_some())
                    || actual != *expected
                {
                    return Ok(Some((offset, actual)));
                }
            }
            Ok(None)
        })
    }

    /// Both validators use identical dependency checks and defer all patches
    /// until every read validates. The matcher scans in order and stops at the
    /// first difference, so arithmetic validation precedes any later database reads.
    fn validate_with(
        &mut self,
        mut first_difference: impl FnMut(
            &[(ReadKey, ReadValue)],
        ) -> Result<Option<(usize, ReadValue)>, E>,
    ) -> Result<bool, E> {
        let mut patches = Vec::new();
        let mut native_patch = None;
        let mut remaining = self.reads.as_slice();
        while let Some((offset, actual)) = first_difference(remaining)? {
            let (key, expected) = &remaining[offset];
            remaining = &remaining[offset + 1..];
            let (ReadKey::Storage(address, slot), ReadValue::Storage(old), ReadValue::Storage(new)) =
                (key, expected, actual)
            else {
                return Ok(Self::conflict(
                    &mut self.conflict,
                    key,
                    "account, code or block hash",
                    false,
                ));
            };
            if let Some(witness) = self.native_increment.as_ref().filter(|witness| {
                witness.target.address == *address && witness.target.slot == *slot
            }) {
                if *old != witness.original
                    || !self
                        .result
                        .as_ref()
                        .is_ok_and(|result| native_rebase::matches_result(witness, result))
                {
                    return Ok(Self::conflict(
                        &mut self.conflict,
                        key,
                        "native increment journal mismatch",
                        false,
                    ));
                }
                let Some(present) = witness.rebase(new) else {
                    return Ok(Self::conflict(
                        &mut self.conflict,
                        key,
                        "native increment gas class or overflow",
                        false,
                    ));
                };
                native_patch = Some((*address, *slot, new, present));
                continue;
            }
            let Some(update) = self
                .fee_updates
                .iter()
                .find(|update| update.address == *address && update.slot == *slot)
            else {
                tracing::trace!(target: "tempo::execution::conflicts", ?key, expected = %old, actual = %new, "Storage values differ");
                return Ok(Self::conflict(
                    &mut self.conflict,
                    key,
                    "ordinary storage",
                    false,
                ));
            };
            let Some(account) = self
                .result
                .as_ref()
                .ok()
                .and_then(|result| result.state.get(address))
            else {
                return Ok(Self::conflict(
                    &mut self.conflict,
                    key,
                    "missing result account",
                    true,
                ));
            };
            let Some(storage) = account.storage.get(slot) else {
                return Ok(Self::conflict(
                    &mut self.conflict,
                    key,
                    "missing result storage",
                    true,
                ));
            };
            if account.is_created()
                || account.is_selfdestructed()
                || storage.original_value != *old
                || update.apply(*old) != Some(storage.present_value)
            {
                return Ok(Self::conflict(
                    &mut self.conflict,
                    key,
                    "fee journal mismatch",
                    true,
                ));
            }
            let Some(present) = update.apply(new) else {
                // Including intermediate maximum-fee overflow: the ordinary
                // executor must produce the canonical error or result.
                return Ok(Self::conflict(
                    &mut self.conflict,
                    key,
                    "fee arithmetic overflow",
                    true,
                ));
            };
            patches.push((*address, *slot, new, present));
        }
        // All dependency and arithmetic checks precede mutations. Preserve every
        // other account field, storage slot, receipt, log and gas value.
        self.fees_rebased = !patches.is_empty();
        self.native_rebased = native_patch.is_some();
        if let Ok(result) = &mut self.result {
            for (address, slot, original, present) in patches.into_iter().chain(native_patch) {
                let storage = result
                    .state
                    .get_mut(&address)
                    .expect("checked account")
                    .storage
                    .get_mut(&slot)
                    .expect("checked slot");
                storage.original_value = original;
                storage.present_value = present;
            }
        }
        Ok(true)
    }
}

enum Message<E> {
    Read(ReadKey, mpsc::SyncSender<Result<ReadValue, E>>),
    Finished(usize, Box<SpeculativeResult<E>>),
    Stopped(Option<Box<dyn std::any::Any + Send>>),
}

#[derive(Debug, thiserror::Error)]
enum ProxyError<E> {
    #[error(transparent)]
    Provider(E),
    #[error("speculative batch cancelled")]
    Cancelled,
}
impl<E: DBErrorMarker> DBErrorMarker for ProxyError<E> {}

#[derive(Debug)]
struct RecordingDatabase<'a, E> {
    remote: RemoteDatabase<'a, E>,
    overlay: Option<CacheDB<RemoteDatabase<'a, E>>>,
    reads: Vec<(ReadKey, ReadValue)>,
    body_reads: Vec<(ReadKey, ReadValue)>,
    forwarded: Option<HashMap<ReadKey, ReadValue>>,
    predicted_nonce_ptr: Option<U256>,
}

fn nonce_ptr_key() -> ReadKey {
    ReadKey::Storage(
        NONCE_PRECOMPILE_ADDRESS,
        nonce_slots::EXPIRING_NONCE_RING_PTR,
    )
}

impl<E: DBErrorMarker> RecordingDatabase<'_, E> {
    fn read(&mut self, key: ReadKey) -> Result<ReadValue, ProxyError<E>> {
        if self.remote.shared.cancelled.load(Ordering::Relaxed) {
            return Err(ProxyError::Cancelled);
        }
        let start = tempo_revm::replay::is_recording_body().then(std::time::Instant::now);
        // This prediction only supplies a worker's read. It is recorded below,
        // including body reads, and receives ordinary exact read validation.
        // Rejected or omitted predecessors therefore cause replay, never a commit
        // based on the wrong ring position. Override stale private lane caches too.
        let value = if key == nonce_ptr_key()
            && let Some(ptr) = self.predicted_nonce_ptr
        {
            ReadValue::Storage(ptr)
        } else if let Some(value) = self.forwarded.as_ref().and_then(|values| values.get(&key)) {
            value.clone()
        } else {
            match &mut self.overlay {
                Some(overlay) => read(overlay, key)?,
                None => self.remote.read(key)?,
            }
        };
        self.reads.push((key, value.clone()));
        if let Some(start) = start {
            self.body_reads.push((key, value.clone()));
            tempo_revm::replay::record_database_time(start.elapsed());
        }
        Ok(value)
    }
}

#[derive(Debug)]
struct RemoteDatabase<'a, E> {
    sender: mpsc::Sender<Message<E>>,
    shared: &'a Work,
}

impl<E> RemoteDatabase<'_, E> {
    fn read(&self, key: ReadKey) -> Result<ReadValue, ProxyError<E>> {
        // Release the read lock before waiting for the coordinator to populate it.
        let cached = self.shared.prefetched.get(&key).cloned().or_else(|| {
            self.shared
                .cache
                .read()
                .expect("read cache poisoned")
                .get(&key)
                .cloned()
        });
        let value = if let Some(value) = cached {
            value
        } else {
            tracing::trace!(target: "tempo::execution::reads", ?key, "Worker database cache miss");
            let (sender, receiver) = mpsc::sync_channel(1);
            self.sender
                .send(Message::Read(key, sender))
                .map_err(|_| ProxyError::Cancelled)?;
            receiver
                .recv()
                .map_err(|_| ProxyError::Cancelled)?
                .map_err(ProxyError::Provider)?
        };
        Ok(value)
    }
}

impl<E: DBErrorMarker> DatabaseRef for RemoteDatabase<'_, E> {
    type Error = ProxyError<E>;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let ReadValue::Account(info) = self.read(ReadKey::Account(address))? else {
            unreachable!()
        };
        Ok(info)
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        let ReadValue::Storage(value) = self.read(ReadKey::Storage(address, slot))? else {
            unreachable!()
        };
        Ok(value)
    }

    fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
        let ReadValue::Code(code) = self.read(ReadKey::Code(hash))? else {
            unreachable!()
        };
        Ok(code)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let ReadValue::BlockHash(hash) = self.read(ReadKey::BlockHash(number))? else {
            unreachable!()
        };
        Ok(hash)
    }
}

impl<E: DBErrorMarker> reth_revm::Database for RecordingDatabase<'_, E> {
    type Error = ProxyError<E>;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let ReadValue::Account(info) = self.read(ReadKey::Account(address))? else {
            unreachable!()
        };
        Ok(info)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        tempo_precompiles::storage::access::storage(address, slot);
        let ReadValue::Storage(value) = self.read(ReadKey::Storage(address, slot))? else {
            unreachable!()
        };
        Ok(value)
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        let ReadValue::Code(code) = self.read(ReadKey::Code(hash))? else {
            unreachable!()
        };
        Ok(code)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        let ReadValue::BlockHash(hash) = self.read(ReadKey::BlockHash(number))? else {
            unreachable!()
        };
        Ok(hash)
    }
}

#[cfg(test)]
mod tests;
