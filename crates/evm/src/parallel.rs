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

use crate::{TempoBlockEnv, evm::TempoEvm};
use alloy_evm::{Database, Evm, EvmEnv};
use alloy_primitives::{Address, B256, U256, map::HashMap};
use rayon::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use reth_revm::{
    context::result::{EVMError, ResultAndState},
    database_interface::DBErrorMarker,
    state::{AccountInfo, Bytecode},
};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::storage::fee_updates::{self, FeeUpdate};
use tempo_revm::replay::{BodyCache, ReadKey, ReadValue, read};
use tempo_revm::{TempoHaltReason, TempoInvalidTransaction, TempoTxEnv};

type Env = EvmEnv<TempoHardfork, TempoBlockEnv>;
type Outcome<E> = Result<ResultAndState<TempoHaltReason>, EVMError<E, TempoInvalidTransaction>>;

/// A bounded worker pool shared by block executors and the payload builder.
#[derive(Clone, Debug)]
pub struct SpeculativeExecutor {
    pool: Arc<ThreadPool>,
    batch_size: usize,
    adaptive_backoff: bool,
    minimum_body_duration: Duration,
    streaming: bool,
    fee_rebasing: bool,
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
        })
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

    /// Starts a bounded batch without committing any writes to `db`.
    ///
    /// Each input has its own block context, including the subblock fee recipient.
    /// The owner retrieves results in input order and serves worker reads while waiting.
    pub(crate) fn speculate<DB: Database>(
        &self,
        db: &mut DB,
        inputs: Vec<(TempoTxEnv, Env)>,
    ) -> SpeculativeBatch<DB::Error> {
        assert!(inputs.len() <= self.batch_size);
        let count = inputs.len();
        // Accounts named by the transaction can be loaded without waiting for a
        // worker round trip. This is only a cache hint: errors are observed by the
        // actual read, and accesses are recorded even when they hit this map.
        let mut prefetched = HashMap::default();
        for (tx, env) in &inputs {
            for key in std::iter::once(tx.inner.caller)
                .chain(tx.calls().filter_map(|(kind, _)| kind.to().copied()))
                .map(ReadKey::Account)
                .chain(tempo_revm::replay::prefetch_keys(
                    tx,
                    env.block_env.beneficiary,
                ))
            {
                if let std::collections::hash_map::Entry::Vacant(entry) = prefetched.entry(key)
                    && let Ok(value) = read(db, key)
                {
                    entry.insert(value);
                }
            }
        }
        let shared = Arc::new(Work {
            inputs,
            prefetched,
            cache: RwLock::new(HashMap::default()),
            next: AtomicUsize::new(0),
            cancelled: AtomicBool::new(false),
        });
        let (sender, receiver) = mpsc::channel();
        let workers = count.min(self.pool.current_num_threads());
        let mut batch = SpeculativeBatch {
            shared: shared.clone(),
            receiver,
            outputs: (0..count).map(|_| None).collect(),
            cursor: 0,
            workers,
        };
        for _ in 0..workers {
            let sender = sender.clone();
            let shared = shared.clone();
            let minimum_body_duration = self.minimum_body_duration;
            let fee_rebasing = self.fee_rebasing;
            self.pool.spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_worker(&shared, &sender, minimum_body_duration, fee_rebasing);
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

#[derive(Debug)]
struct Work {
    inputs: Vec<(TempoTxEnv, Env)>,
    prefetched: HashMap<ReadKey, ReadValue>,
    cache: RwLock<HashMap<ReadKey, ReadValue>>,
    next: AtomicUsize,
    cancelled: AtomicBool,
}

fn run_worker<E: DBErrorMarker>(
    shared: &Work,
    sender: &mpsc::Sender<Message<E>>,
    minimum_body_duration: Duration,
    fee_rebasing: bool,
) {
    let db = RecordingDatabase {
        sender: sender.clone(),
        shared,
        reads: Vec::new(),
        body_reads: Vec::new(),
    };
    let mut evm = TempoEvm::new(db, shared.inputs[0].1.clone());
    evm.inner_mut().enable_body_recording(minimum_body_duration);
    let mut standard_fee_gas = fee_rebasing
        && evm.ctx().cfg.gas_params == tempo_revm::gas_params::tempo_gas_params(evm.ctx().cfg.spec);
    while !shared.cancelled.load(Ordering::Relaxed) {
        let index = shared.next.fetch_add(1, Ordering::Relaxed);
        let Some((tx, env)) = shared.inputs.get(index) else {
            break;
        };
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
        // Fee storage contexts use maximum gas and discard their gas/refund
        // accounting. Restrict rebasing to the standard, bounded gas schedules.
        let record_fees = standard_fee_gas && tx.calls().all(|(kind, _)| kind.is_call());
        let (result, fee_updates) = if record_fees {
            fee_updates::record(|| evm.transact_raw(tx.clone()))
        } else {
            (evm.transact_raw(tx.clone()), Vec::new())
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
        let body_reads = std::mem::take(&mut evm.ctx_mut().journaled_state.database.body_reads);
        let mut body = evm.inner_mut().take_recorded_body();
        if let Some(body) = &mut body {
            body.set_database_reads(body_reads);
        }
        let _ = sender.send(Message::Finished(
            index,
            Box::new(SpeculativeResult {
                env: env.clone(),
                reads,
                result,
                body,
                fee_updates,
                fees_rebased: false,
            }),
        ));
    }
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
            .position(|(candidate, _)| {
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
            })?
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
    /// Successful speculative results reused after validating their reads.
    pub reused: u64,
    /// Call bodies reused after rerunning validation and pre-execution in order.
    pub bodies_reused: u64,
    /// Full results reused after rebasing explicit fee-only arithmetic.
    pub fees_rebased: u64,
    /// Candidates replayed after their state dependencies changed.
    pub conflicts: u64,
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
    pub(crate) body: Option<BodyCache>,
    fee_updates: Vec<FeeUpdate>,
    pub(crate) fees_rebased: bool,
}

impl<E: DBErrorMarker> SpeculativeResult<E> {
    /// Read values, rather than touched addresses, determine dependencies. Two transfers
    /// touching distinct balances in the same TIP-20 therefore need not conflict.
    pub(crate) fn validate<DB: Database<Error = E>>(&mut self, db: &mut DB) -> Result<bool, E> {
        let mut patches = Vec::new();
        for (key, expected) in &self.reads {
            let actual = read(db, *key)?;
            if actual != *expected {
                let (
                    ReadKey::Storage(address, slot),
                    ReadValue::Storage(old),
                    ReadValue::Storage(new),
                ) = (key, expected, actual)
                else {
                    return Ok(false);
                };
                let Some(update) = self
                    .fee_updates
                    .iter()
                    .find(|update| update.address == *address && update.slot == *slot)
                else {
                    return Ok(false);
                };
                let Some(account) = self
                    .result
                    .as_ref()
                    .ok()
                    .and_then(|result| result.state.get(address))
                else {
                    return Ok(false);
                };
                let Some(storage) = account.storage.get(slot) else {
                    return Ok(false);
                };
                if account.is_created()
                    || account.is_selfdestructed()
                    || storage.original_value != *old
                    || update.apply(*old) != Some(storage.present_value)
                {
                    return Ok(false);
                }
                let Some(present) = update.apply(new) else {
                    // Including intermediate maximum-fee overflow: the ordinary
                    // executor must produce the canonical error or result.
                    return Ok(false);
                };
                patches.push((*address, *slot, new, present));
            }
        }
        // All dependency and arithmetic checks precede mutations. Preserve every
        // other account field, storage slot, receipt, log and gas value.
        self.fees_rebased = !patches.is_empty();
        if let Ok(result) = &mut self.result {
            for (address, slot, original, present) in patches {
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
    sender: mpsc::Sender<Message<E>>,
    shared: &'a Work,
    reads: Vec<(ReadKey, ReadValue)>,
    body_reads: Vec<(ReadKey, ReadValue)>,
}

impl<E> RecordingDatabase<'_, E> {
    fn read(&mut self, key: ReadKey) -> Result<ReadValue, ProxyError<E>> {
        if self.shared.cancelled.load(Ordering::Relaxed) {
            return Err(ProxyError::Cancelled);
        }
        let start = tempo_revm::replay::is_recording_body().then(std::time::Instant::now);
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
            let (sender, receiver) = mpsc::sync_channel(1);
            self.sender
                .send(Message::Read(key, sender))
                .map_err(|_| ProxyError::Cancelled)?;
            receiver
                .recv()
                .map_err(|_| ProxyError::Cancelled)?
                .map_err(ProxyError::Provider)?
        };
        self.reads.push((key, value.clone()));
        if let Some(start) = start {
            self.body_reads.push((key, value.clone()));
            tempo_revm::replay::record_database_time(start.elapsed());
        }
        Ok(value)
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
