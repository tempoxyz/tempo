//! Ordered optimistic execution for Tempo transactions.
//!
//! Workers execute against an immutable view of the state at the beginning of a batch.
//! The database stays on its owning thread: cache misses are served by the coordinator,
//! so even providers that are neither `Send` nor `Sync` are supported without unsafe code.
//! Every database read (including reads in reverted calls and transaction validation) is
//! recorded. A result may be reused only after validating those reads against the state
//! produced by the committed prefix. Otherwise the ordinary EVM replays the transaction,
//! optionally reusing a separately validated call body while rerunning fee processing.
//!
//! This deliberately treats shared fee counters as dependencies. Making fee updates
//! commute requires a separate proof covering overflow, gas, logs and contract reads.

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
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;
use tempo_chainspec::hardfork::TempoHardfork;
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
        })
    }

    /// Controls periodic sequential backoff when fewer than one eighth of a window's
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

    pub(crate) const fn adaptive_backoff(&self) -> bool {
        self.adaptive_backoff
    }

    /// Maximum speculative lookahead. Memory usage is bounded by this window.
    pub const fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Executes a bounded batch without committing any writes to `db`.
    ///
    /// Each input has its own block context, including the subblock fee recipient.
    /// The returned results are in input order, independent of worker completion order.
    pub(crate) fn speculate<DB: Database>(
        &self,
        db: &mut DB,
        inputs: Vec<(TempoTxEnv, Env)>,
    ) -> Vec<SpeculativeResult<DB::Error>> {
        assert!(inputs.len() <= self.batch_size);
        let count = inputs.len();
        if count == 0 {
            return Vec::new();
        }
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
        let cache = RwLock::new(HashMap::default());
        let next = AtomicUsize::new(0);
        let (sender, receiver) = mpsc::channel();
        let mut outputs: Vec<_> = (0..count).map(|_| None).collect();

        // Unlike `scope`, `in_place_scope` does not require moving the coordinator
        // closure (or its database) to the pool.
        self.pool.in_place_scope(|scope| {
            // Drop pending response senders before the scope joins workers if a
            // provider panics while serving a read.
            let receiver = receiver;
            for _ in 0..count.min(self.pool.current_num_threads()) {
                let sender = sender.clone();
                let cache = &cache;
                let prefetched = &prefetched;
                let inputs = &inputs;
                let next = &next;
                scope.spawn(move |_| {
                    let db = RecordingDatabase {
                        sender: sender.clone(),
                        cache,
                        prefetched,
                        reads: Vec::new(),
                        body_reads: Vec::new(),
                    };
                    let mut evm = TempoEvm::new(db, inputs[0].1.clone());
                    evm.inner_mut()
                        .enable_body_recording(self.minimum_body_duration);
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some((tx, env)) = inputs.get(index) else {
                            break;
                        };
                        if evm.ctx().cfg != env.cfg_env {
                            let (db, _) = evm.finish();
                            evm = TempoEvm::new(db, env.clone());
                            evm.inner_mut()
                                .enable_body_recording(self.minimum_body_duration);
                        } else {
                            evm.ctx_mut().block = env.block_env.clone();
                        }
                        let result = evm.transact_raw(tx.clone());
                        let reads =
                            std::mem::take(&mut evm.ctx_mut().journaled_state.database.reads);
                        let body_reads =
                            std::mem::take(&mut evm.ctx_mut().journaled_state.database.body_reads);
                        let mut body = evm.inner_mut().take_recorded_body();
                        if let Some(body) = &mut body {
                            body.set_database_reads(body_reads);
                        }
                        // A panic drops this worker's senders. The receiver can
                        // terminate and the scope propagates the panic.
                        let _ = sender.send(Message::Finished(
                            index,
                            Box::new(SpeculativeResult {
                                tx: tx.clone(),
                                env: env.clone(),
                                reads,
                                result,
                                body,
                            }),
                        ));
                    }
                });
            }
            drop(sender);
            while let Ok(message) = receiver.recv() {
                match message {
                    Message::Read(key, response) => {
                        let cached = cache
                            .read()
                            .expect("read cache poisoned")
                            .get(&key)
                            .cloned();
                        let value = cached.map(Ok).unwrap_or_else(|| read(db, key));
                        if let Ok(value) = &value {
                            cache
                                .write()
                                .expect("read cache poisoned")
                                .insert(key, value.clone());
                        }
                        let _ = response.send(value);
                    }
                    Message::Finished(index, result) => outputs[index] = Some(*result),
                }
            }
        });
        outputs
            .into_iter()
            .map(|output| output.expect("worker did not return a result"))
            .collect()
    }
}

/// Per-EVM counters. Speculation is never reported as committed work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutionStats {
    /// Transactions executed by workers, including speculative failures.
    pub speculated: u64,
    /// Successful speculative results reused after validating their reads.
    pub reused: u64,
    /// Call bodies reused after rerunning validation and pre-execution in order.
    pub bodies_reused: u64,
    /// Candidates replayed after their state dependencies changed.
    pub conflicts: u64,
    /// Speculative errors retried against the committed prefix.
    pub retries: u64,
    /// Transactions executed sequentially while the scheduler backs off.
    pub backoff: u64,
}

#[derive(Debug)]
pub(crate) struct SpeculativeResult<E> {
    pub(crate) tx: TempoTxEnv,
    pub(crate) env: Env,
    reads: Vec<(ReadKey, ReadValue)>,
    pub(crate) result: Outcome<E>,
    pub(crate) body: Option<BodyCache>,
}

impl<E: DBErrorMarker> SpeculativeResult<E> {
    /// Read values, rather than touched addresses, determine dependencies. Two transfers
    /// touching distinct balances in the same TIP-20 therefore need not conflict.
    pub(crate) fn validate<DB: Database<Error = E>>(&self, db: &mut DB) -> Result<bool, E> {
        for (key, expected) in &self.reads {
            if read(db, *key)? != *expected {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Debug)]
enum Message<E> {
    Read(ReadKey, mpsc::SyncSender<Result<ReadValue, E>>),
    Finished(usize, Box<SpeculativeResult<E>>),
}

#[derive(Debug)]
struct RecordingDatabase<'a, E> {
    sender: mpsc::Sender<Message<E>>,
    cache: &'a RwLock<HashMap<ReadKey, ReadValue>>,
    prefetched: &'a HashMap<ReadKey, ReadValue>,
    reads: Vec<(ReadKey, ReadValue)>,
    body_reads: Vec<(ReadKey, ReadValue)>,
}

impl<E> RecordingDatabase<'_, E> {
    fn read(&mut self, key: ReadKey) -> Result<ReadValue, E> {
        let start = tempo_revm::replay::is_recording_body().then(std::time::Instant::now);
        // Release the read lock before waiting for the coordinator to populate it.
        let cached = self.prefetched.get(&key).cloned().or_else(|| {
            self.cache
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
                .unwrap_or_else(|_| panic!("database coordinator stopped"));
            receiver.recv().expect("database coordinator stopped")?
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
    type Error = E;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, E> {
        let ReadValue::Account(info) = self.read(ReadKey::Account(address))? else {
            unreachable!()
        };
        Ok(info)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, E> {
        let ReadValue::Storage(value) = self.read(ReadKey::Storage(address, slot))? else {
            unreachable!()
        };
        Ok(value)
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, E> {
        let ReadValue::Code(code) = self.read(ReadKey::Code(hash))? else {
            unreachable!()
        };
        Ok(code)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, E> {
        let ReadValue::BlockHash(hash) = self.read(ReadKey::BlockHash(number))? else {
            unreachable!()
        };
        Ok(hash)
    }
}

#[cfg(test)]
mod tests;
