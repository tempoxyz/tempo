use std::{
    cell::RefCell,
    sync::{
        Arc, Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use reth_engine_tree::tree::{CachedStateProvider, SavedCache};
use reth_evm::{Evm, EvmEnvFor};
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{EvmStateProviderBox, StateProvider, StateProviderFactory};
use reth_tasks::{TaskExecutor, WorkerPool};
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_evm::{
    ExpiringNonceReplay, StorageActionReplay, TempoEvmConfig,
    evm::TempoEvm,
    parallel::{PreexecutedTransaction, PrewarmingExecutor, PrewarmingState},
};
use tempo_transaction_pool::{StateAwarePoolTransaction, best::BestTransaction};
use tracing::{info, instrument, trace};

pub(crate) type PrewarmEvmState = Option<TempoEvm<StateProviderDatabase<EvmStateProviderBox>>>;
type SpeculativePrewarmState =
    Option<PrewarmingExecutor<StateProviderDatabase<EvmStateProviderBox>>>;

enum BuilderWorkerEvm {
    Regular(Box<PrewarmEvmState>),
    Speculative(Box<SpeculativePrewarmState>),
}

struct BuilderWorker {
    context: Arc<AtomicBool>,
    evm: BuilderWorkerEvm,
}

thread_local! {
    // Engine prewarming uses WorkerPool's separate Any slot on these same
    // threads. Keep one builder context here, replacing it on context switches.
    static BUILDER_WORKER: RefCell<Option<BuilderWorker>> = const { RefCell::new(None) };
}

/// Release providers on their owning workers, including when a scoped job panics.
struct BuilderWorkerCleanup<'a> {
    pool: &'a WorkerPool,
    context: Arc<AtomicBool>,
}

impl Drop for BuilderWorkerCleanup<'_> {
    fn drop(&mut self) {
        self.pool.broadcast(self.pool.current_num_threads(), |_| {
            BUILDER_WORKER.with_borrow_mut(|worker| {
                if worker
                    .as_ref()
                    .is_some_and(|worker| Arc::ptr_eq(&worker.context, &self.context))
                {
                    *worker = None;
                }
            });
        });
    }
}

/// Prewarming orchestrator that consumes source [`BestTransactions`] with bounded
/// lookahead, prewarms buffered transactions in parallel, and produces a new
/// [`BestTransactions`] iterator with the source order and invalidations triggered
/// by [`Self::mark_invalid`] preserved.
pub(crate) struct BestTransactionsPrewarming {
    transactions_rx: Receiver<Option<PrewarmedTransaction>>,
    commands_tx: Sender<BestTransactionsCommand>,
    stop: Arc<AtomicBool>,
    parent_hash: B256,
    speculative: bool,
    source_waits: PrewarmingSourceWaits,
}

/// Iterator-local diagnostics; buffered transactions do not sample the clock.
#[derive(Default)]
struct PrewarmingSourceWaits {
    // Calls satisfied by the initial nonblocking buffer check.
    buffered_hits: u64,
    // Includes empty replies and disconnection; this measures the source
    // receive path, not proof that every receive blocked.
    receives: u64,
    receive_elapsed: Duration,
}

/// Builder-local diagnostics for selected speculative handles. Pending and
/// contended slots use ordinary execution; neither path waits for the worker.
#[derive(Debug, Default)]
pub(crate) struct PrewarmingResultWaits {
    pub(crate) ready: u64,
    pub(crate) pending: u64,
    pub(crate) contended: u64,
    // Retain this field for comparison with the blocking diagnostic baseline.
    pub(crate) wait_elapsed: Duration,
}

impl BestTransactionsPrewarming {
    /// Spawns prewarming for `best_txs` and returns a new [`BestTransactions`] iterator.
    pub(crate) fn new<Txs, Provider>(
        prewarm: PrewarmingExecutionContext<Provider>,
        best_txs: Txs,
    ) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
        Provider: StateProviderFactory + Clone + 'static,
    {
        let (transactions_tx, transactions_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let this = Self {
            transactions_rx,
            commands_tx: commands_tx.clone(),
            stop: prewarm.stop.clone(),
            parent_hash: prewarm.parent_hash,
            speculative: prewarm.speculative,
            source_waits: PrewarmingSourceWaits::default(),
        };

        let prewarm_executor = prewarm.executor();
        prewarm
            .executor()
            .spawn_blocking_named("builder-prewarm", move || {
                Self::start_prewarming(
                    prewarm_executor,
                    BestTransactionsPrewarmingContext {
                        best_txs,
                        transactions_tx,
                        commands_rx,
                        commands_tx,
                        prewarm,
                        next_expiring_nonce_offset: 0,
                        speculative_in_flight: 0,
                    },
                );
            });

        this
    }

    /// Runs the coordinator side of prewarming for a payload build.
    ///
    /// See [`BestTransactionsPrewarming`] for details.
    fn start_prewarming<Txs, Provider>(
        executor: TaskExecutor,
        mut ctx: BestTransactionsPrewarmingContext<Txs, Provider>,
    ) where
        Txs: BestTransactions<Item = BestTransaction>,
        Provider: StateProviderFactory + Clone + 'static,
    {
        let pool = executor.prewarming_pool();
        let _cleanup = BuilderWorkerCleanup {
            pool,
            context: ctx.prewarm.stop.clone(),
        };

        pool.in_place_scope(|scope| {
            let prewarm = ctx.prewarm.clone();
            scope.spawn(move |_| {
                pool.broadcast(pool.current_num_threads(), |_| prewarm.with_worker(|_| {}));
            });

            let advance = |ctx: &mut BestTransactionsPrewarmingContext<Txs, Provider>| {
                if ctx.prewarm.speculative
                    && ctx.speculative_in_flight >= pool.current_num_threads() * 2
                {
                    return;
                }
                let Some(tx) = ctx.best_txs.next() else {
                    let _ = ctx.transactions_tx.send(None);
                    return;
                };
                let expiring_nonce_offset = if tx.transaction.is_expiring_nonce() {
                    let offset = ctx.next_expiring_nonce_offset;
                    ctx.next_expiring_nonce_offset += 1;
                    Some(offset)
                } else {
                    None
                };

                let parallel = ctx.prewarm.parallel;
                let prewarm = ctx.prewarm.clone();
                let commands_tx = ctx.commands_tx.clone();
                let transactions_tx = ctx.transactions_tx.clone();

                if prewarm.speculative {
                    ctx.speculative_in_flight += 1;
                    // Publish handles in source order, before workers finish. The
                    // authoritative iterator can still skip or invalidate them.
                    let (producer, handle) =
                        PreexecutedHandle::new(commands_tx, expiring_nonce_offset);
                    let _ = transactions_tx.send(Some(PrewarmedTransaction {
                        tx: tx.clone(),
                        replay: None,
                        preexecuted: Some(handle),
                    }));
                    scope.spawn(move |_| {
                        // A selected transaction can execute ordinarily before
                        // this job starts. Let producer Drop return its permit.
                        // Skip this job's with_worker call; the separate eager
                        // initialization broadcast still runs for the build.
                        if !producer.has_consumer() {
                            return;
                        }
                        let result = prewarm.with_worker(|worker| {
                            if prewarm.is_stopped() {
                                return None;
                            }
                            let BuilderWorkerEvm::Speculative(evm) = worker else {
                                unreachable!("speculative prewarming context")
                            };
                            let evm = evm.as_mut().as_mut()?;
                            evm.execute(tx.transaction.clone_tx_env(), expiring_nonce_offset)
                                .ok()
                        });
                        producer.send(result);
                    });
                    return;
                }

                if !parallel {
                    let _ = ctx
                        .transactions_tx
                        .send(Some(PrewarmedTransaction::without_replay(tx.clone())));
                }

                scope.spawn(move |_| {
                    let tx = Self::prewarm_transaction(prewarm, tx, expiring_nonce_offset);
                    if parallel {
                        let _ = transactions_tx.send(Some(tx));
                    }
                    let _ = commands_tx.send(BestTransactionsCommand::Advance);
                });
            };

            // Fill the initial batch of transactions to execute and prewarm.
            //
            // We schedule 2x the number of threads to make sure that workers are never idle.
            for _ in 0..pool.current_num_threads() * 2 {
                advance(&mut ctx);
            }

            while let Ok(command) = ctx.commands_rx.recv() {
                match command {
                    BestTransactionsCommand::Advance => {
                        advance(&mut ctx);
                    }
                    BestTransactionsCommand::ConsumedSpeculative => {
                        ctx.speculative_in_flight -= 1;
                        advance(&mut ctx);
                    }
                    BestTransactionsCommand::Invalid(invalidation) => {
                        let BufferedInvalidation {
                            invalid,
                            old_rx,
                            new_tx,
                        } = *invalidation;
                        ctx.best_txs.mark_invalid(&invalid.tx, invalid.kind);
                        ctx.transactions_tx = new_tx;

                        for tx in old_rx {
                            if let Some(tx) = tx
                                && !is_invalidated_buffered_transaction(&invalid.tx, &tx.tx)
                            {
                                let _ = ctx.transactions_tx.send(Some(tx));
                            }
                        }
                    }
                    BestTransactionsCommand::NoUpdates => {
                        ctx.best_txs.no_updates();
                    }
                    BestTransactionsCommand::SkipBlobs(skip_blobs) => {
                        ctx.best_txs.set_skip_blobs(skip_blobs);
                    }
                    BestTransactionsCommand::Stop { drain_rx } => {
                        ctx.prewarm.stop();
                        drop(drain_rx);
                        return;
                    }
                    BestTransactionsCommand::InvalidExpiringNonce(invalid) => {
                        ctx.best_txs.mark_invalid(&invalid.tx, invalid.kind);
                    }
                }
            }
        });
    }

    /// Prewarms a transaction by executing it on top of the latest state.
    ///
    /// If [`PrewarmingExecutionContext::parallel`] is enabled and prewarming was successful,
    /// a [`PrewarmedTransaction`] with populated replay data is returned.
    #[instrument(level = "trace", skip_all, fields(parallel = prewarm.parallel, tx_hash = ?tx.hash()))]
    fn prewarm_transaction<Provider>(
        prewarm: PrewarmingExecutionContext<Provider>,
        tx: BestTransaction,
        expiring_nonce_offset: Option<usize>,
    ) -> PrewarmedTransaction
    where
        Provider: StateProviderFactory + Clone + 'static,
    {
        let replay = prewarm.with_worker(|worker| {
            if prewarm.parallel && !is_parallel_candidate(&tx) {
                return None;
            }

            let BuilderWorkerEvm::Regular(evm) = worker else {
                unreachable!("regular prewarming context")
            };
            let evm = evm.as_mut().as_mut()?;

            if prewarm.is_stopped() {
                return None;
            }

            let mut tx_env = tx.transaction.clone_tx_env();
            if let Some(tempo_tx_env) = tx_env.tempo_tx_env.as_mut() {
                tempo_tx_env.expiring_nonce_idx = expiring_nonce_offset;
            }

            let result = match evm.transact_raw(tx_env) {
                Ok(result) => result.result,
                Err(err) => {
                    // Discard actions recorded by the failed transaction before reusing this worker.
                    evm.clear_actions();
                    trace!(
                        target: "payload_builder",
                        %err,
                        "Failed to prewarm transaction by execution"
                    );

                    return None;
                }
            };

            trace!(target: "payload_builder", "Prewarmed transaction");

            if !prewarm.parallel {
                return None;
            }

            let actions = evm.take_actions()?;
            let expiring_nonce = tx
                .transaction
                .is_expiring_nonce()
                .then(|| {
                    let valid_before = tx.transaction.inner().valid_before()?;
                    Some(ExpiringNonceReplay {
                        hash: tx.transaction.expiring_nonce_hash()?,
                        valid_before,
                    })
                })
                .flatten();

            trace!(
                target: "payload_builder",
                actions = actions.len(),
                expiring_nonce = expiring_nonce.is_some(),
                "Generated replay for transaction"
            );

            Some(Box::new(StorageActionReplay {
                result,
                actions,
                validator_fee: evm.validator_fee(),
                expiring_nonce,
            }))
        });

        PrewarmedTransaction {
            tx,
            replay,
            preexecuted: None,
        }
    }
}

impl Drop for BestTransactionsPrewarming {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Move buffered transaction cleanup to the prewarm coordinator instead of this builder thread.
        let (_drain_tx, replacement_rx) = mpsc::channel();
        let drain_rx = core::mem::replace(&mut self.transactions_rx, replacement_rx);
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::Stop { drain_rx });
        info!(
            target: "payload_builder",
            parent_hash = %self.parent_hash,
            speculative = self.speculative,
            buffered_hits = self.source_waits.buffered_hits,
            source_receives = self.source_waits.receives,
            source_receive_seconds = self.source_waits.receive_elapsed.as_secs_f64(),
            "Prewarming source waits"
        );
    }
}

impl Iterator for BestTransactionsPrewarming {
    type Item = PrewarmedTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        // Empty replies describe earlier source polls. Drain them before deciding
        // whether a ready transaction exists, preserving the order of actual txs.
        if let Some(tx) = self.transactions_rx.try_iter().flatten().next() {
            self.source_waits.buffered_hits += 1;
            return Some(tx);
        }
        self.commands_tx
            .send(BestTransactionsCommand::Advance)
            .ok()?;
        // An eager advance can also reply empty while this receive is waiting.
        // Check for buffered transactions before reporting empty to the builder,
        // but do not wait for more replies: it must still check its build budget.
        self.source_waits.receives += 1;
        let receive_start = Instant::now();
        let received = self.transactions_rx.recv();
        self.source_waits.receive_elapsed += receive_start.elapsed();
        received
            .ok()?
            .or_else(|| self.transactions_rx.try_iter().flatten().next())
    }
}

impl BestTransactions for BestTransactionsPrewarming {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        let invalid = InvalidTransaction {
            tx: transaction.tx.clone(),
            kind,
        };
        // Expiring nonces have no dependent transactions to remove from the buffer.
        if transaction.tx.transaction.is_expiring_nonce() {
            let _ = self
                .commands_tx
                .send(BestTransactionsCommand::InvalidExpiringNonce(Box::new(
                    invalid,
                )));
            return;
        }

        let (new_tx, new_rx) = mpsc::channel();
        let old_rx = core::mem::replace(&mut self.transactions_rx, new_rx);
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::Invalid(Box::new(
                BufferedInvalidation {
                    invalid,
                    old_rx,
                    new_tx,
                },
            )));
    }

    fn no_updates(&mut self) {
        let _ = self.commands_tx.send(BestTransactionsCommand::NoUpdates);
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::SkipBlobs(skip_blobs));
    }
}

/// Context for prewarming best transactions for a payload build.
struct BestTransactionsPrewarmingContext<Txs, Provider> {
    best_txs: Txs,
    transactions_tx: Sender<Option<PrewarmedTransaction>>,
    commands_tx: Sender<BestTransactionsCommand>,
    commands_rx: Receiver<BestTransactionsCommand>,
    prewarm: PrewarmingExecutionContext<Provider>,
    next_expiring_nonce_offset: usize,
    speculative_in_flight: usize,
}

/// Prewarmed transaction returned from [`BestTransactionsPrewarming`] iterator.
#[derive(Debug)]
pub(crate) struct PrewarmedTransaction {
    pub(crate) tx: BestTransaction,
    pub(crate) replay: Option<Box<StorageActionReplay>>,
    preexecuted: Option<PreexecutedHandle>,
}

impl PrewarmedTransaction {
    pub(crate) fn without_replay(tx: BestTransaction) -> Self {
        Self {
            tx,
            replay: None,
            preexecuted: None,
        }
    }

    /// Reuse only a ready result for the selected transaction. Ordinary execution
    /// handles pending work without changing source order or releasing its
    /// admission permit before the worker also finishes.
    pub(crate) fn take_preexecuted(
        &mut self,
        waits: &mut PrewarmingResultWaits,
    ) -> Option<PreexecutedTransaction> {
        self.preexecuted.take()?.try_recv(waits)
    }

    pub(crate) fn expiring_nonce_offset(&self) -> Option<usize> {
        self.preexecuted.as_ref()?.expiring_nonce_offset
    }
}

#[derive(Debug)]
struct PreexecutedHandle {
    completion: Arc<SpeculativeCompletion>,
    expiring_nonce_offset: Option<usize>,
}

impl PreexecutedHandle {
    fn new(
        commands_tx: Sender<BestTransactionsCommand>,
        expiring_nonce_offset: Option<usize>,
    ) -> (PreexecutedProducer, Self) {
        let completion = Arc::new(SpeculativeCompletion {
            result: Mutex::new(PreexecutedResult { value: None }),
            commands_tx,
        });
        (
            PreexecutedProducer {
                completion: Some(completion.clone()),
            },
            Self {
                completion,
                expiring_nonce_offset,
            },
        )
    }

    fn try_recv(self, waits: &mut PrewarmingResultWaits) -> Option<PreexecutedTransaction> {
        let mut result = match self.completion.result.try_lock() {
            Ok(result) => result,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                waits.contended += 1;
                return None;
            }
        };
        if result.value.is_some() {
            waits.ready += 1;
        } else {
            waits.pending += 1;
        }
        result.value.take().flatten()
    }
}

/// Close the slot even if the worker exits early or unwinds before publishing.
#[derive(Debug)]
struct PreexecutedProducer {
    completion: Option<Arc<SpeculativeCompletion>>,
}

impl PreexecutedProducer {
    /// Advisory only: the consumer can disappear immediately after this check.
    /// These non-cloneable handles own exactly two strong references, with no
    /// weak references from which another consumer could be created.
    fn has_consumer(&self) -> bool {
        self.completion
            .as_ref()
            .is_some_and(|completion| Arc::strong_count(completion) > 1)
    }

    fn send(mut self, result: Option<PreexecutedTransaction>) {
        if let Some(completion) = self.completion.take() {
            completion.publish(result);
        }
    }
}

impl Drop for PreexecutedProducer {
    fn drop(&mut self) {
        if let Some(completion) = self.completion.take() {
            completion.publish(None);
        }
    }
}

#[derive(Debug)]
struct PreexecutedResult {
    // Outer None means pending; Some(None) means no reusable result.
    value: Option<Option<PreexecutedTransaction>>,
}

/// One result and one admission permit shared by exactly the worker and consumer.
/// Discarding a handle never locks or waits. Capacity returns only after both
/// owners finish, including when a discarded candidate's worker is still running.
#[derive(Debug)]
struct SpeculativeCompletion {
    result: Mutex<PreexecutedResult>,
    commands_tx: Sender<BestTransactionsCommand>,
}

impl SpeculativeCompletion {
    fn publish(&self, value: Option<PreexecutedTransaction>) {
        self.result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .value = Some(value);
    }
}

impl Drop for SpeculativeCompletion {
    fn drop(&mut self) {
        // Release any discarded result before admitting its replacement. Both
        // owners are gone, so exclusive mutex access does not lock or wait.
        drop(
            self.result
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .value
                .take(),
        );
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::ConsumedSpeculative);
    }
}

impl StateAwarePoolTransaction for PrewarmedTransaction {
    fn best_transaction(&self) -> &BestTransaction {
        &self.tx
    }
}

/// Context needed to prewarm transaction storage independently of the real builder.
#[derive(Clone)]
pub(crate) struct PrewarmingExecutionContext<Provider> {
    provider: Provider,
    executor: TaskExecutor,
    parent_hash: B256,
    cache: Option<SavedCache>,
    evm_env: EvmEnvFor<TempoEvmConfig>,
    stop: Arc<AtomicBool>,
    parallel: bool,
    speculative: bool,
    prefix: Option<PrewarmingState>,
}

impl<Provider> PrewarmingExecutionContext<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    pub(crate) fn new(
        provider: Provider,
        executor: TaskExecutor,
        cache: Option<SavedCache>,
        parent_hash: B256,
        evm_env: EvmEnvFor<TempoEvmConfig>,
        parallel: bool,
    ) -> Self {
        Self {
            provider,
            executor,
            parent_hash,
            cache,
            evm_env,
            stop: Arc::new(AtomicBool::new(false)),
            parallel,
            speculative: false,
            prefix: None,
        }
    }

    /// Reuses exact speculative results instead of duplicating prewarming and
    /// scheduling a second execution. Native storage-action replay stays separate.
    pub(crate) fn with_speculative(mut self, enabled: bool) -> Self {
        self.speculative = enabled && !self.parallel;
        self.prefix = self.speculative.then(PrewarmingState::default);
        self
    }

    pub(crate) fn prefix(&self) -> Option<PrewarmingState> {
        self.prefix.clone()
    }

    /// Access only this build's EVM. Like WorkerPool's worker access, the closure
    /// must not yield to Rayon while holding the thread-local mutable borrow.
    fn with_worker<R>(&self, f: impl FnOnce(&mut BuilderWorkerEvm) -> R) -> R {
        BUILDER_WORKER.with_borrow_mut(|worker| {
            if worker
                .as_ref()
                .is_none_or(|worker| !Arc::ptr_eq(&worker.context, &self.stop))
            {
                // Drop the old provider on its owning thread before acquiring
                // another build's provider and execution cache.
                *worker = None;
                *worker = Some(BuilderWorker {
                    context: self.stop.clone(),
                    evm: if self.speculative {
                        BuilderWorkerEvm::Speculative(Box::new(self.speculative_evm_for_ctx()))
                    } else {
                        BuilderWorkerEvm::Regular(Box::new(self.evm_for_ctx()))
                    },
                });
            }
            f(&mut worker.as_mut().expect("builder worker initialized").evm)
        })
    }

    fn speculative_evm_for_ctx(&self) -> SpeculativePrewarmState {
        Some(
            PrewarmingExecutor::new(self.database_for_ctx()?, self.evm_env.clone())
                .with_state(self.prefix.clone()?),
        )
    }

    fn database_for_ctx(&self) -> Option<StateProviderDatabase<EvmStateProviderBox>> {
        let state_provider = match self.provider.state_by_block_hash(self.parent_hash) {
            Ok(provider) => provider,
            Err(err) => {
                trace!(
                    target: "payload_builder",
                    %err,
                    parent_hash = ?self.parent_hash,
                    "failed to build state provider for transaction prewarming"
                );
                return None;
            }
        };
        let mut state_provider: EvmStateProviderBox =
            Box::new(state_provider.into_evm_state_provider());

        if let Some(cache) = &self.cache {
            state_provider = Box::new(CachedStateProvider::new_prewarm(
                state_provider,
                cache.cache().clone(),
            ));
        }

        Some(StateProviderDatabase::new(state_provider))
    }

    pub(crate) fn evm_for_ctx(&self) -> PrewarmEvmState {
        let state_provider = self.database_for_ctx()?;

        let mut evm_env = self.evm_env.clone();

        if !self.parallel {
            evm_env.cfg_env.disable_nonce_check = true;
            evm_env.cfg_env.disable_balance_check = true;
        }

        let mut evm = TempoEvm::new(state_provider, evm_env);

        // Record storage actions for future replay
        if self.parallel {
            evm = evm.with_actions();
        }

        Some(evm)
    }

    pub(crate) fn executor(&self) -> TaskExecutor {
        self.executor.clone()
    }
}

impl<Provider> PrewarmingExecutionContext<Provider> {
    pub(crate) fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Command sent by [`BestTransactionsPrewarming`] consumer.
#[derive(Debug)]
enum BestTransactionsCommand {
    Advance,
    ConsumedSpeculative,
    Invalid(Box<BufferedInvalidation>),
    NoUpdates,
    SkipBlobs(bool),
    Stop {
        /// Receiver moved out of the builder thread so queued transactions drain on the coordinator.
        drain_rx: Receiver<Option<PrewarmedTransaction>>,
    },
    InvalidExpiringNonce(Box<InvalidTransaction>),
}

/// Keep infrequent invalidation data out of every advance and permit message.
#[derive(Debug)]
struct BufferedInvalidation {
    invalid: InvalidTransaction,
    old_rx: Receiver<Option<PrewarmedTransaction>>,
    new_tx: Sender<Option<PrewarmedTransaction>>,
}

/// Invalid transaction encountered during execution.
#[derive(Debug)]
struct InvalidTransaction {
    tx: BestTransaction,
    kind: InvalidPoolTransactionError,
}

/// Returns whether the candidate transaction is invalidated by the given invalid transaction.
fn is_invalidated_buffered_transaction(
    invalid: &BestTransaction,
    candidate: &BestTransaction,
) -> bool {
    // Skip invalidation for expiring nonce transactions - they are independent
    // and should not block other expiring nonce txs from the same sender
    if invalid.transaction.is_expiring_nonce() {
        return false;
    }

    if invalid.transaction.is_aa_2d() {
        candidate
            .transaction
            .aa_transaction_id()
            .zip(invalid.transaction.aa_transaction_id())
            .is_some_and(|(candidate_id, invalid_id)| candidate_id.seq_id() == invalid_id.seq_id())
    } else {
        !candidate.transaction.is_aa_2d()
            && candidate.transaction.sender() == invalid.transaction.sender()
    }
}

/// Returns true if the transaction is a candidate for parallel prewarming.
fn is_parallel_candidate(tx: &BestTransaction) -> bool {
    // Payment lane transactions
    tx.transaction.is_payment()
        // 2D or expiring nonces, no protocol nonces
        && tx
            .transaction
            .nonce_key_ref()
            .is_some_and(|nonce_key| !nonce_key.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockHeader, Header, Signed, TxLegacy};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use reth_engine_tree::tree::ExecutionCache;
    use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
    use reth_primitives_traits::{
        Recovered, SealedHeader, transaction::error::InvalidTransactionError,
    };
    use reth_storage_api::noop::NoopProvider;
    use reth_transaction_pool::{
        TransactionOrigin, ValidPoolTransaction, identifier::TransactionId,
    };
    use std::{
        collections::VecDeque,
        num::NonZeroU64,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };
    use tempo_chainspec::TempoChainSpec;
    use tempo_evm::{TempoEvmConfig, TempoNextBlockEnvAttributes};
    use tempo_precompiles::storage::actions::StorageAction;
    use tempo_primitives::{
        TempoHeader, TempoPrimitives, TempoTransaction, TempoTxEnvelope, transaction::Call,
    };
    use tempo_transaction_pool::transaction::TempoPooledTransaction;

    #[derive(Debug, Default)]
    struct TestLog {
        yielded: usize,
        empty_polls: usize,
        invalid: usize,
        no_updates: usize,
        skip_blobs: Vec<bool>,
    }

    struct TestBestTransactions {
        txs: VecDeque<BestTransaction>,
        log: Arc<Mutex<TestLog>>,
    }

    impl TestBestTransactions {
        fn new(txs: Vec<BestTransaction>, log: Arc<Mutex<TestLog>>) -> Self {
            Self {
                txs: txs.into(),
                log,
            }
        }
    }

    impl Iterator for TestBestTransactions {
        type Item = BestTransaction;

        fn next(&mut self) -> Option<Self::Item> {
            let tx = self.txs.pop_front();
            {
                let mut log = self.log.lock().unwrap();
                if tx.is_some() {
                    log.yielded += 1;
                } else {
                    log.empty_polls += 1;
                }
            }
            if tx.is_none() {
                thread::sleep(Duration::from_millis(1));
            }
            tx
        }
    }

    impl BestTransactions for TestBestTransactions {
        fn mark_invalid(&mut self, transaction: &Self::Item, _kind: InvalidPoolTransactionError) {
            self.log.lock().unwrap().invalid += 1;
            self.txs
                .retain(|tx| !is_invalidated_buffered_transaction(transaction, tx));
        }

        fn no_updates(&mut self) {
            self.log.lock().unwrap().no_updates += 1;
        }

        fn set_skip_blobs(&mut self, skip_blobs: bool) {
            self.log.lock().unwrap().skip_blobs.push(skip_blobs);
        }
    }

    fn test_tx(sender: Address, nonce: u64) -> BestTransaction {
        test_tx_with_gas_limit(sender, nonce, 21_000)
    }

    fn test_tx_with_gas_limit(sender: Address, nonce: u64, gas_limit: u64) -> BestTransaction {
        let tx = TxLegacy {
            chain_id: Some(42431),
            nonce,
            gas_price: 20_000_000_000,
            gas_limit,
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope =
            TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()));
        let pooled = TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender));
        Arc::new(ValidPoolTransaction {
            transaction_id: TransactionId::new(0u64.into(), nonce),
            transaction: pooled,
            propagate: true,
            timestamp: Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    fn test_payment_tx(sender: Address, gas_limit: u64) -> BestTransaction {
        test_payment_tx_with_nonce_key(sender, gas_limit, U256::ONE)
    }

    fn test_payment_tx_with_nonce_key(
        sender: Address,
        gas_limit: u64,
        nonce_key: U256,
    ) -> BestTransaction {
        let mut token = [0u8; 20];
        token[..2].copy_from_slice(&[0x20, 0xc0]);
        let token = Address::from(token);

        // transfer(address,uint256) with a zero recipient and amount.
        let mut input = vec![0xa9, 0x05, 0x9c, 0xbb];
        input.resize(4 + 32 + 32, 0);
        let tx = TempoTransaction {
            chain_id: 42431,
            fee_token: Some(token),
            gas_limit,
            calls: vec![Call {
                to: TxKind::Call(token),
                value: U256::ZERO,
                input: input.into(),
            }],
            nonce_key,
            valid_before: (nonce_key == U256::MAX).then_some(NonZeroU64::new(100).unwrap()),
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::AA(tx.into_signed(Signature::test_signature().into()));
        let pooled = TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender));
        Arc::new(ValidPoolTransaction {
            transaction_id: TransactionId::new(0u64.into(), 0),
            transaction: pooled,
            propagate: true,
            timestamp: Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    struct TestPrewarming {
        prewarming: Option<BestTransactionsPrewarming>,
        executor: TaskExecutor,
    }

    impl Drop for TestPrewarming {
        fn drop(&mut self) {
            drop(self.prewarming.take());
            self.executor
                .spawn_blocking_named("builder-prewarm", || {})
                .get();
        }
    }

    impl std::ops::Deref for TestPrewarming {
        type Target = BestTransactionsPrewarming;

        fn deref(&self) -> &Self::Target {
            self.prewarming.as_ref().expect("prewarming exists")
        }
    }

    impl std::ops::DerefMut for TestPrewarming {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.prewarming.as_mut().expect("prewarming exists")
        }
    }

    fn prewarming(txs: Vec<BestTransaction>, log: Arc<Mutex<TestLog>>) -> TestPrewarming {
        let executor = TaskExecutor::test();
        prewarming_with_executor(executor, txs, log)
    }

    fn prewarming_with_executor(
        executor: TaskExecutor,
        txs: Vec<BestTransaction>,
        log: Arc<Mutex<TestLog>>,
    ) -> TestPrewarming {
        let context = prewarming_context(executor.clone(), false);
        let prewarming =
            BestTransactionsPrewarming::new(context, TestBestTransactions::new(txs, log));
        TestPrewarming {
            prewarming: Some(prewarming),
            executor,
        }
    }

    fn prewarming_context(
        executor: TaskExecutor,
        parallel: bool,
    ) -> PrewarmingExecutionContext<NoopProvider<TempoChainSpec, TempoPrimitives>> {
        let evm_config = TempoEvmConfig::moderato();
        let provider =
            NoopProvider::<TempoChainSpec, TempoPrimitives>::new(evm_config.chain_spec().clone());
        let parent_header = SealedHeader::seal_slow(TempoHeader {
            inner: Header {
                number: 0,
                timestamp: 1,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(1),
                ..Default::default()
            },
            general_gas_limit: 30_000_000,
            timestamp_millis_part: 0,
            shared_gas_limit: 0,
            ..Default::default()
        });
        let attributes = TempoNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: 2,
                suggested_fee_recipient: Address::ZERO,
                prev_randao: B256::ZERO,
                gas_limit: parent_header.gas_limit(),
                parent_beacon_block_root: None,
                withdrawals: None,
                extra_data: Default::default(),
                slot_number: None,
            },
            general_gas_limit: 30_000_000,
            shared_gas_limit: 0,
            timestamp_millis_part: 0,
            consensus_context: None,
        };
        let evm_env = evm_config
            .next_evm_env(&parent_header, &attributes)
            .expect("test next block env");
        PrewarmingExecutionContext {
            provider,
            executor,
            parent_hash: parent_header.hash(),
            cache: None,
            evm_env,
            stop: Arc::default(),
            parallel,
            speculative: false,
            prefix: None,
        }
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if condition() {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(condition(), "condition did not become true before timeout");
    }

    #[test]
    fn source_ordering_is_unchanged_when_prewarming_is_enabled() {
        let sender = Address::random();
        let txs = vec![test_tx(sender, 0), test_tx(sender, 1), test_tx(sender, 2)];
        let expected = txs.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming(txs, log);
        let actual = (0..expected.len())
            .map(|_| *prewarming.next().expect("transaction").tx.hash())
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn prewarming_eagerly_drains_source_iterator() {
        let sender = Address::random();
        let executor = TaskExecutor::test();
        let txs = (0..executor.prewarming_pool().current_num_threads() * 2 + 4)
            .map(|nonce| test_tx(sender, nonce as u64))
            .collect::<Vec<_>>();
        let expected = txs.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming_with_executor(executor, txs, log.clone());
        wait_until(|| log.lock().unwrap().yielded == expected.len());

        let actual = (0..expected.len())
            .map(|_| *prewarming.next().expect("transaction").tx.hash())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn empty_source_is_polled_for_eager_advances_and_each_consumer_advance() {
        let executor = TaskExecutor::test();
        let eager_advances = executor.prewarming_pool().current_num_threads() * 2;
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming_with_executor(executor, Vec::new(), log.clone());

        wait_until(|| log.lock().unwrap().empty_polls == eager_advances);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == eager_advances + 1);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == eager_advances + 2);
    }

    #[test]
    fn stale_empty_replies_do_not_hide_buffered_transactions() {
        for empty_replies in [2, 32] {
            let (transactions_tx, transactions_rx) = mpsc::channel();
            let (commands_tx, commands_rx) = mpsc::channel();
            let sender = Address::random();
            let first = test_tx(sender, 0);
            let second = test_tx(sender, 1);
            for _ in 0..empty_replies {
                transactions_tx.send(None).unwrap();
            }
            for tx in [&first, &second] {
                transactions_tx
                    .send(Some(PrewarmedTransaction::without_replay(tx.clone())))
                    .unwrap();
            }
            let mut prewarming = BestTransactionsPrewarming {
                transactions_rx,
                commands_tx,
                stop: Arc::default(),
                parent_hash: B256::ZERO,
                speculative: false,
                source_waits: PrewarmingSourceWaits::default(),
            };

            assert_eq!(prewarming.next().unwrap().tx.hash(), first.hash());
            assert_eq!(prewarming.next().unwrap().tx.hash(), second.hash());
            assert_eq!(prewarming.source_waits.buffered_hits, 2);
            assert_eq!(prewarming.source_waits.receives, 0);
            assert_eq!(prewarming.source_waits.receive_elapsed, Duration::ZERO);
            assert!(matches!(
                commands_rx.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
        }
    }

    #[test]
    fn stale_empty_replies_do_not_hide_a_fresh_advance() {
        let (transactions_tx, transactions_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        for _ in 0..32 {
            transactions_tx.send(None).unwrap();
        }
        let tx = test_tx(Address::random(), 0);
        let expected = *tx.hash();
        let coordinator = thread::spawn(move || {
            assert!(matches!(
                commands_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                BestTransactionsCommand::Advance
            ));
            transactions_tx
                .send(Some(PrewarmedTransaction::without_replay(tx)))
                .unwrap();
        });
        let mut prewarming = BestTransactionsPrewarming {
            transactions_rx,
            commands_tx,
            stop: Arc::default(),
            parent_hash: B256::ZERO,
            speculative: false,
            source_waits: PrewarmingSourceWaits::default(),
        };

        let next = prewarming.next();
        coordinator.join().unwrap();
        assert_eq!(*next.expect("fresh transaction").tx.hash(), expected);
        assert_eq!(prewarming.source_waits.buffered_hits, 0);
        assert_eq!(prewarming.source_waits.receives, 1);
    }

    #[test]
    fn empty_advance_returns_none_and_can_resume_on_a_later_poll() {
        let (transactions_tx, transactions_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let tx = test_tx(Address::random(), 0);
        let expected = *tx.hash();
        let coordinator = thread::spawn(move || {
            for reply in [None, Some(PrewarmedTransaction::without_replay(tx))] {
                assert!(matches!(
                    commands_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                    BestTransactionsCommand::Advance
                ));
                transactions_tx.send(reply).unwrap();
            }
        });
        let mut prewarming = BestTransactionsPrewarming {
            transactions_rx,
            commands_tx,
            stop: Arc::default(),
            parent_hash: B256::ZERO,
            speculative: false,
            source_waits: PrewarmingSourceWaits::default(),
        };

        assert!(prewarming.next().is_none());
        assert_eq!(prewarming.source_waits.receives, 1);
        assert_eq!(
            *prewarming.next().expect("later transaction").tx.hash(),
            expected
        );
        coordinator.join().unwrap();
        assert_eq!(prewarming.source_waits.receives, 2);
        assert_eq!(prewarming.source_waits.buffered_hits, 0);
        let receive_elapsed = prewarming.source_waits.receive_elapsed;
        assert!(prewarming.next().is_none());
        // A failed Advance does not attempt or time another receive.
        assert_eq!(prewarming.source_waits.receives, 2);
        assert_eq!(prewarming.source_waits.receive_elapsed, receive_elapsed);
    }

    #[test]
    fn buffered_transactions_survive_empty_replies_and_coordinator_disconnect() {
        let (transactions_tx, transactions_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let tx = test_tx(Address::random(), 0);
        let expected = *tx.hash();
        transactions_tx.send(None).unwrap();
        transactions_tx
            .send(Some(PrewarmedTransaction::without_replay(tx)))
            .unwrap();
        drop(transactions_tx);
        drop(commands_rx);
        let mut prewarming = BestTransactionsPrewarming {
            transactions_rx,
            commands_tx,
            stop: Arc::default(),
            parent_hash: B256::ZERO,
            speculative: false,
            source_waits: PrewarmingSourceWaits::default(),
        };

        assert_eq!(
            *prewarming.next().expect("buffered transaction").tx.hash(),
            expected
        );
        assert!(prewarming.next().is_none());
    }

    #[test]
    fn mark_invalid_filters_already_buffered_invalidated_transactions() {
        let sender = Address::random();
        let mut sender_nonces = 0..;
        let tx1 = test_tx(sender, sender_nonces.next().expect("first nonce"));
        let tx2 = test_tx(sender, sender_nonces.next().expect("second nonce"));
        let tx3 = test_tx(
            Address::random(),
            sender_nonces.next().expect("third nonce"),
        );
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming(vec![tx1.clone(), tx2.clone(), tx3.clone()], log.clone());
        assert_eq!(
            prewarming.next().as_ref().map(|tx| tx.tx.hash()),
            Some(tx1.hash())
        );

        wait_until(|| log.lock().unwrap().yielded == 3);
        prewarming.mark_invalid(
            &PrewarmedTransaction::without_replay(tx1),
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
        );

        let next = prewarming.next().expect("non-invalidated transaction");
        assert_eq!(next.tx.hash(), tx3.hash());
        assert_ne!(next.tx.hash(), tx2.hash());
        wait_until(|| log.lock().unwrap().invalid == 1);
    }

    #[test]
    fn commands_are_forwarded_to_source_iterator() {
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming(Vec::new(), log.clone());

        prewarming.no_updates();
        prewarming.set_skip_blobs(true);

        wait_until(|| {
            let log = log.lock().unwrap();
            log.no_updates == 1 && log.skip_blobs == vec![true]
        });
    }

    #[test]
    fn failed_prewarm_clears_actions_before_same_worker_is_reused() {
        let executor = TaskExecutor::test();
        let mut context = prewarming_context(executor, true);
        context.evm_env.block_env.basefee = 0;

        let pool = WorkerPool::new(1, "prewarm-actions-test");
        let _cleanup = BuilderWorkerCleanup {
            pool: &pool,
            context: context.stop.clone(),
        };

        pool.install_fn(|| {
            let failed_action = StorageAction::Sstore(
                Address::random(),
                U256::from(1),
                U256::from(2),
                U256::from(3),
            );
            context.with_worker(|worker| {
                let BuilderWorkerEvm::Regular(evm) = worker else {
                    panic!("prewarm EVM")
                };
                let evm = evm.as_mut().as_mut().expect("prewarm EVM");
                // Model an action recorded before the failed execution returned an error.
                assert_eq!(evm.replace_actions(vec![failed_action]), Some(Vec::new()));
            });

            let sender = Address::random();
            let failed = BestTransactionsPrewarming::prewarm_transaction(
                context.clone(),
                test_payment_tx(sender, 0),
                None,
            );
            assert!(failed.replay.is_none());
            context.with_worker(|worker| {
                let BuilderWorkerEvm::Regular(evm) = worker else {
                    panic!("prewarm EVM")
                };
                let evm = evm.as_mut().as_mut().expect("prewarm EVM");
                assert_eq!(evm.take_actions(), Some(Vec::new()));
            });

            let successful = BestTransactionsPrewarming::prewarm_transaction(
                context,
                test_payment_tx(sender, 500_000),
                None,
            );
            let replay = successful.replay.expect("successful prewarm replay");
            assert!(!replay.actions.is_empty());
            assert!(!replay.actions.contains(&failed_action));
        });
    }

    #[test]
    fn builder_workers_do_not_replace_engine_worker_state() {
        let executor = TaskExecutor::test();
        let mut engine = prewarming_context(executor.clone(), false);
        engine.cache = Some(SavedCache::new(B256::ZERO, ExecutionCache::new(1024)));
        let builder = prewarming_context(executor, false).with_speculative(true);
        let pool = WorkerPool::new(1, "prewarm-engine-isolation-test");

        // Engine initialization precedes a speculative builder job on the same
        // worker. Using WorkerPool's Any slot here caused a deterministic type
        // mismatch; the reverse interleaving must also retain the Engine EVM.
        pool.init::<PrewarmEvmState>(|_| engine.evm_for_ctx());
        let cleanup = BuilderWorkerCleanup {
            pool: &pool,
            context: builder.stop.clone(),
        };
        pool.install_fn(|| {
            builder.with_worker(|worker| {
                assert!(matches!(worker, BuilderWorkerEvm::Speculative(evm) if evm.is_some()));
            });
            WorkerPool::with_worker(|worker| {
                assert!(worker.get::<PrewarmEvmState>().is_some());
            });
        });
        assert_eq!(engine.cache.as_ref().unwrap().usage_count(), 2);

        // Engine reset/clear cannot invalidate the builder's local EVM, and
        // builder cleanup cannot discard the Engine provider's cache handle.
        pool.clear();
        pool.init::<PrewarmEvmState>(|_| engine.evm_for_ctx());
        drop(cleanup);
        pool.install_fn(|| {
            WorkerPool::with_worker(|worker| {
                assert!(worker.get::<PrewarmEvmState>().is_some());
            });
            BUILDER_WORKER.with_borrow(|worker| assert!(worker.is_none()));
        });
        assert_eq!(engine.cache.as_ref().unwrap().usage_count(), 2);
        pool.clear();
        assert!(engine.cache.as_ref().unwrap().is_available());
    }

    #[test]
    fn builder_worker_context_switches_release_their_own_caches() {
        let executor = TaskExecutor::test();
        let pool = WorkerPool::new(1, "prewarm-context-isolation-test");
        for speculative in [false, true] {
            let mut first =
                prewarming_context(executor.clone(), false).with_speculative(speculative);
            let mut second =
                prewarming_context(executor.clone(), false).with_speculative(speculative);
            first.cache = Some(SavedCache::new(B256::ZERO, ExecutionCache::new(1024)));
            second.cache = Some(SavedCache::new(B256::ZERO, ExecutionCache::new(1024)));
            let first_cache = first.cache.as_ref().unwrap();
            let second_cache = second.cache.as_ref().unwrap();
            let cleanup_first = || BuilderWorkerCleanup {
                pool: &pool,
                context: first.stop.clone(),
            };
            let cleanup_second = || BuilderWorkerCleanup {
                pool: &pool,
                context: second.stop.clone(),
            };

            pool.install_fn(|| first.with_worker(|_| {}));
            assert_eq!(first_cache.usage_count(), 2);
            pool.install_fn(|| second.with_worker(|_| {}));
            assert!(first_cache.is_available());
            assert_eq!(second_cache.usage_count(), 2);
            // An older scope finishing must not clear a newer build's state.
            drop(cleanup_first());
            assert_eq!(second_cache.usage_count(), 2);
            pool.install_fn(|| first.with_worker(|_| {}));
            assert!(second_cache.is_available());
            drop(cleanup_second());
            assert_eq!(first_cache.usage_count(), 2);
            drop(cleanup_first());
            assert!(first_cache.is_available());

            // Cleanup runs after Rayon joins all scoped work, even on unwind.
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _cleanup = cleanup_first();
                pool.in_place_scope(|scope| {
                    scope.spawn(|_| {
                        first.with_worker(|_| {});
                        panic!("failed scoped prewarm job");
                    });
                });
            }));
            assert!(result.is_err());
            assert!(first_cache.is_available());
        }
    }

    #[test]
    fn discarded_speculative_handles_wait_for_worker_completion_to_refill() {
        for worker_first in [false, true] {
            let (commands_tx, commands_rx) = mpsc::channel();
            let (producer, handle) = PreexecutedHandle::new(commands_tx, None);
            let (finish_tx, finish_rx) = mpsc::channel();
            let worker = thread::spawn(move || {
                finish_rx.recv().unwrap();
                producer.send(None);
            });
            if worker_first {
                finish_tx.send(()).unwrap();
                worker.join().unwrap();
                assert!(commands_rx.try_recv().is_err());
                drop(handle);
            } else {
                // This must return before the worker can finish. It must also
                // retain admission capacity until that queued work completes.
                drop(handle);
                assert!(commands_rx.try_recv().is_err());
                finish_tx.send(()).unwrap();
                worker.join().unwrap();
            }
            assert!(matches!(
                commands_rx.try_recv(),
                Ok(BestTransactionsCommand::ConsumedSpeculative)
            ));
            assert!(commands_rx.try_recv().is_err());
        }
    }

    fn speculative_candidate() -> (BestTransaction, PreexecutedTransaction) {
        let context = prewarming_context(TaskExecutor::test(), false);
        let mut env = EvmEnvFor::<TempoEvmConfig>::default();
        env.block_env.inner.gas_limit = 30_000_000;
        let tx = test_tx(Address::with_last_byte(201), 0);
        let mut tx_env = tx.transaction.clone_tx_env();
        tx_env.inner.chain_id = None;
        tx_env.inner.gas_price = 0;
        tx_env.inner.gas_limit = 1_000_000;
        let candidate = PrewarmingExecutor::new(context.database_for_ctx().unwrap(), env)
            .execute(tx_env, None)
            .expect("zero-fee speculative transaction");
        (tx, candidate)
    }

    fn assert_one_speculative_permit(commands_rx: &Receiver<BestTransactionsCommand>) {
        assert!(matches!(
            commands_rx.try_recv(),
            Ok(BestTransactionsCommand::ConsumedSpeculative)
        ));
        assert!(commands_rx.try_recv().is_err());
    }

    #[test]
    fn speculative_wait_diagnostics_accumulate_only_selected_handles() {
        let mut tx = PrewarmedTransaction::without_replay(test_tx(Address::random(), 0));
        let mut waits = PrewarmingResultWaits::default();
        assert!(tx.take_preexecuted(&mut waits).is_none());
        assert_eq!((waits.ready, waits.pending, waits.contended), (0, 0, 0));

        for pending in 0..=2 {
            let (commands_tx, commands_rx) = mpsc::channel();
            let (producer, handle) = PreexecutedHandle::new(commands_tx, None);
            tx.preexecuted = Some(handle);
            assert!(producer.has_consumer());
            if pending == 0 {
                // A completed slot without a reusable result is still ready.
                producer.send(None);
                assert!(tx.take_preexecuted(&mut waits).is_none());
            } else {
                assert!(tx.take_preexecuted(&mut waits).is_none());
                assert!(!producer.has_consumer());
                // Fallback cannot grant capacity while the producer still lives.
                assert!(commands_rx.try_recv().is_err());
                drop(producer);
            }
            assert!(tx.take_preexecuted(&mut waits).is_none());
            assert_eq!(
                (waits.ready, waits.pending, waits.contended),
                (1, pending, 0)
            );
            assert_eq!(waits.wait_elapsed, Duration::ZERO);
            assert_one_speculative_permit(&commands_rx);
        }
    }

    #[test]
    fn speculative_producer_abort_preserves_ready_only_consumer_and_permit() {
        for panic in [false, true] {
            for consumer_first in [false, true] {
                let (commands_tx, commands_rx) = mpsc::channel();
                let (producer, handle) = PreexecutedHandle::new(commands_tx, None);
                let mut waits = PrewarmingResultWaits::default();
                let handle = if consumer_first {
                    assert!(handle.try_recv(&mut waits).is_none());
                    assert!(!producer.has_consumer());
                    None
                } else {
                    Some(handle)
                };
                assert!(commands_rx.try_recv().is_err());
                let outcome = catch_unwind(AssertUnwindSafe(move || {
                    let _producer = producer;
                    if panic {
                        panic!("worker exited before publishing");
                    }
                }));
                assert_eq!(outcome.is_err(), panic);
                if let Some(handle) = handle {
                    assert!(commands_rx.try_recv().is_err());
                    assert!(handle.try_recv(&mut waits).is_none());
                }
                assert_eq!(waits.ready, u64::from(!consumer_first));
                assert_eq!(waits.pending, u64::from(consumer_first));
                assert_eq!(waits.contended, 0);
                assert_one_speculative_permit(&commands_rx);
            }
        }
    }

    #[test]
    fn speculative_result_is_delivered_once_or_abandoned_before_capacity_returns() {
        for producer_first in [false, true] {
            let (tx, candidate) = speculative_candidate();
            // Moving the same cross-crate value preserves its maps' debug order.
            let expected = format!("{candidate:?}");
            let (commands_tx, commands_rx) = mpsc::channel();
            let (producer, handle) = PreexecutedHandle::new(commands_tx, Some(7));
            let mut tx = PrewarmedTransaction {
                tx,
                replay: None,
                preexecuted: Some(handle),
            };
            let offset = tx.expiring_nonce_offset();
            let mut waits = PrewarmingResultWaits::default();
            if producer_first {
                producer.send(Some(candidate));
                assert!(commands_rx.try_recv().is_err());
                assert_eq!(
                    format!("{:?}", tx.take_preexecuted(&mut waits).unwrap()),
                    expected
                );
            } else {
                // A true advisory check may race with consumer fallback. The
                // producer can still publish safely after its consumer is gone.
                assert!(producer.has_consumer());
                assert!(tx.take_preexecuted(&mut waits).is_none());
                assert!(!producer.has_consumer());
                assert!(commands_rx.try_recv().is_err());
                producer.send(Some(candidate));
            }
            assert_eq!(offset, Some(7));
            assert!(tx.take_preexecuted(&mut waits).is_none());
            assert_eq!(waits.ready, u64::from(producer_first));
            assert_eq!(waits.pending, u64::from(!producer_first));
            assert_eq!(waits.contended, 0);
            assert_eq!(waits.wait_elapsed, Duration::ZERO);
            assert_one_speculative_permit(&commands_rx);
        }
    }

    #[test]
    fn speculative_contended_result_falls_back_before_publication_unlocks() {
        for published in [false, true] {
            let (commands_tx, commands_rx) = mpsc::channel();
            let (producer, handle) = PreexecutedHandle::new(commands_tx, None);
            // Borrow the real producer owner. An extra Arc would alter permits.
            let mut result = producer.completion.as_ref().unwrap().result.lock().unwrap();
            if published {
                result.value = Some(None);
            }
            let (returned_tx, returned_rx) = mpsc::channel();
            let consumer = thread::spawn(move || {
                let mut waits = PrewarmingResultWaits::default();
                assert!(handle.try_recv(&mut waits).is_none());
                returned_tx.send(waits).unwrap();
            });
            // The producer still holds the mutex: completion proves no lock wait.
            let waits = returned_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            assert_eq!((waits.ready, waits.pending, waits.contended), (0, 0, 1));
            assert_eq!(waits.wait_elapsed, Duration::ZERO);
            assert!(!producer.has_consumer());
            assert!(commands_rx.try_recv().is_err());
            drop(result);
            producer.send(None);
            consumer.join().unwrap();
            assert_one_speculative_permit(&commands_rx);
        }
    }

    #[test]
    fn speculative_poisoned_result_preserves_fallback_publication_and_permit() {
        for published in [false, true] {
            let (commands_tx, commands_rx) = mpsc::channel();
            let (producer, handle) = PreexecutedHandle::new(commands_tx, None);
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let mut result = producer.completion.as_ref().unwrap().result.lock().unwrap();
                if published {
                    result.value = Some(None);
                }
                panic!("publication failed while holding the result mutex");
            }));
            assert!(outcome.is_err());
            let mut waits = PrewarmingResultWaits::default();
            assert!(handle.try_recv(&mut waits).is_none());
            assert_eq!(waits.ready, u64::from(published));
            assert_eq!(waits.pending, u64::from(!published));
            assert_eq!(waits.contended, 0);
            assert!(commands_rx.try_recv().is_err());
            // Both publication and final cleanup recover the same poisoned lock.
            drop(producer);
            assert_one_speculative_permit(&commands_rx);
        }
    }

    #[test]
    fn abandoned_queued_producer_skips_work_and_returns_its_permit_on_drop() {
        let (commands_tx, commands_rx) = mpsc::channel();
        let (producer, handle) = PreexecutedHandle::new(commands_tx, None);
        let (start_tx, start_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            start_rx.recv().unwrap();
            if !producer.has_consumer() {
                return;
            }
            // The build's separate eager initialization remains unchanged.
            panic!("an abandoned queued job must not call with_worker or execute");
        });
        let mut waits = PrewarmingResultWaits::default();
        assert!(handle.try_recv(&mut waits).is_none());
        assert!(commands_rx.try_recv().is_err());
        start_tx.send(()).unwrap();
        worker.join().unwrap();
        assert_one_speculative_permit(&commands_rx);
    }

    #[test]
    fn delayed_first_result_preserves_source_order_and_expiring_nonce_offsets() {
        let (transactions_tx, transactions_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let sender = Address::random();
        let expiring = (0..3)
            .map(|index| test_payment_tx_with_nonce_key(sender, 500_000 + index, U256::MAX))
            .collect::<Vec<_>>();
        let (ordinary, candidate) = speculative_candidate();
        let expected_result = format!("{candidate:?}");
        let transactions = expiring.into_iter().chain([ordinary]).collect::<Vec<_>>();
        let expected_hashes = transactions.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let mut delayed = Vec::new();
        let mut candidate = Some(candidate);
        for (index, tx) in transactions.into_iter().enumerate() {
            let offset = (index < 3).then_some(index);
            let (producer, handle) = PreexecutedHandle::new(commands_tx.clone(), offset);
            transactions_tx
                .send(Some(PrewarmedTransaction {
                    tx,
                    replay: None,
                    preexecuted: Some(handle),
                }))
                .unwrap();
            if index < 2 {
                delayed.push(producer);
            } else {
                producer.send(if index == 3 { candidate.take() } else { None });
            }
        }
        let mut prewarming = BestTransactionsPrewarming {
            transactions_rx,
            commands_tx,
            stop: Arc::default(),
            parent_hash: B256::ZERO,
            speculative: true,
            source_waits: PrewarmingSourceWaits::default(),
        };
        let skipped = prewarming.next().unwrap();
        assert_eq!(*skipped.tx.hash(), expected_hashes[0]);
        assert_eq!(skipped.expiring_nonce_offset(), Some(0));
        prewarming.mark_invalid(
            &skipped,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
        );
        drop(skipped);
        let mut waits = PrewarmingResultWaits::default();
        let mut captured_offsets = Vec::new();
        for (index, expected_hash) in expected_hashes.iter().enumerate().skip(1) {
            let mut selected = prewarming.next().unwrap();
            assert_eq!(selected.tx.hash(), expected_hash);
            // The builder captures this before consuming the handle, including
            // ordinary fallback, and publishes it with the authoritative result.
            captured_offsets.push(selected.expiring_nonce_offset());
            let result = selected.take_preexecuted(&mut waits);
            if index == 3 {
                assert_eq!(format!("{:?}", result.unwrap()), expected_result);
            } else {
                assert!(result.is_none());
            }
        }
        assert_eq!(captured_offsets, [Some(1), Some(2), None]);
        assert_eq!((waits.ready, waits.pending, waits.contended), (2, 1, 0));
        assert_eq!(prewarming.source_waits.buffered_hits, 4);
        assert_eq!(prewarming.source_waits.receives, 0);
        assert!(delayed.iter().all(|producer| !producer.has_consumer()));
        let commands = commands_rx.try_iter().collect::<Vec<_>>();
        assert_eq!(
            commands
                .iter()
                .filter(|command| matches!(command, BestTransactionsCommand::ConsumedSpeculative))
                .count(),
            2
        );
        assert_eq!(
            commands
                .iter()
                .filter(|command| matches!(
                    command,
                    BestTransactionsCommand::InvalidExpiringNonce(_)
                ))
                .count(),
            1
        );
        assert_eq!(commands.len(), 3);
        // Skipping or falling back did not release either delayed worker permit.
        for producer in delayed {
            producer.send(None);
            assert_one_speculative_permit(&commands_rx);
        }
        drop(prewarming);
        assert!(matches!(
            commands_rx.try_recv(),
            Ok(BestTransactionsCommand::Stop { .. })
        ));
        assert!(commands_rx.try_recv().is_err());
    }

    #[test]
    fn speculative_prewarming_preserves_order_and_bounds_completed_results() {
        let executor = TaskExecutor::test();
        let engine = prewarming_context(executor.clone(), false);
        let shared_executor = executor.clone();
        shared_executor
            .prewarming_pool()
            .init::<PrewarmEvmState>(|_| engine.evm_for_ctx());
        let window = executor.prewarming_pool().current_num_threads() * 2;
        let transactions = (0..window * 3)
            .map(|_| test_payment_tx(Address::random(), 500_000))
            .collect::<Vec<_>>();
        let hashes = transactions.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));
        let context = prewarming_context(executor.clone(), false).with_speculative(true);
        let mut prewarming = TestPrewarming {
            prewarming: Some(BestTransactionsPrewarming::new(
                context,
                TestBestTransactions::new(transactions, log.clone()),
            )),
            executor,
        };
        wait_until(|| log.lock().unwrap().yielded == window);
        // Empty-buffer polls can race with pending refill commands. They must
        // not grant additional speculative capacity before a handle is consumed.
        for _ in 0..window * 3 {
            prewarming
                .commands_tx
                .send(BestTransactionsCommand::Advance)
                .unwrap();
        }
        prewarming.no_updates();
        wait_until(|| log.lock().unwrap().no_updates == 1);
        assert_eq!(log.lock().unwrap().yielded, window);
        // Taking the first result must not let worker completion drain the
        // whole source. Both owners finishing releases exactly one slot.
        let mut first = prewarming.next().expect("first source candidate");
        assert_eq!(*first.tx.hash(), hashes[0]);
        assert!(first.preexecuted.is_some());
        let _ = first.take_preexecuted(&mut PrewarmingResultWaits::default());
        wait_until(|| log.lock().unwrap().yielded == window + 1);
        for hash in &hashes[1..window] {
            let candidate = prewarming.next().expect("source candidate");
            assert_eq!(candidate.tx.hash(), hash);
            assert!(candidate.preexecuted.is_some());
            // Discarding never waits; capacity returns once its worker also finishes.
            drop(candidate);
        }
        wait_until(|| log.lock().unwrap().yielded == window * 2);
        // Dropping the builder with a full window must stop without deadlock.
        drop(prewarming);
        let pool = shared_executor.prewarming_pool();
        pool.broadcast(pool.current_num_threads(), |worker| {
            assert!(worker.get::<PrewarmEvmState>().is_some());
            BUILDER_WORKER.with_borrow(|worker| assert!(worker.is_none()));
        });
        pool.clear();
    }

    #[test]
    fn expiring_nonce_invalidation_keeps_the_existing_buffer() {
        let (transactions_tx, transactions_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let sender = Address::random();
        let rejected = test_payment_tx_with_nonce_key(sender, 500_000, U256::MAX);
        let buffered = [
            test_payment_tx_with_nonce_key(sender, 600_000, U256::MAX),
            test_payment_tx(sender, 500_000),
            test_tx(sender, 0),
        ];
        for tx in &buffered {
            transactions_tx
                .send(Some(PrewarmedTransaction::without_replay(tx.clone())))
                .unwrap();
        }
        let mut prewarming = BestTransactionsPrewarming {
            transactions_rx,
            commands_tx,
            stop: Arc::default(),
            parent_hash: B256::ZERO,
            speculative: false,
            source_waits: PrewarmingSourceWaits::default(),
        };

        // Leave the coordinator commands unprocessed: the original buffer must
        // remain readable even across repeated rejections.
        for _ in 0..3 {
            prewarming.mark_invalid(
                &PrewarmedTransaction::without_replay(rejected.clone()),
                InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
            );
        }
        for expected in &buffered {
            let tx = prewarming.transactions_rx.try_recv().unwrap().unwrap();
            assert_eq!(tx.tx.hash(), expected.hash());
        }
        // Existing worker senders must still deliver to the same receiver.
        transactions_tx
            .send(Some(PrewarmedTransaction::without_replay(
                buffered[0].clone(),
            )))
            .unwrap();
        let delivered = prewarming.transactions_rx.try_recv().unwrap().unwrap();
        assert_eq!(delivered.tx.hash(), buffered[0].hash());
        for _ in 0..3 {
            let BestTransactionsCommand::InvalidExpiringNonce(invalid) =
                commands_rx.try_recv().unwrap()
            else {
                panic!("expiring nonce invalidation must not replace the buffer");
            };
            assert_eq!(invalid.tx.hash(), rejected.hash());
            assert!(matches!(
                invalid.kind,
                InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported)
            ));
        }
    }

    #[test]
    fn expiring_nonce_invalidation_is_forwarded_without_filtering_other_transactions() {
        let sender = Address::random();
        let rejected = test_payment_tx_with_nonce_key(sender, 500_000, U256::MAX);
        let remaining = [
            test_payment_tx_with_nonce_key(sender, 600_000, U256::MAX),
            test_payment_tx(sender, 500_000),
            test_tx(sender, 0),
        ];
        let txs = std::iter::once(rejected.clone())
            .chain(remaining.iter().cloned())
            .collect();
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming(txs, log.clone());
        assert_eq!(prewarming.next().unwrap().tx.hash(), rejected.hash());
        wait_until(|| log.lock().unwrap().yielded == 4);

        prewarming.mark_invalid(
            &PrewarmedTransaction::without_replay(rejected),
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
        );
        wait_until(|| log.lock().unwrap().invalid == 1);
        for expected in remaining {
            assert_eq!(prewarming.next().unwrap().tx.hash(), expected.hash());
        }
    }
}
