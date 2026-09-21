use crate::prewarming_state::{self, Slot};
use std::{
    cell::RefCell,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
};

use alloy_primitives::B256;
use reth_engine_tree::tree::{CachedStateProvider, ReadinessReporter, SavedCache};
use reth_evm::{Evm, EvmEnvFor};
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{StateProviderBox, StateProviderFactory};
use reth_tasks::{
    TaskExecutor, WorkerPool,
    prewarm_cpu::{Context as CpuContext, Job as CpuJob, Outcome as CpuOutcome},
};
use reth_tracing::readiness::{ReadTotals, Role as ReadinessRole, Scope as ReadinessScope};
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_evm::{ExpiringNonceReplay, StorageActionReplay, TempoEvmConfig, evm::TempoEvm};
use tempo_transaction_pool::{StateAwarePoolTransaction, best::BestTransaction};
use tracing::{instrument, trace};

pub(crate) type PrewarmEvmState = Option<TempoEvm<StateProviderDatabase<StateProviderBox>>>;

thread_local! {
    static BUILDER_PREWARM: RefCell<Slot<PrewarmEvmState>> = const {RefCell::new(Slot::new())};
}

struct ClearBuilderState<'a> {
    pool: &'a WorkerPool,
    owner: Weak<AtomicBool>,
}
impl Drop for ClearBuilderState<'_> {
    fn drop(&mut self) {
        self.pool
            .broadcast_fn(|| prewarming_state::clear(&BUILDER_PREWARM, &self.owner));
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
}

impl BestTransactionsPrewarming {
    /// Spawns prewarming for `best_txs` and returns a new [`BestTransactions`] iterator.
    pub(crate) fn new<Txs, Provider>(
        prewarm: PrewarmingExecutionContext<Provider>,
        best_txs: Txs,
        observer: CpuContext,
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
                    },
                    observer,
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
        observer: CpuContext,
    ) where
        Txs: BestTransactions<Item = BestTransaction>,
        Provider: StateProviderFactory + Clone + 'static,
    {
        let pool = executor.prewarming_pool();
        let _clear = ClearBuilderState {
            pool,
            owner: Arc::downgrade(&ctx.prewarm.stop),
        };

        pool.in_place_scope(|scope| {
            let prewarm = ctx.prewarm.clone();
            scope.spawn(move |_| {
                pool.broadcast_fn(|| {
                    prewarming_state::initialize(&BUILDER_PREWARM, &prewarm.stop, || {
                        prewarm.evm_for_ctx()
                    })
                });
            });

            let advance = |ctx: &mut BestTransactionsPrewarmingContext<Txs, Provider>| {
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

                if !parallel {
                    let _ = ctx
                        .transactions_tx
                        .send(Some(PrewarmedTransaction::without_replay(tx.clone())));
                }

                let cpu_job = observer.dispatch();
                scope.spawn(move |_| {
                    let tx = Self::prewarm_transaction(prewarm, tx, expiring_nonce_offset, cpu_job);
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
                    BestTransactionsCommand::Invalid {
                        invalid,
                        old_rx,
                        new_tx,
                    } => {
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
                }
            }
        });
        // The existing scope has joined every leaf. Normal TLS cleanup is excluded.
        observer.finish();
        drop(_clear);
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
        cpu_job: CpuJob,
    ) -> PrewarmedTransaction
    where
        Provider: StateProviderFactory + Clone + 'static,
    {
        let _readiness = prewarm
            .prewarm_read_totals
            .as_ref()
            .map(|totals| ReadinessScope::enter_shared(ReadinessRole::Prewarm, Arc::clone(totals)));
        let mut cpu = cpu_job.start();
        if prewarm.parallel && !is_parallel_candidate(&tx) {
            cpu.outcome(CpuOutcome::ParallelIneligible);
            return PrewarmedTransaction::without_replay(tx);
        }
        let replay = prewarming_state::with_state(
            &BUILDER_PREWARM,
            &prewarm.stop,
            || prewarm.evm_for_ctx(),
            |state| {
                let Some(evm) = state.as_mut() else {
                    cpu.outcome(CpuOutcome::EvmUnavailable);
                    return None;
                };

                if prewarm.is_stopped() {
                    cpu.outcome(CpuOutcome::Stopped);
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
                        cpu.outcome(CpuOutcome::ExecutionError);
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
                    cpu.outcome(CpuOutcome::Executed);
                    return None;
                }

                let Some(actions) = evm.take_actions() else {
                    cpu.outcome(CpuOutcome::ReplayUnavailable);
                    return None;
                };
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

                cpu.outcome(CpuOutcome::WithReplay);
                Some(Box::new(StorageActionReplay {
                    result,
                    actions,
                    validator_fee: evm.validator_fee(),
                    expiring_nonce,
                }))
            },
        );

        PrewarmedTransaction { tx, replay }
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
    }
}

impl Iterator for BestTransactionsPrewarming {
    type Item = PrewarmedTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(Some(tx)) = self.transactions_rx.try_recv() {
            return Some(tx);
        }
        self.commands_tx
            .send(BestTransactionsCommand::Advance)
            .ok()?;
        self.transactions_rx.recv().ok().flatten()
    }
}

impl BestTransactions for BestTransactionsPrewarming {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        let (new_tx, new_rx) = mpsc::channel();
        let old_rx = core::mem::replace(&mut self.transactions_rx, new_rx);
        let _ = self.commands_tx.send(BestTransactionsCommand::Invalid {
            invalid: InvalidTransaction {
                tx: transaction.tx.clone(),
                kind,
            },
            old_rx,
            new_tx,
        });
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
}

/// Prewarmed transaction returned from [`BestTransactionsPrewarming`] iterator.
#[derive(Debug)]
pub(crate) struct PrewarmedTransaction {
    pub(crate) tx: BestTransaction,
    pub(crate) replay: Option<Box<StorageActionReplay>>,
}

impl PrewarmedTransaction {
    pub(crate) fn without_replay(tx: BestTransaction) -> Self {
        Self { tx, replay: None }
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
    /// Keeps the summary alive until both builder execution and all prewarm workers finish,
    /// without retaining another execution-cache handle.
    _readiness_reporter: Option<Arc<ReadinessReporter>>,
    prewarm_read_totals: Option<Arc<ReadTotals>>,
    evm_env: EvmEnvFor<TempoEvmConfig>,
    stop: Arc<AtomicBool>,
    parallel: bool,
}

impl<Provider> PrewarmingExecutionContext<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    pub(crate) fn new(
        provider: Provider,
        executor: TaskExecutor,
        cache: Option<SavedCache>,
        readiness_reporter: Option<Arc<ReadinessReporter>>,
        parent_hash: B256,
        evm_env: EvmEnvFor<TempoEvmConfig>,
        parallel: bool,
    ) -> Self {
        let prewarm_read_totals = cache.as_ref().and_then(SavedCache::prewarm_read_totals);
        Self {
            provider,
            executor,
            parent_hash,
            cache,
            _readiness_reporter: readiness_reporter,
            prewarm_read_totals,
            evm_env,
            stop: Arc::new(AtomicBool::new(false)),
            parallel,
        }
    }

    pub(crate) fn evm_for_ctx(&self) -> PrewarmEvmState {
        let mut state_provider = match self.provider.state_by_block_hash(self.parent_hash) {
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

        if let Some(cache) = &self.cache {
            state_provider = Box::new(CachedStateProvider::new_prewarm(
                state_provider,
                cache.cache().clone(),
            ));
        }

        let state_provider = StateProviderDatabase::new(state_provider);

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
    Invalid {
        invalid: InvalidTransaction,
        old_rx: Receiver<Option<PrewarmedTransaction>>,
        new_tx: Sender<Option<PrewarmedTransaction>>,
    },
    NoUpdates,
    SkipBlobs(bool),
    Stop {
        /// Receiver moved out of the builder thread so queued transactions drain on the coordinator.
        drain_rx: Receiver<Option<PrewarmedTransaction>>,
    },
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
            .nonce_key()
            .is_some_and(|nonce_key| !nonce_key.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockHeader, Header, Signed, TxLegacy};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
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
            nonce_key: U256::ONE,
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
        let prewarming = BestTransactionsPrewarming::new(
            context,
            TestBestTransactions::new(txs, log),
            CpuContext::default(),
        );
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
            _readiness_reporter: None,
            prewarm_read_totals: None,
            evm_env,
            stop: Arc::default(),
            parallel,
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

    #[derive(Clone, Default)]
    struct Events(Arc<std::sync::Mutex<Vec<std::collections::BTreeMap<String, String>>>>);

    impl tracing::Subscriber for Events {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            #[derive(Default)]
            struct Fields(std::collections::BTreeMap<String, String>);
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.insert(field.name().into(), format!("{value:?}"));
                }
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.0.insert(field.name().into(), value.into());
                }
            }
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[test]
    fn observer_counts_parallel_ineligible_leaf_before_early_return() {
        const CHILD: &str = "TEMPO_TEST_PREWARM_INELIGIBLE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "prewarming::tests::observer_counts_parallel_ineligible_leaf_before_early_return", "--nocapture"])
                .env(CHILD, "1")
                .env("TEMPO_LIFECYCLE_PREWARM_CPU", "leaf_v1")
                .env("RETH_LIFECYCLE_FILE", "test-subscriber-only")
                .status().unwrap();
            assert!(status.success());
            return;
        }
        let events = Events::default();
        tracing::subscriber::with_default(events.clone(), || {
            let context = prewarming_context(TaskExecutor::test(), true);
            let observer = CpuContext::new(
                reth_tasks::prewarm_cpu::Role::Builder,
                reth_tasks::prewarm_cpu::Mode::Transactions,
            );
            let result = BestTransactionsPrewarming::prewarm_transaction(
                context,
                test_tx(Address::random(), 0),
                None,
                observer.dispatch(),
            );
            assert!(result.replay.is_none());
            assert!(BUILDER_PREWARM.with_borrow(|slot| slot.state().is_none()));
            observer.finish();
        });
        let rows = events.0.lock().unwrap();
        let selected: Vec<_> = rows
            .iter()
            .filter(|row| row.get("stage").is_some_and(|s| s.starts_with("prewarm_")))
            .collect();
        assert_eq!(
            selected
                .iter()
                .map(|row| row["stage"].as_str())
                .collect::<Vec<_>>(),
            [
                "prewarm_context_started",
                "prewarm_leaf_started",
                "prewarm_leaf_completed",
                "prewarm_context_completed"
            ]
        );
        assert_eq!(selected[2]["prewarm_outcome"], "7");
        assert_eq!(selected[3]["prewarm_dispatched"], "1");
        assert_eq!(selected[3]["prewarm_started"], "1");
        assert_eq!(selected[3]["prewarm_completed"], "1");
    }

    #[test]
    fn builder_prewarming_preserves_other_active_context_environment() {
        let executor = TaskExecutor::test();
        let pool = executor.prewarming_pool();
        let mut engine_context = prewarming_context(executor.clone(), false);
        engine_context.evm_env.block_env.number = U256::from(11);
        // This is the engine's concrete Tempo prewarm state type, not an unrelated usize.
        type EngineState =
            Option<reth_evm::EvmFor<TempoEvmConfig, StateProviderDatabase<StateProviderBox>>>;
        let same_type: EngineState = engine_context.evm_for_ctx();
        let _: PrewarmEvmState = same_type;
        pool.init::<EngineState>(|_| engine_context.evm_for_ctx());

        let mut builder_context = prewarming_context(executor.clone(), false);
        builder_context.evm_env.block_env.number = U256::from(22);
        let log = Arc::new(Mutex::new(TestLog::default()));
        let prewarming = BestTransactionsPrewarming::new(
            builder_context,
            TestBestTransactions::new(vec![], log),
            CpuContext::default(),
        );
        let running_builder = TestPrewarming {
            prewarming: Some(prewarming),
            executor: executor.clone(),
        };
        // Keep the real builder coordinator alive while its initial broadcast
        // completes; no leaf or provider mock is replacing the production initializer.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let initialized = AtomicBool::new(true);
            pool.broadcast_fn(|| {
                let current = BUILDER_PREWARM.with_borrow(|slot| {
                    slot.state()
                        .and_then(|state| state.as_ref())
                        .map(|evm| evm.block().number)
                });
                if current != Some(U256::from(22)) {
                    initialized.store(false, Ordering::Relaxed)
                }
            });
            if initialized.load(Ordering::Relaxed) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "builder initialization did not complete"
            );
            thread::yield_now();
        }
        let observed = pool.install_fn(|| {
            WorkerPool::with_worker_mut(|worker| {
                // Exact get_or_init pattern used by the engine transaction leaf.
                worker
                    .get_or_init::<EngineState>(|| engine_context.evm_for_ctx())
                    .as_ref()
                    .unwrap()
                    .block()
                    .number
            })
        });
        drop(running_builder);
        pool.broadcast(pool.current_num_threads(), |worker| {
            assert_eq!(
                worker.get::<EngineState>().as_ref().unwrap().block().number,
                U256::from(11)
            );
            assert!(BUILDER_PREWARM.with_borrow(|slot| slot.state().is_none()));
        });
        assert_eq!(
            observed,
            U256::from(11),
            "another active role replaced the selected call's EVM environment"
        );
    }

    #[test]
    fn builder_state_initialization_and_panic_cleanup_preserve_borrowed_engine_evm() {
        let executor = TaskExecutor::test();
        let pool = WorkerPool::new(1, "prewarm-nested-owner");
        let mut engine = prewarming_context(executor.clone(), false);
        engine.evm_env.block_env.number = U256::from(11);
        let mut builder = prewarming_context(executor, false);
        builder.evm_env.block_env.number = U256::from(22);
        pool.init::<PrewarmEvmState>(|_| engine.evm_for_ctx());
        pool.install_fn(|| {
            WorkerPool::with_worker_mut(|worker| {
                let engine_evm = worker.get_mut::<PrewarmEvmState>().as_mut().unwrap();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _clear = ClearBuilderState {
                        pool: &pool,
                        owner: Arc::downgrade(&builder.stop),
                    };
                    // Rayon services this callback while the shared engine slot remains borrowed.
                    pool.broadcast_fn(|| {
                        prewarming_state::initialize(&BUILDER_PREWARM, &builder.stop, || {
                            builder.evm_for_ctx()
                        })
                    });
                    prewarming_state::with_state(
                        &BUILDER_PREWARM,
                        &builder.stop,
                        || unreachable!(),
                        |state| {
                            assert_eq!(state.as_ref().unwrap().block().number, U256::from(22));
                            assert_eq!(engine_evm.block().number, U256::from(11));
                            panic!("synthetic builder leaf panic");
                        },
                    );
                }));
                assert!(result.is_err());
                assert!(BUILDER_PREWARM.with_borrow(|slot| slot.state().is_none()));
                assert_eq!(engine_evm.block().number, U256::from(11));
            })
        });
    }

    #[test]
    fn parallel_ineligible_leaf_does_not_initialize_builder_state() {
        let executor = TaskExecutor::test();
        let context = prewarming_context(executor, true);
        let pool = WorkerPool::new(1, "prewarm-ineligible");
        pool.install_fn(|| {
            let result = BestTransactionsPrewarming::prewarm_transaction(
                context,
                test_tx(Address::random(), 0),
                None,
                CpuJob::default(),
            );
            assert!(result.replay.is_none());
            assert!(BUILDER_PREWARM.with_borrow(|slot| slot.state().is_none()));
        });
    }

    #[test]
    fn prewarming_does_not_use_shared_worker_state_slot() {
        let executor = TaskExecutor::test();
        let pool = executor.prewarming_pool();
        pool.init::<usize>(|existing| existing.map(|value| *value).unwrap_or(1));

        let sender = Address::random();
        let txs = vec![test_tx(sender, 0)];
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming_with_executor(executor.clone(), txs, log);

        assert!(prewarming.next().is_some());

        pool.broadcast(pool.current_num_threads(), |worker| {
            assert_eq!(*worker.get::<usize>(), 1);
        });
    }

    #[test]
    fn failed_prewarm_clears_actions_before_same_worker_is_reused() {
        let executor = TaskExecutor::test();
        let mut context = prewarming_context(executor, true);
        context.evm_env.block_env.basefee = 0;

        let pool = WorkerPool::new(1, "prewarm-actions-test");
        let _clear = ClearBuilderState {
            pool: &pool,
            owner: Arc::downgrade(&context.stop),
        };
        pool.broadcast_fn(|| {
            prewarming_state::initialize(&BUILDER_PREWARM, &context.stop, || context.evm_for_ctx())
        });

        pool.install_fn(|| {
            let failed_action = StorageAction::Sstore(
                Address::random(),
                U256::from(1),
                U256::from(2),
                U256::from(3),
            );
            prewarming_state::with_state(
                &BUILDER_PREWARM,
                &context.stop,
                || unreachable!(),
                |state| {
                    let evm = state.as_mut().expect("prewarm EVM");
                    // Model an action recorded before the failed execution returned an error.
                    assert_eq!(evm.replace_actions(vec![failed_action]), Some(Vec::new()));
                },
            );

            let sender = Address::random();
            let failed = BestTransactionsPrewarming::prewarm_transaction(
                context.clone(),
                test_payment_tx(sender, 0),
                None,
                CpuJob::default(),
            );
            assert!(failed.replay.is_none());
            prewarming_state::with_state(
                &BUILDER_PREWARM,
                &context.stop,
                || unreachable!(),
                |state| {
                    let evm = state.as_mut().expect("prewarm EVM");
                    assert_eq!(evm.take_actions(), Some(Vec::new()));
                },
            );

            let successful = BestTransactionsPrewarming::prewarm_transaction(
                context,
                test_payment_tx(sender, 500_000),
                None,
                CpuJob::default(),
            );
            let replay = successful.replay.expect("successful prewarm replay");
            assert!(!replay.actions.is_empty());
            assert!(!replay.actions.contains(&failed_action));
        });
    }
}
