use std::{
    collections::{HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    time::Duration,
};

use alloy_consensus::transaction::Recovered;
use alloy_primitives::{Address, B256};
use reth_engine_tree::tree::{CachedStateProvider, SavedCache};
use reth_evm::{BlockExecutorFactory, EvmEnv, EvmEnvFor, database::StateProviderDatabase};
use reth_evm_ethereum::EvmFactory as _;
use reth_storage_api::{EvmStateProviderBox, StateProvider as _, StateProviderFactory};
use reth_tasks::{TaskExecutor, WorkerStatefulPool};
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_evm::{
    ExpiringNonceReplay, StorageActionReplay, TempoEvmConfig, TempoTxResult, evm::TempoEvm,
};
use tempo_transaction_pool::{AASequenceId, FeeBalances, best::BestTransaction};
use tracing::{instrument, trace};

/// How long [`BestTransactionsParallel::next_until`] waits for a result between two checks of
/// its stop condition.
const RESULT_POLL_INTERVAL: Duration = Duration::from_millis(1);

pub(crate) type PrewarmEvmState = Option<TempoEvm<'static>>;

/// The pool's best transactions in order, without those whose fee payer can no longer pay.
///
/// With prewarming, the next few transactions also execute on the prewarming pool while the
/// builder is busy with the ones before them, which loads the state they touch into the
/// execution cache. The builder takes every transaction from the source itself, so prewarming
/// runs a bounded number of transactions ahead of it and never holds it up.
pub(crate) struct BestTransactionsLookahead<Provider> {
    source: Box<dyn BestTransactions<Item = BestTransaction>>,
    fee_balances: FeeBalances,
    /// Transactions taken from the source that the builder has not asked for yet, in source
    /// order.
    ahead: VecDeque<BestTransaction>,
    /// How many transactions to hold in `ahead`.
    depth: usize,
    /// `None` without prewarming.
    prewarmer: Option<Prewarmer<Provider>>,
}

impl<Provider> BestTransactionsLookahead<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    /// Wraps `source`, prewarming its transactions with `prewarm` if there is one.
    ///
    /// `fallback_fee_tokens` lists the tokens execution may fall back to when no transaction
    /// field or fee-manager rule selects the fee token.
    pub(crate) fn new(
        source: Box<dyn BestTransactions<Item = BestTransaction>>,
        fallback_fee_tokens: &'static [Address],
        prewarm: Option<PrewarmingExecutionContext<Provider>>,
    ) -> Self {
        let prewarmer = prewarm.map(Prewarmer::new);
        Self {
            source,
            fee_balances: FeeBalances::new(fallback_fee_tokens),
            ahead: VecDeque::new(),
            depth: prewarmer.as_ref().map_or(1, Prewarmer::depth),
            prewarmer,
        }
    }

    /// Returns the next transaction whose fee payer can still pay, or `None` if the source has
    /// none right now or `should_stop` reports true.
    ///
    /// `should_stop` is checked before every candidate, so the caller decides how long a run of
    /// skipped transactions may go on for.
    pub(crate) fn next_until(
        &mut self,
        mut should_stop: impl FnMut() -> bool,
    ) -> Option<BestTransaction> {
        loop {
            if should_stop() {
                return None;
            }
            self.fill();
            let tx = self.ahead.pop_front()?;
            // Checked now and not when the transaction left the source: the transactions
            // included since then may have lowered the balance of its fee payer.
            match self.fee_balances.check(&tx) {
                Ok(()) => return Some(tx),
                Err(err) => self.mark_invalid(&tx, err),
            }
        }
    }

    /// Marks `tx` as invalid, which also skips the transactions that depend on it.
    pub(crate) fn mark_invalid(&mut self, tx: &BestTransaction, kind: InvalidPoolTransactionError) {
        self.source.mark_invalid(tx, kind);
        // The source stops yielding the lane of `tx`, but part of it may already wait here.
        // Expiring nonce transactions do not depend on each other.
        if !tx.transaction.is_expiring_nonce() {
            let lane = Lane::of(tx);
            self.ahead.retain(|ahead| Lane::of(ahead) != lane);
        }
    }

    /// Records the fee balances that an included transaction lowered.
    pub(crate) fn on_new_result(&mut self, result: &TempoTxResult) {
        self.fee_balances.on_new_result(result);
    }

    /// Takes transactions from the source until `depth` of them wait in `ahead`.
    fn fill(&mut self) {
        while self.ahead.len() < self.depth {
            let Some(tx) = self.source.next() else {
                return;
            };
            // A transaction that is about to be skipped is not worth a worker.
            if let Some(prewarmer) = &mut self.prewarmer
                && self.fee_balances.check(&tx).is_ok()
            {
                prewarmer.spawn(tx.clone(), None);
            }
            self.ahead.push_back(tx);
        }
    }
}

/// The pool's best transactions, executed on the prewarming pool ahead of the builder, which
/// only replays what a successful execution did.
///
/// Transactions come back in the order their execution finishes, not in source order, so that a
/// slow one does not hold back the rest.
pub(crate) struct BestTransactionsParallel<Provider> {
    source: Box<dyn BestTransactions<Item = BestTransaction>>,
    prewarmer: Prewarmer<Provider>,
    results_tx: Sender<PrewarmedTransaction>,
    results_rx: Receiver<PrewarmedTransaction>,
    /// Transactions handed to the pool whose result the builder has not taken yet.
    outstanding: usize,
    /// Most transactions to have outstanding.
    depth: usize,
    /// Lanes passed to [`Self::mark_invalid`]. Results on them are dropped as they arrive.
    invalidated: HashSet<Lane>,
}

impl<Provider> BestTransactionsParallel<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    /// Executes the transactions of `source` with `prewarm`.
    pub(crate) fn new(
        source: Box<dyn BestTransactions<Item = BestTransaction>>,
        prewarm: PrewarmingExecutionContext<Provider>,
    ) -> Self {
        let prewarmer = Prewarmer::new(prewarm);
        let (results_tx, results_rx) = mpsc::channel();
        Self {
            source,
            depth: prewarmer.depth(),
            prewarmer,
            results_tx,
            results_rx,
            outstanding: 0,
            invalidated: HashSet::new(),
        }
    }

    /// Returns the next executed transaction, or `None` if there is none to wait for or
    /// `should_stop` reports true.
    ///
    /// An execution takes as long as its transaction does. `should_stop` is checked every
    /// [`RESULT_POLL_INTERVAL`] while waiting, so the caller decides how long that may hold it
    /// up.
    pub(crate) fn next_until(
        &mut self,
        mut should_stop: impl FnMut() -> bool,
    ) -> Option<PrewarmedTransaction> {
        loop {
            if should_stop() {
                return None;
            }
            while self.outstanding < self.depth {
                let Some(tx) = self.source.next() else {
                    break;
                };
                self.prewarmer.spawn(tx, Some(self.results_tx.clone()));
                self.outstanding += 1;
            }
            if self.outstanding == 0 {
                return None;
            }
            match self.results_rx.recv_timeout(RESULT_POLL_INTERVAL) {
                Ok(tx) => {
                    self.outstanding -= 1;
                    // The source yielded this transaction before it saw the invalidation.
                    if !self.invalidated.contains(&Lane::of(&tx.tx)) {
                        return Some(tx);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                // `results_tx` keeps the channel open.
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// Marks `tx` as invalid, which also skips the transactions that depend on it.
    pub(crate) fn mark_invalid(&mut self, tx: &BestTransaction, kind: InvalidPoolTransactionError) {
        self.source.mark_invalid(tx, kind);
        // Expiring nonce transactions do not depend on each other.
        if !tx.transaction.is_expiring_nonce() {
            self.invalidated.insert(Lane::of(tx));
        }
    }
}

/// Executes transactions on the prewarming pool, each on top of the parent state.
struct Prewarmer<Provider> {
    ctx: Arc<PrewarmingExecutionContext<Provider>>,
    /// Owns the EVMs of the pool's workers. `None` only while dropping.
    workers: Option<Arc<WorkerStatefulPool>>,
    /// Number of expiring nonce transactions handed to the pool so far.
    expiring_nonce_transactions: usize,
}

impl<Provider> Prewarmer<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    fn new(ctx: PrewarmingExecutionContext<Provider>) -> Self {
        Self {
            workers: Some(WorkerStatefulPool::new(
                ctx.executor.prewarming_pool().clone(),
            )),
            ctx: Arc::new(ctx),
            expiring_nonce_transactions: 0,
        }
    }

    /// How many transactions to have on the pool at once.
    ///
    /// Twice the number of threads, so that a worker that finishes finds the next one waiting.
    fn depth(&self) -> usize {
        self.ctx.executor.prewarming_pool().current_num_threads() * 2
    }

    /// Queues `tx` for execution and sends the outcome to `results`, if given.
    fn spawn(&mut self, tx: BestTransaction, results: Option<Sender<PrewarmedTransaction>>) {
        let Some(workers) = self.workers.clone() else {
            return;
        };
        let expiring_nonce_offset = tx.transaction.is_expiring_nonce().then(|| {
            let offset = self.expiring_nonce_transactions;
            self.expiring_nonce_transactions += 1;
            offset
        });
        let ctx = self.ctx.clone();
        self.ctx.executor.prewarming_pool().spawn(move || {
            let tx = Self::prewarm_transaction(&workers, &ctx, tx, expiring_nonce_offset);
            if let Some(results) = results {
                // The build is over if nobody takes the result.
                let _ = results.send(tx);
            }
        });
    }

    /// Prewarms a transaction by executing it on top of the latest state.
    ///
    /// If [`PrewarmingExecutionContext::parallel`] is enabled and prewarming was successful,
    /// a [`PrewarmedTransaction`] with populated replay data is returned.
    #[instrument(level = "trace", skip_all, fields(parallel = prewarm.parallel, tx_hash = ?tx.hash()))]
    fn prewarm_transaction(
        pool: &WorkerStatefulPool,
        prewarm: &PrewarmingExecutionContext<Provider>,
        tx: BestTransaction,
        expiring_nonce_offset: Option<usize>,
    ) -> PrewarmedTransaction {
        if prewarm.parallel && !is_parallel_candidate(&tx) {
            return PrewarmedTransaction::without_replay(tx);
        }

        let replay = pool.get_or_init(
            || prewarm.evm_for_ctx(),
            |evm| {
                let evm = evm.as_mut()?;

                if prewarm.is_stopped() {
                    return None;
                }

                let mut tx_env = tx.transaction.clone_tx_env();
                tx_env.set_expiring_nonce_idx(expiring_nonce_offset);
                let tx_env = Recovered::new_unchecked(tx_env, tx.transaction.sender());

                let result = match evm.transact(&tx_env).map(|executed| executed.detach()) {
                    Ok(executed) => executed,
                    Err(err) => {
                        // Discard actions recorded by the failed transaction before reusing this worker.
                        evm.ext().actions.clear();
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

                let actions = evm.ext().actions.take()?;
                let expiring_nonce = tx
                    .transaction
                    .is_expiring_nonce()
                    .then(|| {
                        let valid_before = tx.transaction.inner().as_aa()?.tx().valid_before?.get();
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

                let spec = evm.config_spec_id();
                match StorageActionReplay::new(result, actions, expiring_nonce, spec) {
                    Ok(replay) => Some(Box::new(replay)),
                    Err(err) => {
                        trace!(
                            target: "payload_builder",
                            %err,
                            "Failed to generate replay for transaction"
                        );
                        None
                    }
                }
            },
        );

        PrewarmedTransaction { tx, replay }
    }
}

impl<Provider> Drop for Prewarmer<Provider> {
    fn drop(&mut self) {
        self.ctx.stop();
        // Dropping the last handle waits until every worker of the pool, busy or not, has
        // cleared its EVM. Leave that wait to a worker.
        if let Some(workers) = self.workers.take() {
            self.ctx
                .executor
                .prewarming_pool()
                .spawn(move || drop(workers));
        }
    }
}

/// Prewarmed transaction returned from [`BestTransactionsParallel`].
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

/// Context needed to prewarm transaction storage independently of the real builder.
#[derive(Clone)]
pub(crate) struct PrewarmingExecutionContext<Provider> {
    provider: Provider,
    executor: TaskExecutor,
    parent_hash: B256,
    cache: Option<SavedCache>,
    evm_env: EvmEnvFor<TempoEvmConfig>,
    evm_config: TempoEvmConfig,
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
        parent_hash: B256,
        evm_env: EvmEnvFor<TempoEvmConfig>,
        evm_config: TempoEvmConfig,
        parallel: bool,
    ) -> Self {
        Self {
            provider,
            executor,
            parent_hash,
            cache,
            evm_env,
            evm_config,
            stop: Arc::new(AtomicBool::new(false)),
            parallel,
        }
    }

    pub(crate) fn evm_for_ctx(&self) -> PrewarmEvmState {
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

        let state_provider = StateProviderDatabase::new(state_provider);

        let mut evm_env = self.evm_env.clone();

        if !self.parallel {
            evm_env = evm_env
                .with_nonce_check_disabled()
                .with_balance_check_disabled();
        }

        let mut evm = self.evm_config.evm_with_database(state_provider, evm_env);

        // Record storage actions for future replay
        if self.parallel {
            evm.ext_mut().actions.enable();
            // Enabling replaces the disabled recorder, so reconnect native precompiles
            // to the same action buffer used by protocol nonce and fee operations.
            BlockExecutorFactory::evm_factory(&self.evm_config).configure_evm(&mut evm);
        }

        Some(evm)
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

/// The transactions that an invalid transaction takes with it.
///
/// Invalidating a regular transaction blocks every later regular transaction from the same
/// sender. Invalidating a 2D nonce transaction blocks only its `(sender, nonce_key)` sequence.
#[derive(Debug, PartialEq, Eq, Hash)]
enum Lane {
    Sender(Address),
    Sequence(AASequenceId),
}

impl Lane {
    fn of(tx: &BestTransaction) -> Self {
        tx.transaction
            .aa_transaction_id()
            .filter(|_| tx.transaction.is_aa_2d())
            .map_or_else(
                || Self::Sender(tx.transaction.sender()),
                |id| Self::Sequence(*id.seq_id()),
            )
    }
}

/// Returns true if the transaction is a candidate for parallel prewarming.
fn is_parallel_candidate(tx: &BestTransaction) -> bool {
    // Payment lane transactions
    // TODO: switch to `is_payment_v3` after T15 is active.
    tx.transaction.is_payment_v2()
        // 2D or expiring nonces, no protocol nonces
        && tx
            .transaction
            .nonce_key_ref()
            .is_some_and(|nonce_key| !nonce_key.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockHeader, Header, SignableTransaction, TxLegacy};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
    use reth_primitives_traits::{
        Recovered, SealedHeader, transaction::error::InvalidTransactionError,
    };
    use reth_storage_api::noop::NoopProvider;
    use reth_tasks::WorkerPool;
    use reth_transaction_pool::{
        TransactionOrigin, ValidPoolTransaction, identifier::TransactionId,
    };
    use std::{num::NonZeroU64, sync::Mutex, thread, time::Instant};
    use tempo_chainspec::TempoChainSpec;
    use tempo_evm::{TempoEvmConfig, TempoNextBlockEnvAttributes};
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        storage::{StorageCtx, StorageKey, actions::StorageAction},
        tip20::{ITIP20, TIP20Token, tip20_slots},
    };
    use tempo_primitives::{
        TempoHeader, TempoPrimitives, TempoTransaction, TempoTxEnvelope, transaction::Call,
    };
    use tempo_transaction_pool::transaction::TempoPooledTransaction;

    #[derive(Debug, Default)]
    struct TestLog {
        yielded: usize,
        empty_polls: usize,
        invalid: usize,
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
            let mut log = self.log.lock().unwrap();
            if tx.is_some() {
                log.yielded += 1;
            } else {
                log.empty_polls += 1;
            }
            tx
        }
    }

    impl BestTransactions for TestBestTransactions {
        fn mark_invalid(&mut self, transaction: &Self::Item, _kind: InvalidPoolTransactionError) {
            self.log.lock().unwrap().invalid += 1;
            if !transaction.transaction.is_expiring_nonce() {
                let lane = Lane::of(transaction);
                self.txs.retain(|tx| Lane::of(tx) != lane);
            }
        }

        fn no_updates(&mut self) {}

        fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
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
        let envelope = TempoTxEnvelope::Legacy(tx.into_signed(Signature::test_signature()));
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

    type TestProvider = NoopProvider<TempoChainSpec, TempoPrimitives>;

    fn invalid_kind() -> InvalidPoolTransactionError {
        InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported)
    }

    /// A lookahead that holds `depth` of `txs` and does not prewarm them.
    fn lookahead(
        txs: Vec<BestTransaction>,
        depth: usize,
        log: Arc<Mutex<TestLog>>,
    ) -> BestTransactionsLookahead<TestProvider> {
        BestTransactionsLookahead {
            source: Box::new(TestBestTransactions::new(txs, log)),
            fee_balances: FeeBalances::new(&[]),
            ahead: VecDeque::new(),
            depth,
            prewarmer: None,
        }
    }

    /// Occupies every prewarming worker until the returned sender is dropped, so that the jobs
    /// spawned after it stay queued.
    fn block_workers(executor: &TaskExecutor) -> Sender<()> {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let pool = executor.prewarming_pool();
        for _ in 0..pool.current_num_threads() {
            let release_rx = release_rx.clone();
            pool.spawn(move || {
                let _ = release_rx.lock().unwrap().recv();
            });
        }
        release_tx
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
            evm_config,
            stop: Arc::default(),
            parallel,
        }
    }

    #[test]
    fn parallel_prewarming_preserves_custom_precompiles_builder() {
        static BUILDER_STATES: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let factory = tempo_evm::TempoEvmFactory::new_with_precompiles(|env, ext| {
            BUILDER_STATES.fetch_or(
                if ext.actions.is_enabled() { 2 } else { 1 },
                Ordering::Relaxed,
            );
            Box::new(tempo_precompiles::TempoPrecompiles::new(
                env.spec,
                ext.actions.clone(),
                ext.non_creditable_slots.clone(),
            ))
        });
        let mut context = prewarming_context(TaskExecutor::test(), true);
        context.evm_config = context.evm_config.with_evm_factory(factory);
        let evm = context.evm_for_ctx().expect("prewarming EVM");
        assert!(evm.ext().actions.is_enabled());
        assert_eq!(BUILDER_STATES.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn parallel_prewarm_records_native_transfer_balance_changes() {
        let mut context = prewarming_context(TaskExecutor::test(), true);
        context.evm_env.block.basefee = U256::ZERO;
        let mut evm = context.evm_for_ctx().expect("prewarm EVM");
        let sender = Address::repeat_byte(0x31);
        let recipient = Address::repeat_byte(0x32);
        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let mut token = TIP20Token::from_address(PATH_USD_ADDRESS).unwrap();
            token
                .initialize(sender, "pathUSD", "pathUSD", "USD", Address::ZERO, sender)
                .unwrap();
            token.increment_balance(sender, U256::from(1000)).unwrap();
        });
        evm.state_mut().commit_transaction();
        evm.state_mut().clear_transaction_state();
        evm.ext().actions.clear();

        // transfer(address,uint256), matching a payment transaction eligible for replay.
        let mut input = vec![0xa9, 0x05, 0x9c, 0xbb];
        input.extend_from_slice(&recipient.into_word().0);
        input.extend_from_slice(B256::with_last_byte(100).as_slice());
        let tx = TempoTransaction {
            chain_id: 42431,
            fee_token: Some(PATH_USD_ADDRESS),
            gas_limit: 1_000_000,
            calls: vec![Call {
                to: TxKind::Call(PATH_USD_ADDRESS),
                value: U256::ZERO,
                input: input.into(),
            }],
            nonce_key: U256::ONE,
            ..Default::default()
        };
        let envelope = TempoTxEnvelope::AA(tx.into_signed(Signature::test_signature().into()));
        let tx = tempo_evm::TempoTxEnv::from(Recovered::new_unchecked(envelope, sender));
        let result = evm
            .transact(&Recovered::new_unchecked(tx, sender))
            .expect("transfer transaction")
            .commit();
        assert!(result.status, "native transfer failed: {result:?}");
        let actions = evm.ext().actions.take().expect("enabled recorder");
        let sender_slot = sender.mapping_slot(tip20_slots::BALANCES);
        let recipient_slot = recipient.mapping_slot(tip20_slots::BALANCES);
        assert!(actions.contains(&StorageAction::Sstore(
            PATH_USD_ADDRESS,
            sender_slot,
            U256::from(1000),
            U256::from(900),
        )));
        assert!(actions.contains(&StorageAction::Sstore(
            PATH_USD_ADDRESS,
            recipient_slot,
            U256::ZERO,
            U256::from(100),
        )));
        StorageCtx::enter_evm_without_tip1060_accounting(&mut evm, || {
            let token = TIP20Token::from_address(PATH_USD_ADDRESS).unwrap();
            assert_eq!(
                token
                    .balance_of(ITIP20::balanceOfCall { account: sender })
                    .unwrap(),
                U256::from(900)
            );
            assert_eq!(
                token
                    .balance_of(ITIP20::balanceOfCall { account: recipient })
                    .unwrap(),
                U256::from(100)
            );
        });
    }

    #[test]
    fn failed_prewarm_clears_actions_before_same_worker_is_reused() {
        let executor = TaskExecutor::test();
        let mut context = prewarming_context(executor, true);
        context.evm_env.block.basefee = U256::ZERO;

        let pool = WorkerStatefulPool::new(Arc::new(WorkerPool::new(1, "prewarm-actions-test")));
        pool.init::<PrewarmEvmState>(|_| context.evm_for_ctx());

        pool.install_fn(|| {
            let failed_action =
                StorageAction::Sstore(Address::random(), U256::ONE, U256::from(2), U256::from(3));
            pool.get_or_init(
                || context.evm_for_ctx(),
                |evm| {
                    let evm = evm.as_mut().expect("prewarm EVM");
                    // Model an action recorded before the failed execution returned an error.
                    assert_eq!(
                        evm.ext().actions.replace(vec![failed_action]),
                        Some(Vec::new())
                    );
                },
            );

            let sender = Address::random();
            let failed =
                Prewarmer::prewarm_transaction(&pool, &context, test_payment_tx(sender, 0), None);
            assert!(failed.replay.is_none());
            pool.get_or_init(
                || context.evm_for_ctx(),
                |evm| {
                    let evm = evm.as_mut().expect("prewarm EVM");
                    assert_eq!(evm.ext().actions.take(), Some(Vec::new()));
                },
            );

            let successful = Prewarmer::prewarm_transaction(
                &pool,
                &context,
                test_payment_tx(sender, 500_000),
                None,
            );
            let replay = successful.replay.expect("successful prewarm replay");
            assert!(!replay.actions.is_empty());
            assert!(!replay.actions.contains(&failed_action));
        });
    }

    #[test]
    fn lookahead_yields_transactions_in_source_order() {
        let sender = Address::random();
        let txs = (0..10)
            .map(|nonce| test_tx(sender, nonce))
            .collect::<Vec<_>>();
        let expected = txs.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let mut lookahead = BestTransactionsLookahead::new(
            Box::new(TestBestTransactions::new(txs, Default::default())),
            &[],
            Some(prewarming_context(TaskExecutor::test(), false)),
        );

        let actual = std::iter::from_fn(|| lookahead.next_until(|| false))
            .map(|tx| *tx.hash())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn lookahead_takes_only_its_depth_from_the_source() {
        let sender = Address::random();
        let txs = (0..10).map(|nonce| test_tx(sender, nonce)).collect();
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut lookahead = lookahead(txs, 4, log.clone());

        assert!(lookahead.next_until(|| false).is_some());
        assert_eq!(log.lock().unwrap().yielded, 4);
        assert!(lookahead.next_until(|| false).is_some());
        assert_eq!(log.lock().unwrap().yielded, 5);
    }

    #[test]
    fn lookahead_polls_an_empty_source_once_per_call() {
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut lookahead = lookahead(Vec::new(), 4, log.clone());

        assert!(lookahead.next_until(|| false).is_none());
        assert_eq!(log.lock().unwrap().empty_polls, 1);
        assert!(lookahead.next_until(|| false).is_none());
        assert_eq!(log.lock().unwrap().empty_polls, 2);
    }

    #[test]
    fn lookahead_skips_a_transaction_whose_fee_payer_cannot_pay() {
        let drained = Address::random();
        let txs = vec![
            test_tx(drained, 0),
            test_tx(drained, 1),
            test_tx(Address::random(), 0),
        ];
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut lookahead = lookahead(txs.clone(), 4, log.clone());
        lookahead
            .fee_balances
            .set_balance(txs[0].transaction.fee_balance_slot().unwrap(), U256::ZERO);

        assert_eq!(
            lookahead.next_until(|| false).map(|tx| *tx.hash()),
            Some(*txs[2].hash())
        );
        // The second transaction of the drained sender went with the first.
        assert_eq!(log.lock().unwrap().invalid, 1);
        assert!(lookahead.next_until(|| false).is_none());
    }

    #[test]
    fn lookahead_stops_skipping_transactions_when_told_to() {
        let txs = (0..10)
            .map(|_| test_tx(Address::random(), 0))
            .collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut lookahead = lookahead(txs.clone(), 1, log.clone());
        // No fee payer can pay, so every transaction is skipped.
        for tx in &txs {
            lookahead
                .fee_balances
                .set_balance(tx.transaction.fee_balance_slot().unwrap(), U256::ZERO);
        }

        let mut checks = 0;
        let next = lookahead.next_until(|| {
            checks += 1;
            checks > 3
        });

        assert!(next.is_none());
        assert_eq!(log.lock().unwrap().invalid, 3);
        assert_eq!(log.lock().unwrap().yielded, 3);
    }

    #[test]
    fn lookahead_does_not_prewarm_a_transaction_whose_fee_payer_cannot_pay() {
        let executor = TaskExecutor::test();
        // Keeps the prewarm jobs queued, where each holds on to its transaction.
        let release = block_workers(&executor);
        let payable = test_tx(Address::random(), 0);
        let drained = test_tx(Address::random(), 0);
        let mut lookahead = BestTransactionsLookahead::new(
            Box::new(TestBestTransactions::new(
                vec![payable.clone(), drained.clone()],
                Default::default(),
            )),
            &[],
            Some(prewarming_context(executor, false)),
        );
        lookahead
            .fee_balances
            .set_balance(drained.transaction.fee_balance_slot().unwrap(), U256::ZERO);

        lookahead.fill();

        // One reference here, one in the lookahead, and for `payable` one in its prewarm job.
        assert_eq!(Arc::strong_count(&payable), 3);
        assert_eq!(Arc::strong_count(&drained), 2);
        drop(release);
    }

    #[test]
    fn mark_invalid_drops_waiting_transactions_on_the_same_lane() {
        let sender = Address::random();
        let invalid_regular = test_tx(sender, 0);
        let invalid_2d = test_payment_tx_with_nonce_key(sender, 500_000, U256::from(1));
        let waiting = [
            // Same sender as the invalid regular transaction.
            test_tx(sender, 1),
            // Same `(sender, nonce_key)` sequence as the invalid 2D transaction.
            test_payment_tx_with_nonce_key(sender, 500_000, U256::from(1)),
            // Other sequence of the same sender.
            test_payment_tx_with_nonce_key(sender, 500_000, U256::from(2)),
            test_tx(Address::random(), 0),
        ];
        let mut lookahead = lookahead(waiting.to_vec(), 8, Default::default());
        lookahead.fill();

        for invalid in [&invalid_regular, &invalid_2d] {
            lookahead.mark_invalid(invalid, invalid_kind());
        }

        for expected in &waiting[2..] {
            assert_eq!(
                lookahead.next_until(|| false).map(|tx| *tx.hash()),
                Some(*expected.hash())
            );
        }
        assert!(lookahead.next_until(|| false).is_none());
    }

    #[test]
    fn expiring_nonce_invalidation_keeps_waiting_transactions() {
        let sender = Address::random();
        let rejected = test_payment_tx_with_nonce_key(sender, 500_000, U256::MAX);
        let waiting = [
            test_payment_tx_with_nonce_key(sender, 600_000, U256::MAX),
            test_payment_tx(sender, 500_000),
            test_tx(sender, 0),
        ];
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut lookahead = lookahead(waiting.to_vec(), 8, log.clone());
        lookahead.fill();

        lookahead.mark_invalid(&rejected, invalid_kind());

        // The source hears of it, and nothing that waits depends on it.
        assert_eq!(log.lock().unwrap().invalid, 1);
        for expected in &waiting {
            assert_eq!(
                lookahead.next_until(|| false).map(|tx| *tx.hash()),
                Some(*expected.hash())
            );
        }
    }

    #[test]
    fn parallel_yields_every_transaction() {
        let txs = (0..10)
            .map(|_| test_tx(Address::random(), 0))
            .collect::<Vec<_>>();
        let expected = txs.iter().map(|tx| *tx.hash()).collect::<HashSet<_>>();
        let mut parallel = BestTransactionsParallel::new(
            Box::new(TestBestTransactions::new(txs, Default::default())),
            prewarming_context(TaskExecutor::test(), true),
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        let actual = std::iter::from_fn(|| parallel.next_until(|| Instant::now() >= deadline))
            .map(|tx| *tx.tx.hash())
            .collect::<HashSet<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn parallel_keeps_a_bounded_number_of_transactions_outstanding() {
        let executor = TaskExecutor::test();
        let release = block_workers(&executor);
        let depth = executor.prewarming_pool().current_num_threads() * 2;
        let txs = (0..depth + 5)
            .map(|_| test_tx(Address::random(), 0))
            .collect();
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut parallel = BestTransactionsParallel::new(
            Box::new(TestBestTransactions::new(txs, log.clone())),
            prewarming_context(executor, true),
        );

        let mut checks = 0;
        let next = parallel.next_until(|| {
            checks += 1;
            checks > 1
        });

        assert!(next.is_none());
        assert_eq!(log.lock().unwrap().yielded, depth);
        drop(release);
    }

    #[test]
    fn parallel_stops_waiting_for_an_execution_when_told_to() {
        let executor = TaskExecutor::test();
        let release = block_workers(&executor);
        let mut parallel = BestTransactionsParallel::new(
            Box::new(TestBestTransactions::new(
                vec![test_tx(Address::random(), 0)],
                Default::default(),
            )),
            prewarming_context(executor, true),
        );

        // Release the workers after a timeout so that a regression fails instead of hanging.
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let watchdog = thread::spawn(move || {
            let timed_out = done_rx.recv_timeout(Duration::from_secs(5)).is_err();
            drop(release);
            timed_out
        });

        let deadline = Instant::now() + Duration::from_millis(20);
        let next = parallel.next_until(|| Instant::now() >= deadline);
        let _ = done_tx.send(());

        assert!(
            !watchdog.join().unwrap(),
            "selection waited for an execution past its deadline"
        );
        assert!(next.is_none());
    }

    #[test]
    fn parallel_drops_results_on_an_invalidated_lane() {
        let sender = Address::random();
        let invalid = test_tx(sender, 0);
        let late_same_sender = test_tx(sender, 1);
        let other = test_tx(Address::random(), 0);
        let mut parallel = BestTransactionsParallel::new(
            Box::new(TestBestTransactions::new(Vec::new(), Default::default())),
            prewarming_context(TaskExecutor::test(), true),
        );
        parallel.mark_invalid(&invalid, invalid_kind());

        // Results of executions that started before the invalidation.
        for tx in [late_same_sender, other.clone()] {
            parallel
                .results_tx
                .send(PrewarmedTransaction::without_replay(tx))
                .unwrap();
            parallel.outstanding += 1;
        }

        assert_eq!(
            parallel.next_until(|| false).map(|tx| *tx.tx.hash()),
            Some(*other.hash())
        );
        assert!(parallel.next_until(|| false).is_none());
    }

    #[test]
    fn dropping_a_prewarmer_does_not_wait_for_a_busy_worker() {
        let executor = TaskExecutor::test();
        // One worker stays busy, as with a transaction of another build that does not return.
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        executor.prewarming_pool().spawn(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("worker started");
        let prewarmer = Prewarmer::new(prewarming_context(executor, false));

        // Release the worker after a timeout so that a regression fails instead of hanging.
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let watchdog = thread::spawn(move || {
            let timed_out = done_rx.recv_timeout(Duration::from_secs(5)).is_err();
            drop(release_tx);
            timed_out
        });

        drop(prewarmer);
        let _ = done_tx.send(());

        assert!(
            !watchdog.join().unwrap(),
            "dropping the prewarmer waited for a worker that another build keeps busy"
        );
    }
}
