use std::{
    cell::RefCell,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
};

use alloy_primitives::B256;
use reth_engine_tree::tree::{CachedStateProvider, SavedCache};
use reth_evm::{Evm, EvmEnvFor};
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{StateProviderBox, StateProviderFactory};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_evm::{ExpiringNonceReplay, StorageActionReplay, TempoEvmConfig, evm::TempoEvm};
use tempo_transaction_pool::{StateAwarePoolTransaction, best::BestTransaction};
use tokio::sync::{mpsc as async_mpsc, oneshot};
use tracing::{instrument, trace};

use crate::wait::{TransactionWaiter, WaitResult};

pub(crate) type PrewarmEvmState = Option<TempoEvm<StateProviderDatabase<StateProviderBox>>>;

thread_local! {
    // EVMs are not Send. Keep them on their worker thread, separate from Reth's validator state.
    // The weak owner identifies the build and prevents its allocation from being reused too early.
    static PREWARM_EVM: RefCell<(Weak<AtomicBool>, PrewarmEvmState)> =
        const { RefCell::new((Weak::new(), None)) };
}

/// Prewarming orchestrator that consumes source [`BestTransactions`] with bounded
/// lookahead, prewarms buffered transactions in parallel, and produces a new
/// [`BestTransactions`] iterator with the source order and invalidations triggered
/// by [`Self::mark_invalid`] preserved.
pub(crate) struct BestTransactionsPrewarming {
    transactions_rx: async_mpsc::UnboundedReceiver<Option<PrewarmedTransaction>>,
    commands_tx: Sender<BestTransactionsCommand>,
    stop: Arc<AtomicBool>,
    /// Keep a timed-out consumer from queuing advances before a reply arrives.
    advance_pending: bool,
    pending_tx: Option<PrewarmedTransaction>,
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
        let (transactions_tx, transactions_rx) = async_mpsc::unbounded_channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let this = Self {
            transactions_rx,
            commands_tx: commands_tx.clone(),
            stop: prewarm.stop.clone(),
            advance_pending: false,
            pending_tx: None,
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

        pool.in_place_scope(|scope| {
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

                let ready = if !parallel {
                    let (ready_tx, ready_rx) = oneshot::channel();
                    let mut tx = PrewarmedTransaction::without_replay(tx.clone());
                    tx.ready = Some(ready_rx);
                    let _ = ctx.transactions_tx.send(Some(tx));
                    Some(ready_tx)
                } else {
                    None
                };

                scope.spawn(move |_| {
                    let tx = Self::prewarm_transaction(prewarm, tx, expiring_nonce_offset);
                    if parallel {
                        let _ = transactions_tx.send(Some(tx));
                    }
                    if let Some(ready) = ready {
                        let _ = ready.send(());
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
                        mut old_rx,
                        new_tx,
                    } => {
                        ctx.best_txs.mark_invalid(&invalid.tx, invalid.kind);
                        ctx.transactions_tx = new_tx;

                        while let Some(tx) = old_rx.blocking_recv() {
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

        let stop = &ctx.prewarm.stop;
        pool.broadcast(pool.current_num_threads(), |_| {
            PREWARM_EVM.with_borrow_mut(|(owner, evm)| {
                if std::ptr::eq(owner.as_ptr(), Arc::as_ptr(stop)) {
                    *owner = Weak::new();
                    *evm = None;
                }
            });
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
        let replay = prewarm.with_evm(|state| {
            if prewarm.parallel && !is_parallel_candidate(&tx) {
                return None;
            }

            let evm = state.as_mut()?;

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
            ready: None,
        }
    }
}

impl Drop for BestTransactionsPrewarming {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Move buffered transaction cleanup to the prewarm coordinator instead of this builder thread.
        let (_drain_tx, replacement_rx) = async_mpsc::unbounded_channel();
        let drain_rx = core::mem::replace(&mut self.transactions_rx, replacement_rx);
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::Stop { drain_rx });
    }
}

impl BestTransactionsPrewarming {
    /// Discard stale empty replies without hiding transactions already in the queue.
    fn try_next(&mut self) -> Option<PrewarmedTransaction> {
        while let Ok(tx) = self.transactions_rx.try_recv() {
            self.advance_pending = false;
            if tx.is_some() {
                return tx;
            }
        }
        None
    }

    fn request_advance(&mut self) -> Option<()> {
        if !self.advance_pending {
            self.commands_tx
                .send(BestTransactionsCommand::Advance)
                .ok()?;
            self.advance_pending = true;
        }
        Some(())
    }

    /// Preserve source order while waiting for prewarming to finish.
    pub(crate) fn next_with_waiter(
        &mut self,
        mut waiter: Option<&mut TransactionWaiter>,
    ) -> Option<PrewarmedTransaction> {
        if self.pending_tx.is_none() {
            self.pending_tx = self.next_transaction(waiter.as_deref_mut());
        }
        let tx = self.pending_tx.as_mut()?;
        if let Some(ready) = &mut tx.ready {
            if ready.try_recv() == Err(oneshot::error::TryRecvError::Empty) {
                if let Some(waiter) = waiter {
                    if matches!(waiter.wait(ready, false), WaitResult::TimedOut) {
                        return None;
                    }
                } else {
                    let _ = tx.ready.take().unwrap().blocking_recv();
                }
            }
            tx.ready = None;
        }
        self.pending_tx.take()
    }

    /// Wait on pool arrivals only after an empty reply from the coordinator.
    fn next_transaction(
        &mut self,
        waiter: Option<&mut TransactionWaiter>,
    ) -> Option<PrewarmedTransaction> {
        if let Some(tx) = self.try_next() {
            return Some(tx);
        }
        self.request_advance()?;
        let Some(waiter) = waiter else {
            let tx = self.transactions_rx.blocking_recv()?;
            self.advance_pending = false;
            return tx.or_else(|| self.try_next());
        };

        loop {
            match waiter.wait(self.transactions_rx.recv(), !self.advance_pending) {
                WaitResult::Ready(Some(tx)) => {
                    self.advance_pending = false;
                    if tx.is_some() {
                        return tx;
                    }
                }
                WaitResult::PoolChanged => self.request_advance()?,
                WaitResult::Ready(None) | WaitResult::TimedOut => return None,
            }
        }
    }
}

impl Iterator for BestTransactionsPrewarming {
    type Item = PrewarmedTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_with_waiter(None)
    }
}

impl BestTransactions for BestTransactionsPrewarming {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        if self
            .pending_tx
            .as_ref()
            .is_some_and(|tx| is_invalidated_buffered_transaction(&transaction.tx, &tx.tx))
        {
            self.pending_tx = None;
        }
        self.advance_pending = false;
        let (new_tx, new_rx) = async_mpsc::unbounded_channel();
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
    transactions_tx: async_mpsc::UnboundedSender<Option<PrewarmedTransaction>>,
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
    /// Ordered prewarming publishes the transaction first and completes it on the worker.
    ready: Option<oneshot::Receiver<()>>,
}

impl PrewarmedTransaction {
    pub(crate) fn without_replay(tx: BestTransaction) -> Self {
        Self {
            tx,
            replay: None,
            ready: None,
        }
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

    fn with_evm<R>(&self, f: impl FnOnce(&mut PrewarmEvmState) -> R) -> R {
        PREWARM_EVM.with_borrow_mut(|(owner, evm)| {
            if !std::ptr::eq(owner.as_ptr(), Arc::as_ptr(&self.stop)) {
                *owner = Arc::downgrade(&self.stop);
                *evm = self.evm_for_ctx();
            }
            f(evm)
        })
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
        old_rx: async_mpsc::UnboundedReceiver<Option<PrewarmedTransaction>>,
        new_tx: async_mpsc::UnboundedSender<Option<PrewarmedTransaction>>,
    },
    NoUpdates,
    SkipBlobs(bool),
    Stop {
        /// Receiver moved out of the builder thread so queued transactions drain on the coordinator.
        drain_rx: async_mpsc::UnboundedReceiver<Option<PrewarmedTransaction>>,
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
    use reth_tasks::WorkerPool;
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
        incoming: Option<Receiver<BestTransaction>>,
        log: Arc<Mutex<TestLog>>,
    }

    impl TestBestTransactions {
        fn new(txs: Vec<BestTransaction>, log: Arc<Mutex<TestLog>>) -> Self {
            Self {
                txs: txs.into(),
                incoming: None,
                log,
            }
        }
    }

    impl Iterator for TestBestTransactions {
        type Item = BestTransaction;

        fn next(&mut self) -> Option<Self::Item> {
            if let Some(incoming) = &self.incoming {
                self.txs.extend(incoming.try_iter());
            }
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
        }
    }

    fn prewarming_channels() -> (
        BestTransactionsPrewarming,
        async_mpsc::UnboundedSender<Option<PrewarmedTransaction>>,
        Receiver<BestTransactionsCommand>,
    ) {
        let (transactions_tx, transactions_rx) = async_mpsc::unbounded_channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        (
            BestTransactionsPrewarming {
                transactions_rx,
                commands_tx,
                stop: Arc::default(),
                advance_pending: false,
                pending_tx: None,
            },
            transactions_tx,
            commands_rx,
        )
    }

    fn test_waiter(executor: &TaskExecutor) -> (TransactionWaiter, async_mpsc::Sender<B256>) {
        let (pending_tx, pending_rx) = async_mpsc::channel(1);
        let mut waiter = TransactionWaiter::new(executor, pending_rx);
        waiter.set_deadline(Instant::now() + Duration::from_secs(5));
        (waiter, pending_tx)
    }

    fn expect_advance(commands: &Receiver<BestTransactionsCommand>) {
        assert!(matches!(
            commands.recv_timeout(Duration::from_secs(1)).unwrap(),
            BestTransactionsCommand::Advance
        ));
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
    fn ordered_prewarming_keeps_unfinished_work_across_timeouts() {
        let executor = TaskExecutor::test();
        let (mut waiter, _pending_tx) = test_waiter(&executor);
        let (mut prewarming, transactions_tx, commands_rx) = prewarming_channels();
        let sender = Address::random();
        let first = test_tx(sender, 0);
        let second = test_tx(sender, 1);
        let (ready_tx, ready_rx) = oneshot::channel();
        let mut pending = PrewarmedTransaction::without_replay(first.clone());
        pending.ready = Some(ready_rx);
        transactions_tx.send(Some(pending)).unwrap();
        transactions_tx
            .send(Some(PrewarmedTransaction::without_replay(second.clone())))
            .unwrap();

        for _ in 0..3 {
            waiter.set_deadline(Instant::now() + Duration::from_millis(1));
            assert!(prewarming.next_with_waiter(Some(&mut waiter)).is_none());
        }
        assert!(commands_rx.try_recv().is_err());
        assert_eq!(waiter.take_idle_elapsed(), Duration::ZERO);

        ready_tx.send(()).unwrap();
        assert_eq!(prewarming.next().unwrap().tx.hash(), first.hash());
        assert_eq!(prewarming.next().unwrap().tx.hash(), second.hash());
    }

    #[test]
    fn budgeted_wait_retries_on_pool_arrival_then_receives_ready_work() {
        let executor = TaskExecutor::test();
        let (mut waiter, pending_tx) = test_waiter(&executor);
        let (mut prewarming, transactions_tx, commands_rx) = prewarming_channels();
        let tx = test_tx(Address::random(), 0);
        let expected = *tx.hash();
        let coordinator = thread::spawn(move || {
            expect_advance(&commands_rx);
            transactions_tx.send(None).unwrap();
            // The builder must wait for this notification before asking for more work.
            assert!(commands_rx.recv_timeout(Duration::from_millis(10)).is_err());
            pending_tx.try_send(B256::ZERO).unwrap();
            expect_advance(&commands_rx);
            transactions_tx
                .send(Some(PrewarmedTransaction::without_replay(tx)))
                .unwrap();
        });
        assert_eq!(
            *prewarming
                .next_with_waiter(Some(&mut waiter))
                .unwrap()
                .tx
                .hash(),
            expected
        );
        assert!(waiter.take_idle_elapsed() > Duration::ZERO);
        coordinator.join().unwrap();
    }

    #[test]
    fn budgeted_wait_does_not_queue_advances_on_timeout() {
        let executor = TaskExecutor::test();
        let (mut waiter, _pending_tx) = test_waiter(&executor);
        let (mut prewarming, transactions_tx, commands_rx) = prewarming_channels();
        for _ in 0..3 {
            waiter.set_deadline(Instant::now() + Duration::from_millis(1));
            assert!(prewarming.next_with_waiter(Some(&mut waiter)).is_none());
        }
        assert!(matches!(
            commands_rx.try_recv().unwrap(),
            BestTransactionsCommand::Advance
        ));
        assert!(commands_rx.try_recv().is_err());
        assert_eq!(waiter.take_idle_elapsed(), Duration::ZERO);

        let tx = test_tx(Address::random(), 0);
        transactions_tx
            .send(Some(PrewarmedTransaction::without_replay(tx.clone())))
            .unwrap();
        waiter.set_deadline(Instant::now() + Duration::from_secs(1));
        assert_eq!(
            prewarming
                .next_with_waiter(Some(&mut waiter))
                .unwrap()
                .tx
                .hash(),
            tx.hash()
        );
    }

    #[test]
    fn ready_prewarm_wakes_an_idle_builder_without_a_pool_arrival() {
        let executor = TaskExecutor::test();
        let (mut waiter, _pending_tx) = test_waiter(&executor);
        let (mut prewarming, transactions_tx, commands_rx) = prewarming_channels();
        let tx = test_tx(Address::random(), 0);
        let expected = *tx.hash();
        let coordinator = thread::spawn(move || {
            expect_advance(&commands_rx);
            transactions_tx.send(None).unwrap();
            thread::sleep(Duration::from_millis(10));
            transactions_tx
                .send(Some(PrewarmedTransaction::without_replay(tx)))
                .unwrap();
        });
        assert_eq!(
            *prewarming
                .next_with_waiter(Some(&mut waiter))
                .unwrap()
                .tx
                .hash(),
            expected
        );
        coordinator.join().unwrap();
    }

    #[test]
    fn budgeted_wait_resumes_after_idle_in_both_prewarming_modes() {
        for parallel in [false, true] {
            let executor = TaskExecutor::test();
            let (mut waiter, pending_tx) = test_waiter(&executor);
            let (incoming, incoming_rx) = mpsc::channel();
            let mut source = TestBestTransactions::new(Vec::new(), Arc::default());
            source.incoming = Some(incoming_rx);
            let mut prewarming = TestPrewarming {
                prewarming: Some(BestTransactionsPrewarming::new(
                    prewarming_context(executor.clone(), parallel),
                    source,
                )),
                executor,
            };
            for _ in 0..2 {
                let txs = (0..16)
                    .map(|nonce| test_tx(Address::random(), nonce))
                    .collect::<Vec<_>>();
                let mut expected = txs.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
                let incoming = incoming.clone();
                let pending_tx = pending_tx.clone();
                let producer = thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    for tx in txs {
                        incoming.send(tx).unwrap();
                    }
                    pending_tx.try_send(B256::ZERO).unwrap();
                });
                waiter.set_deadline(Instant::now() + Duration::from_secs(5));
                let mut actual = (0..expected.len())
                    .map(|_| {
                        *prewarming
                            .next_with_waiter(Some(&mut waiter))
                            .unwrap()
                            .tx
                            .hash()
                    })
                    .collect::<Vec<_>>();
                if parallel {
                    actual.sort_unstable();
                    expected.sort_unstable();
                }
                assert_eq!(actual, expected);
                producer.join().unwrap();
            }
        }
    }

    #[test]
    fn invalidation_replaces_an_outstanding_advance() {
        let executor = TaskExecutor::test();
        let (mut waiter, _pending_tx) = test_waiter(&executor);
        let (mut prewarming, old_tx, commands_rx) = prewarming_channels();
        waiter.set_deadline(Instant::now() + Duration::from_millis(1));
        assert!(prewarming.next_with_waiter(Some(&mut waiter)).is_none());
        let valid = test_tx(Address::random(), 0);
        let expected = *valid.hash();
        prewarming.mark_invalid(
            &PrewarmedTransaction::without_replay(test_tx(Address::random(), 0)),
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
        );
        let coordinator = thread::spawn(move || {
            expect_advance(&commands_rx);
            let BestTransactionsCommand::Invalid { new_tx, .. } =
                commands_rx.recv_timeout(Duration::from_secs(1)).unwrap()
            else {
                panic!("expected invalidation")
            };
            drop(old_tx);
            expect_advance(&commands_rx);
            new_tx
                .send(Some(PrewarmedTransaction::without_replay(valid)))
                .unwrap();
        });
        waiter.set_deadline(Instant::now() + Duration::from_secs(5));
        assert_eq!(
            *prewarming
                .next_with_waiter(Some(&mut waiter))
                .unwrap()
                .tx
                .hash(),
            expected
        );
        coordinator.join().unwrap();
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
            let (mut prewarming, transactions_tx, commands_rx) = prewarming_channels();
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

            assert_eq!(prewarming.next().unwrap().tx.hash(), first.hash());
            assert_eq!(prewarming.next().unwrap().tx.hash(), second.hash());
            assert!(matches!(
                commands_rx.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
        }
    }

    #[test]
    fn stale_empty_replies_do_not_hide_a_fresh_advance() {
        let (mut prewarming, transactions_tx, commands_rx) = prewarming_channels();
        for _ in 0..32 {
            transactions_tx.send(None).unwrap();
        }
        let tx = test_tx(Address::random(), 0);
        let expected = *tx.hash();
        let coordinator = thread::spawn(move || {
            expect_advance(&commands_rx);
            transactions_tx
                .send(Some(PrewarmedTransaction::without_replay(tx)))
                .unwrap();
        });

        let next = prewarming.next();
        coordinator.join().unwrap();
        assert_eq!(*next.expect("fresh transaction").tx.hash(), expected);
    }

    #[test]
    fn empty_advance_returns_none_and_can_resume_on_a_later_poll() {
        let (mut prewarming, transactions_tx, commands_rx) = prewarming_channels();
        let tx = test_tx(Address::random(), 0);
        let expected = *tx.hash();
        let coordinator = thread::spawn(move || {
            for reply in [None, Some(PrewarmedTransaction::without_replay(tx))] {
                expect_advance(&commands_rx);
                transactions_tx.send(reply).unwrap();
            }
        });

        assert!(prewarming.next().is_none());
        assert_eq!(
            *prewarming.next().expect("later transaction").tx.hash(),
            expected
        );
        coordinator.join().unwrap();
        assert!(prewarming.next().is_none());
    }

    #[test]
    fn buffered_transactions_survive_empty_replies_and_coordinator_disconnect() {
        let (mut prewarming, transactions_tx, commands_rx) = prewarming_channels();
        let tx = test_tx(Address::random(), 0);
        let expected = *tx.hash();
        transactions_tx.send(None).unwrap();
        transactions_tx
            .send(Some(PrewarmedTransaction::without_replay(tx)))
            .unwrap();
        drop(transactions_tx);
        drop(commands_rx);

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
    fn prewarming_does_not_use_shared_worker_state_slot() {
        let executor = TaskExecutor::test();
        let pool = executor.prewarming_pool();
        pool.init::<usize>(|existing| existing.map(|value| *value).unwrap_or(1));

        let sender = Address::random();
        let txs = vec![test_tx(sender, 0)];
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming_with_executor(executor.clone(), txs, log);

        assert!(prewarming.next().is_some());
        drop(prewarming);

        pool.broadcast(pool.current_num_threads(), |worker| {
            assert_eq!(*worker.get::<usize>(), 1);
        });
    }

    #[test]
    fn prewarming_reinitializes_state_when_the_build_changes() {
        let executor = TaskExecutor::test();
        let first = prewarming_context(executor.clone(), false);
        let second = prewarming_context(executor, false);
        let pool = WorkerPool::new(1, "prewarm-context-test");
        pool.install_fn(|| {
            first.with_evm(|state| {
                assert!(state.is_some());
                *state = None;
            });
            first.with_evm(|state| assert!(state.is_none()));
            second.with_evm(|state| assert!(state.is_some()));
            first.with_evm(|state| assert!(state.is_some()));
        });
    }

    #[test]
    fn failed_prewarm_clears_actions_before_same_worker_is_reused() {
        let executor = TaskExecutor::test();
        let mut context = prewarming_context(executor, true);
        context.evm_env.block_env.basefee = 0;

        let pool = WorkerPool::new(1, "prewarm-actions-test");
        pool.install_fn(|| {
            let failed_action = StorageAction::Sstore(
                Address::random(),
                U256::from(1),
                U256::from(2),
                U256::from(3),
            );
            context.with_evm(|state| {
                let evm = state.as_mut().expect("prewarm EVM");
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
            context.with_evm(|state| {
                let evm = state.as_mut().expect("prewarm EVM");
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

        pool.clear();
    }
}
