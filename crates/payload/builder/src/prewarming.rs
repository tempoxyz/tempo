use std::{
    collections::VecDeque,
    sync::mpsc::{self, Receiver, Sender},
    time::Instant,
};

use alloy_primitives::B256;
use reth_evm::{ConfigureEvm, Evm, EvmEnvFor};
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{StateProviderBox, StateProviderFactory};
use reth_tasks::{TaskExecutor, pool::WorkerPool};
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_evm::{TempoEvmConfig, evm::TempoEvm};
use tempo_transaction_pool::best::BestTransaction;
use tracing::trace;

/// Total best-transaction window touched per advance: one returned immediately
/// plus buffered transactions prewarmed for the next builder iterations.
const PREWARMING_WINDOW: usize = 16;
const PREWARMING_BUFFERED_LOOKAHEAD: usize = PREWARMING_WINDOW - 1;

type PrewarmEvmState = Option<TempoEvm<StateProviderDatabase<StateProviderBox>>>;

/// Prewarming orchestrator that consumes source [`BestTransactions`] with bounded
/// lookahead, prewarms buffered transactions in parallel, and produces a new
/// [`BestTransactions`] iterator with the source order and invalidations triggered
/// by [`Self::mark_invalid`] preserved.
pub(crate) struct BestTransactionsPrewarming {
    commands_tx: Sender<BestTransactionsCommand>,
}

impl BestTransactionsPrewarming {
    /// Spawns prewarming for `best_txs` and returns a new [`BestTransactions`] iterator.
    pub(crate) fn new<Txs, Provider>(
        executor: TaskExecutor,
        evm_config: TempoEvmConfig,
        provider: Provider,
        parent_hash: B256,
        evm_env: EvmEnvFor<TempoEvmConfig>,
        best_txs: Txs,
    ) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
        Provider: StateProviderFactory + Clone + 'static,
    {
        let (commands_tx, commands_rx) = mpsc::channel();
        let prewarm = PrewarmingExecutionContext {
            evm_config,
            provider,
            parent_hash,
            evm_env,
        };
        let prewarm_executor = executor.clone();
        executor.spawn_blocking_named("builder-prewarm", move || {
            Self::start_prewarming(
                prewarm_executor,
                BestTransactionsPrewarmingContext {
                    best_txs,
                    commands_rx,
                    prewarm,
                },
            );
        });

        Self { commands_tx }
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
            let mut buffered_txs = VecDeque::new();
            let fill_prewarming_buffer =
                |ctx: &mut BestTransactionsPrewarmingContext<Txs, Provider>,
                 buffered_txs: &mut VecDeque<BestTransaction>| {
                    while buffered_txs.len() < PREWARMING_BUFFERED_LOOKAHEAD {
                        let Some(tx) = ctx.best_txs.next() else {
                            break;
                        };

                        let prewarm_tx = tx.clone();
                        buffered_txs.push_back(tx);

                        let prewarm = ctx.prewarm.clone();
                        scope.spawn(move |_| Self::prewarm_transaction(prewarm, prewarm_tx));
                    }
                };

            while let Ok(command) = ctx.commands_rx.recv() {
                match command {
                    BestTransactionsCommand::Advance { response } => {
                        let tx = buffered_txs.pop_front().or_else(|| ctx.best_txs.next());
                        let should_refill = tx.is_some();
                        let _ = response.send(tx);

                        if should_refill {
                            fill_prewarming_buffer(&mut ctx, &mut buffered_txs);
                        }
                    }
                    BestTransactionsCommand::Invalid(invalid) => {
                        ctx.best_txs.mark_invalid(&invalid.tx, invalid.kind);
                        buffered_txs
                            .retain(|tx| !is_invalidated_buffered_transaction(&invalid.tx, tx));
                        fill_prewarming_buffer(&mut ctx, &mut buffered_txs);
                    }
                    BestTransactionsCommand::NoUpdates => {
                        ctx.best_txs.no_updates();
                    }
                    BestTransactionsCommand::SkipBlobs(skip_blobs) => {
                        ctx.best_txs.set_skip_blobs(skip_blobs);
                    }
                    BestTransactionsCommand::Stop => {
                        return;
                    }
                }
            }
        });

        pool.clear();
    }

    fn prewarm_transaction<Provider>(
        prewarm: PrewarmingExecutionContext<Provider>,
        tx: BestTransaction,
    ) where
        Provider: StateProviderFactory + Clone + 'static,
    {
        WorkerPool::with_worker_mut(|worker| {
            let worker_state =
                worker.get_or_init::<PrewarmWorkerState>(PrewarmWorkerState::default);
            if worker_state.parent_hash != prewarm.parent_hash {
                worker_state.parent_hash = prewarm.parent_hash;
                worker_state.evm = prewarm.evm_for_ctx();
            }

            let Some(evm) = worker_state.evm.as_mut() else {
                return;
            };

            let start = Instant::now();
            let tx_hash = *tx.hash();
            let tx_env = tx.transaction.clone().into_with_tx_env().tx_env;

            if let Err(err) = evm.transact_raw(tx_env) {
                trace!(
                    target: "payload_builder",
                    %err,
                    ?tx_hash,
                    "Failed to prewarm transaction"
                );
                return;
            }

            trace!(
                target: "payload_builder",
                elapsed = ?start.elapsed(),
                ?tx_hash,
                "Prewarmed transaction"
            );
        });
    }
}

impl Drop for BestTransactionsPrewarming {
    fn drop(&mut self) {
        let _ = self.commands_tx.send(BestTransactionsCommand::Stop);
    }
}

impl Iterator for BestTransactionsPrewarming {
    type Item = BestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        let (response, rx) = mpsc::channel();
        self.commands_tx
            .send(BestTransactionsCommand::Advance { response })
            .ok()?;
        rx.recv().ok().flatten()
    }
}

impl BestTransactions for BestTransactionsPrewarming {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::Invalid(InvalidTransaction {
                tx: transaction.clone(),
                kind,
            }));
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
    commands_rx: Receiver<BestTransactionsCommand>,
    prewarm: PrewarmingExecutionContext<Provider>,
}

/// Context needed to execute prewarm transactions independently of the real builder.
#[derive(Clone)]
struct PrewarmingExecutionContext<Provider> {
    evm_config: TempoEvmConfig,
    provider: Provider,
    parent_hash: B256,
    evm_env: EvmEnvFor<TempoEvmConfig>,
}

#[derive(Default)]
struct PrewarmWorkerState {
    parent_hash: B256,
    evm: PrewarmEvmState,
}

impl<Provider> PrewarmingExecutionContext<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    fn evm_for_ctx(&self) -> PrewarmEvmState {
        let state_provider = match self.provider.state_by_block_hash(self.parent_hash) {
            Ok(provider) => provider,
            Err(err) => {
                trace!(
                    target: "payload_builder",
                    %err,
                    parent_hash = ?self.parent_hash,
                    "failed to build state provider for prewarm transaction"
                );
                return None;
            }
        };
        let state_provider = StateProviderDatabase::new(state_provider);
        let mut evm_env = self.evm_env.clone();
        evm_env.cfg_env.disable_nonce_check = true;
        evm_env.cfg_env.disable_balance_check = true;

        Some(self.evm_config.evm_with_env(state_provider, evm_env))
    }
}

/// Command sent by [`BestTransactionsPrewarming`] consumer.
#[derive(Debug)]
enum BestTransactionsCommand {
    Advance {
        response: Sender<Option<BestTransaction>>,
    },
    Invalid(InvalidTransaction),
    NoUpdates,
    SkipBlobs(bool),
    Stop,
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
        candidate.transaction.sender() == invalid.transaction.sender()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{BlockHeader, Header, Signed, TxLegacy};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use reth_evm::NextBlockEnvAttributes;
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
    use tempo_evm::TempoNextBlockEnvAttributes;
    use tempo_primitives::{TempoHeader, TempoPrimitives, TempoTxEnvelope};
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
        let tx = TxLegacy {
            chain_id: Some(42431),
            nonce,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
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

    fn prewarming(
        txs: Vec<BestTransaction>,
        log: Arc<Mutex<TestLog>>,
    ) -> BestTransactionsPrewarming {
        let executor = TaskExecutor::test();
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
            subblock_fee_recipients: Default::default(),
        };
        let evm_env = evm_config
            .next_evm_env(&parent_header, &attributes)
            .expect("test next block env");

        BestTransactionsPrewarming::new(
            executor,
            evm_config,
            provider,
            parent_header.hash(),
            evm_env,
            TestBestTransactions::new(txs, log),
        )
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
            .map(|_| *prewarming.next().expect("transaction").hash())
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn prewarming_window_limits_source_iterator_drain_after_first_advance() {
        let sender = Address::random();
        let txs = (0..PREWARMING_WINDOW + 4)
            .map(|nonce| test_tx(sender, nonce as u64))
            .collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming(txs, log.clone());
        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().yielded, 0);

        assert!(prewarming.next().is_some());
        wait_until(|| log.lock().unwrap().yielded == PREWARMING_WINDOW);
        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().yielded, PREWARMING_WINDOW);

        assert!(prewarming.next().is_some());
        wait_until(|| log.lock().unwrap().yielded == PREWARMING_WINDOW + 1);
    }

    #[test]
    fn empty_source_is_polled_once_per_advance() {
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming(Vec::new(), log.clone());

        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().empty_polls, 0);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == 1);
        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().empty_polls, 1);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == 2);
    }

    #[test]
    fn mark_invalid_filters_already_buffered_invalidated_transactions() {
        let sender = Address::random();
        let tx1 = test_tx(sender, 0);
        let tx2 = test_tx(sender, 1);
        let tx3 = test_tx(Address::random(), 0);
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming(vec![tx1.clone(), tx2.clone(), tx3.clone()], log.clone());
        assert_eq!(
            prewarming.next().as_ref().map(|tx| tx.hash()),
            Some(tx1.hash())
        );

        wait_until(|| log.lock().unwrap().yielded == 3);
        prewarming.mark_invalid(
            &tx1,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
        );

        let next = prewarming.next().expect("non-invalidated transaction");
        assert_eq!(next.hash(), tx3.hash());
        assert_ne!(next.hash(), tx2.hash());
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
}
