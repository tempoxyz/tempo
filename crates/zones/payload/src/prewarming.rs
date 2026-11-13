//! Builder-local L1 cache prewarming.
//!
//! Each queued deposit and pool transaction is executed in an independent throwaway Zone builder.
//! Execution output is discarded; only L1 reads populate the cache shared with canonical execution.

use crate::builder::build_advance_tempo_tx_owned;
use alloy_primitives::{Address, B256, map::HashSet};
use futures::{
    FutureExt as _, StreamExt as _,
    future::{AbortHandle, Abortable, ready},
    stream,
};
use reth_evm::{
    BlockExecutor as _, ConfigureEvm, database::StateProviderDatabase, execute::BlockBuilder,
};
use reth_primitives_traits::{Recovered, SealedHeader};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::{BestTransactions, error::InvalidPoolTransactionError};
use std::{collections::VecDeque, error::Error, future::Future, sync::Arc, time::Duration};
use tempo_contracts::zones::DepositType;
use tempo_evm::{TempoNextBlockEnvAttributes, TempoTxEnv};
use tempo_primitives::TempoHeader;
use tempo_transaction_pool::best::BestTransaction;
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, trace};
use zone_evm::ZoneEvmConfig;
use zone_l1::{PreparedL1Block, state::L1StateProvider};
use zone_precompiles::{L1StateError, L1StorageReader};

/// Most Tempo commitment fetches in flight while prewarming one Zone block.
const MAX_COMMITMENT_FETCHES: usize = 64;

/// Longest wait for one prewarm commitment fetch, so a stalled Tempo RPC cannot leave a fetch task
/// behind per Zone block.
const COMMITMENT_FETCH_TIMEOUT: Duration = Duration::from_secs(1);

/// Most commitment misses queued for fetching; later misses are left to canonical execution.
const MAX_QUEUED_COMMITMENT_FETCHES: usize = 1024;

/// Most pool transactions simulated ahead of the builder. Pool execution starts only after
/// `advanceTempo`, so this is how much the pool warms while it runs.
const POOL_LOOKAHEAD: usize = 128;

/// One disposable simulation.
enum Simulation {
    /// A single-deposit `advanceTempo`, run through the Zone block executor.
    Deposit(Box<PreparedL1Block>),
    /// A pool transaction, run on the bare EVM: the Zone block executor rejects anything before the
    /// block's `advanceTempo`, which would end the simulation before any account is read.
    Pool(BestTransaction),
}

/// Immutable canonical inputs used to construct isolated prewarming workers.
pub(crate) struct PrewarmingExecutionContext<Provider> {
    task_executor: TaskExecutor,
    /// Stops the block's commitment fetch task once the context, and with it every simulation, is
    /// gone.
    fetches: AbortHandle,
    provider: Provider,
    evm_config: ZoneEvmConfig<L1StoragePrewarmer>,
    parent_header: SealedHeader<TempoHeader>,
    next_block_env_attributes: TempoNextBlockEnvAttributes,
    chain_id: u64,
}

impl<Provider> PrewarmingExecutionContext<Provider>
where
    Provider: StateProviderFactory + Send + Sync + 'static,
{
    /// Creates the context and spawns its [`L1StoragePrewarmer`] fetch task.
    pub(crate) fn new(
        task_executor: TaskExecutor,
        provider: Provider,
        evm_config: &ZoneEvmConfig,
        parent_header: SealedHeader<TempoHeader>,
        next_block_env_attributes: TempoNextBlockEnvAttributes,
        chain_id: u64,
        l1_block_number: u64,
    ) -> Arc<Self> {
        let (reader, fetch_task) =
            L1StoragePrewarmer::new(evm_config.l1_reader().clone(), l1_block_number);
        let (fetches, registration) = AbortHandle::new_pair();
        task_executor.spawn_task(Abortable::new(fetch_task, registration).map(drop));
        Arc::new(Self {
            task_executor,
            fetches,
            provider,
            evm_config: evm_config.with_l1_reader(reader),
            parent_header,
            next_block_env_attributes,
            chain_id,
        })
    }

    /// Enqueues one disposable simulation per deposit.
    pub(crate) fn start(self: &Arc<Self>, prepared: &PreparedL1Block) -> Prewarming {
        let handle = Prewarming::default();
        let mut decryptions = prepared.decryptions.iter();

        // The pool bounds concurrency; cancelled queued jobs skip EVM initialization.
        for deposit in &prepared.queued_deposits {
            let decryptions = (deposit.depositType == DepositType::Deposit)
                .then(|| decryptions.next().cloned())
                .flatten()
                .into_iter()
                .collect();
            let partial = PreparedL1Block {
                header: prepared.header.clone(),
                enabled_tokens: prepared.enabled_tokens.clone(),
                queued_deposits: vec![deposit.clone()],
                decryptions,
                recipients: Vec::new(),
                follows_checkpoint_blocks: false,
            };
            self.spawn(&handle.0, Simulation::Deposit(Box::new(partial)));
        }
        handle
    }

    /// Wraps the builder's pool iterator so each transaction is simulated before the builder takes
    /// it, while their gas limits fit in `gas`. Dropping the returned iterator cancels its queued
    /// simulations.
    pub(crate) fn lookahead<I: BestTransactions<Item = BestTransaction>>(
        self: &Arc<Self>,
        inner: I,
        gas: u64,
    ) -> PoolLookahead<I> {
        let (context, prewarming) = (self.clone(), Prewarming::default());
        PoolLookahead::new(
            inner,
            gas,
            Box::new(move |transaction| {
                context.spawn(&prewarming.0, Simulation::Pool(transaction.clone()))
            }),
        )
    }

    /// Enqueues `simulation` on the prewarming pool, skipped once `abort` is aborted.
    fn spawn(self: &Arc<Self>, abort: &AbortHandle, simulation: Simulation) {
        let (context, abort) = (self.clone(), abort.clone());
        self.task_executor.prewarming_pool().spawn(move || {
            if !abort.is_aborted()
                && let Err(error) = context.simulate(simulation)
            {
                // Failures are expected (queue-hash checks, parent-state nonces); reads before
                // the failure have already warmed the cache.
                trace!(target: "zone::payload", %error, "Prewarm simulation failed");
            }
        });
    }

    /// Executes `simulation` on a throwaway builder for the next block and discards the result.
    fn simulate(&self, simulation: Simulation) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut worker = self.evm_config.builder_for_next_block(
            StateProviderDatabase::new(
                self.provider
                    .state_by_block_hash(self.parent_header.hash())?
                    .into_evm_state_provider(),
            ),
            &self.parent_header,
            self.next_block_env_attributes.clone(),
        )?;
        worker.apply_pre_execution_changes()?;
        match simulation {
            Simulation::Deposit(partial) => {
                // Queue-hash validation may fail, but preceding reads have already warmed the
                // shared cache.
                worker.executor_mut().execute_transaction_without_commit(
                    build_advance_tempo_tx_owned(*partial, self.chain_id),
                )?;
            }
            Simulation::Pool(transaction) => {
                let transaction = transaction.to_consensus();
                let signer = transaction.signer();
                // A reverted transaction still warmed whatever it read.
                let _ = worker
                    .evm_mut()
                    .transact(&Recovered::new_unchecked(
                        TempoTxEnv::from(transaction),
                        signer,
                    ))?
                    .discard();
            }
        }
        Ok(())
    }
}

impl<Provider> Drop for PrewarmingExecutionContext<Provider> {
    fn drop(&mut self) {
        self.fetches.abort();
    }
}

/// Cancels queued work that has not started when dropped.
#[derive(Debug)]
pub(crate) struct Prewarming(AbortHandle);

impl Default for Prewarming {
    fn default() -> Self {
        Self(AbortHandle::new_pair().0)
    }
}

impl Drop for Prewarming {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Pool transactions in the inner iterator's order, each simulated up to [`POOL_LOOKAHEAD`]
/// transactions before it is yielded while their gas limits fit in the block's gas.
pub(crate) struct PoolLookahead<I> {
    inner: I,
    /// Taken from `inner` and already simulated, in order.
    buffer: VecDeque<BestTransaction>,
    /// Gas left for simulations.
    gas: u64,
    simulate: Box<dyn FnMut(&BestTransaction) + Send>,
}

impl<I: BestTransactions<Item = BestTransaction>> PoolLookahead<I> {
    pub(crate) fn new(
        inner: I,
        gas: u64,
        simulate: Box<dyn FnMut(&BestTransaction) + Send>,
    ) -> Self {
        let mut lookahead = Self {
            inner,
            buffer: VecDeque::with_capacity(POOL_LOOKAHEAD),
            gas,
            simulate,
        };
        lookahead.fill();
        lookahead
    }

    /// Tops the buffer up from `inner`, which also picks up transactions that entered the pool.
    fn fill(&mut self) {
        while self.buffer.len() < POOL_LOOKAHEAD
            && let Some(transaction) = self.inner.next()
        {
            if let Some(gas) = self.gas.checked_sub(transaction.gas_limit()) {
                self.gas = gas;
                (self.simulate)(&transaction);
            }
            self.buffer.push_back(transaction);
        }
    }
}

impl<I: BestTransactions<Item = BestTransaction>> Iterator for PoolLookahead<I> {
    type Item = BestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        self.fill();
        self.buffer.pop_front()
    }
}

impl<I: BestTransactions<Item = BestTransaction>> BestTransactions for PoolLookahead<I> {
    fn mark_invalid(&mut self, invalid: &Self::Item, kind: InvalidPoolTransactionError) {
        // `inner` skips the rest of the invalid transaction's nonce lane, where non-AA
        // transactions share nonce key 0, except for expiring-nonce transactions, which are
        // independent. Drop that lane's transactions already taken from it too.
        if !invalid.transaction.is_expiring_nonce() {
            let lane = |tx: &BestTransaction| {
                (tx.sender(), tx.transaction.nonce_key().unwrap_or_default())
            };
            let invalid_lane = lane(invalid);
            self.buffer.retain(|tx| lane(tx) != invalid_lane);
        }
        self.inner.mark_invalid(invalid, kind);
    }

    fn no_updates(&mut self) {
        self.inner.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.inner.set_skip_blobs(skip_blobs);
    }
}

/// A [`L1StorageReader`], used for simulations, that never blocks on a Tempo L1 commitment read.
///
/// Storage reads pass through unchanged. Cached commitments are returned as is.
/// Misses are queued for a parallel fetch and read as zero, like an unconfigured account.
#[derive(Clone)]
struct L1StoragePrewarmer {
    provider: L1StateProvider,
    l1_block_number: u64,
    fetches: mpsc::Sender<Address>,
}

impl L1StorageReader for L1StoragePrewarmer {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        self.provider.read_l1_storage(account, slot, block_number)
    }

    fn read_l1_commitment(
        &self,
        account: Address,
        _block_number: u64,
    ) -> Result<B256, L1StateError> {
        if let Some(commitment) = self
            .provider
            .cache()
            .lock()
            .get_commitment(account, self.l1_block_number)
        {
            return Ok(commitment);
        }
        // A miss dropped from a full queue is fetched by canonical execution instead.
        if let Err(TrySendError::Closed(_)) = self.fetches.try_send(account) {
            debug!(target: "zone::payload", %account, "Commitment prewarm fetch task stopped");
        }
        Ok(B256::ZERO)
    }
}

impl L1StoragePrewarmer {
    /// Returns a reader whose commitment misses are fetched at `l1_block_number`, and the task
    /// that fetches each missed account once, up to [`MAX_COMMITMENT_FETCHES`] at a time.
    ///
    /// The task ends once every clone of the reader is dropped and its fetches finish, or when
    /// aborted.
    fn new(
        provider: L1StateProvider,
        l1_block_number: u64,
    ) -> (Self, impl Future<Output = ()> + Send + 'static) {
        let (fetches, mut accounts) = mpsc::channel(MAX_QUEUED_COMMITMENT_FETCHES);
        let reader = Self {
            provider: provider.clone(),
            l1_block_number,
            fetches,
        };
        let task = async move {
            let provider = &provider;
            let mut fetched = HashSet::<Address>::default();
            stream::poll_fn(move |cx| accounts.poll_recv(cx))
                .filter(move |account| ready(fetched.insert(*account)))
                .for_each_concurrent(MAX_COMMITMENT_FETCHES, |account| async move {
                    // A failed fetch is retried by canonical execution on its own cache miss.
                    match tokio::time::timeout(
                        COMMITMENT_FETCH_TIMEOUT,
                        provider.read_l1_commitment_async(account, l1_block_number),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {}
                        Ok(Err(error)) => {
                            debug!(target: "zone::payload", %account, %error, "Commitment prewarm fetch failed");
                        }
                        Err(_) => {
                            debug!(target: "zone::payload", %account, "Commitment prewarm fetch timed out");
                        }
                    }
                })
                .await;
        };
        (reader, task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_provider::{Provider as _, ProviderBuilder, mock::Asserter};
    use alloy_rpc_types_eth::AccountInfo;
    use tempo_alloy::TempoNetwork;
    use tempo_primitives::account::encode_config_commitment;
    use zone_l1::{L1StateCache, state::L1StateProviderConfig};

    const TEMPO_BLOCK: u64 = 10;

    fn provider(asserter: Asserter) -> L1StateProvider {
        L1StateProvider::new_raw(
            L1StateProviderConfig::default(),
            L1StateCache::default(),
            ProviderBuilder::new_with_network::<TempoNetwork>()
                .connect_mocked_client(asserter)
                .erased(),
            tokio::runtime::Handle::current(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prewarm_reader_serves_cache_and_sends_misses() {
        // The mock has no answers, so any RPC would fail the reads below.
        let provider = provider(Asserter::new());
        let (cached, fresh) = (Address::repeat_byte(1), Address::repeat_byte(2));
        let (slot, value, commitment) = (
            B256::repeat_byte(3),
            B256::repeat_byte(4),
            B256::repeat_byte(5),
        );
        {
            let mut cache = provider.cache().lock();
            cache.set_commitment(cached, TEMPO_BLOCK, commitment);
            cache.set(cached, slot, TEMPO_BLOCK - 1, value);
        }
        let (fetches, mut sent) = mpsc::channel(8);
        let reader = L1StoragePrewarmer {
            provider,
            l1_block_number: TEMPO_BLOCK,
            fetches,
        };

        let reads = tokio::task::spawn_blocking(move || {
            (
                // Commitments resolve at the next Zone block's Tempo block, whatever the anchor.
                reader.read_l1_commitment(cached, TEMPO_BLOCK - 1),
                reader.read_l1_commitment(fresh, TEMPO_BLOCK - 1),
                reader.read_l1_commitment(fresh, TEMPO_BLOCK - 1),
                reader.read_l1_storage(cached, slot, TEMPO_BLOCK - 1),
            )
        })
        .await
        .unwrap();

        assert_eq!(
            reads,
            (Ok(commitment), Ok(B256::ZERO), Ok(B256::ZERO), Ok(value))
        );
        let mut misses = Vec::new();
        while let Some(account) = sent.recv().await {
            misses.push(account);
        }
        assert_eq!(misses, vec![fresh, fresh]);
    }

    #[tokio::test]
    async fn prewarm_reader_fetches_each_sent_account_once() {
        let asserter = Asserter::new();
        let (failed, fetched, commitment) = (
            Address::repeat_byte(1),
            Address::repeat_byte(2),
            B256::repeat_byte(5),
        );
        // `failed`'s one fetch errors, so a repeated fetch would take `fetched`'s answer.
        asserter.push_failure_msg("unavailable");
        asserter.push_success(&AccountInfo {
            extension: encode_config_commitment(commitment).into(),
            ..Default::default()
        });
        let provider = provider(asserter);
        let (reader, task) = L1StoragePrewarmer::new(provider.clone(), TEMPO_BLOCK);
        for account in [failed, failed, fetched] {
            reader.fetches.try_send(account).unwrap();
        }
        drop(reader);

        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap();

        let mut cache = provider.cache().lock();
        assert_eq!(cache.get_commitment(failed, TEMPO_BLOCK), None);
        assert_eq!(cache.get_commitment(fetched, TEMPO_BLOCK), Some(commitment));
    }

    #[tokio::test]
    async fn prewarm_reader_drops_misses_when_queue_is_full() {
        let (fetches, mut sent) = mpsc::channel(1);
        let reader = L1StoragePrewarmer {
            provider: provider(Asserter::new()),
            l1_block_number: TEMPO_BLOCK,
            fetches,
        };
        let (first, second) = (Address::repeat_byte(1), Address::repeat_byte(2));

        assert_eq!(
            reader.read_l1_commitment(first, TEMPO_BLOCK),
            Ok(B256::ZERO)
        );
        assert_eq!(
            reader.read_l1_commitment(second, TEMPO_BLOCK),
            Ok(B256::ZERO)
        );
        drop(reader);

        assert_eq!(sent.recv().await, Some(first));
        assert_eq!(sent.recv().await, None);
    }
}
