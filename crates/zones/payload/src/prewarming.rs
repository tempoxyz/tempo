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
use tokio::sync::mpsc;
use tracing::{debug, trace};
use zone_evm::ZoneEvmConfig;
use zone_l1::{PreparedL1Block, state::L1StateProvider};
use zone_precompiles::{L1StateError, L1StorageReader};

/// Most Tempo commitment fetches in flight per Zone block.
const MAX_COMMITMENT_FETCHES: usize = 64;

/// Longest wait per commitment fetch, so a stalled Tempo RPC can't hold up the fetch task.
const COMMITMENT_FETCH_TIMEOUT: Duration = Duration::from_secs(1);

/// Most pool txs simulated ahead of the builder, i.e. what warms while `advanceTempo` runs.
const POOL_LOOKAHEAD: usize = 128;

/// One disposable simulation.
enum Simulation {
    /// A single-deposit `advanceTempo`, run through the Zone block executor.
    Deposit(Box<PreparedL1Block>),
    /// A pool tx on the bare EVM, since the Zone executor rejects txs before `advanceTempo`.
    Pool(BestTransaction),
}

/// Immutable canonical inputs used to construct isolated prewarming workers.
pub(crate) struct PrewarmingExecutionContext<Provider> {
    task_executor: TaskExecutor,
    fetch_task: AbortHandle,
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
        let (abort, registration) = AbortHandle::new_pair();
        task_executor.spawn_task(Abortable::new(fetch_task, registration).map(drop));
        Arc::new(Self {
            task_executor,
            fetch_task: abort,
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

    /// Wraps the builder's pool iterator to simulate each tx before it's taken.
    /// Dropping the iterator cancels its queued simulations.
    pub(crate) fn lookahead<I: BestTransactions<Item = BestTransaction>>(
        self: &Arc<Self>,
        inner: I,
    ) -> PoolLookahead<I> {
        let (context, prewarming) = (self.clone(), Prewarming::default());
        PoolLookahead::new(
            inner,
            Box::new(move |tx| context.spawn(&prewarming.0, Simulation::Pool(tx.clone()))),
        )
    }

    /// Enqueues `simulation` on the prewarming pool, skipped once `abort` is aborted.
    fn spawn(self: &Arc<Self>, abort: &AbortHandle, simulation: Simulation) {
        let (context, abort) = (self.clone(), abort.clone());
        self.task_executor.prewarming_pool().spawn(move || {
            if !abort.is_aborted()
                && let Err(error) = context.simulate(simulation)
            {
                // Expected (queue-hash checks, parent-state nonces); earlier reads still warmed.
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
                // Queue-hash validation may fail, but earlier reads already warmed the cache.
                worker.executor_mut().execute_transaction_without_commit(
                    build_advance_tempo_tx_owned(*partial, self.chain_id),
                )?;
            }
            Simulation::Pool(tx) => {
                let tx = tx.to_consensus();
                let signer = tx.signer();
                // A reverted tx still warmed whatever it read.
                let _ = worker
                    .evm_mut()
                    .transact(&Recovered::new_unchecked(TempoTxEnv::from(tx), signer))?
                    .discard();
            }
        }
        Ok(())
    }
}

impl<Provider> Drop for PrewarmingExecutionContext<Provider> {
    fn drop(&mut self) {
        self.fetch_task.abort();
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

/// Yields `inner`'s txs in order, simulating each up to [`POOL_LOOKAHEAD`] txs ahead.
pub(crate) struct PoolLookahead<I> {
    inner: I,
    buffer: VecDeque<BestTransaction>,
    simulate: Box<dyn FnMut(&BestTransaction) + Send>,
}

impl<I: BestTransactions<Item = BestTransaction>> PoolLookahead<I> {
    pub(crate) fn new(inner: I, simulate: Box<dyn FnMut(&BestTransaction) + Send>) -> Self {
        let mut lookahead = Self {
            inner,
            buffer: VecDeque::with_capacity(POOL_LOOKAHEAD),
            simulate,
        };
        lookahead.fill();
        lookahead
    }

    /// Tops the buffer up from `inner`, which also yields txs that entered the pool.
    fn fill(&mut self) {
        while self.buffer.len() < POOL_LOOKAHEAD
            && let Some(tx) = self.inner.next()
        {
            (self.simulate)(&tx);
            self.buffer.push_back(tx);
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
        // `inner` skips the rest of a non-expiring tx's nonce lane (non-AA txs use key 0), so drop
        // the lane's buffered txs too.
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

/// An [`L1StorageReader`] for simulations that never blocks on a commitment: misses are queued for
/// a parallel fetch and read as zero, like an unconfigured account.
#[derive(Clone)]
struct L1StoragePrewarmer {
    provider: L1StateProvider,
    l1_block_number: u64,
    fetches: mpsc::UnboundedSender<Address>,
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
        if self.fetches.send(account).is_err() {
            debug!(target: "zone::payload", %account, "Commitment prewarm fetch task stopped");
        }
        Ok(B256::ZERO)
    }
}

impl L1StoragePrewarmer {
    /// Returns a reader and its task, which fetches each missed account once at `l1_block_number`
    /// and ends once every reader clone is dropped.
    fn new(
        provider: L1StateProvider,
        l1_block_number: u64,
    ) -> (Self, impl Future<Output = ()> + Send + 'static) {
        // Bounded by the lookahead's txs, each paying `L1_COMMITMENT_READ_GAS` per read.
        let (fetches, mut accounts) = mpsc::unbounded_channel();
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
                    let fetch = provider.read_l1_commitment_async(account, l1_block_number);
                    let result = tokio::time::timeout(COMMITMENT_FETCH_TIMEOUT, fetch).await;
                    if !matches!(result, Ok(Ok(_))) {
                        debug!(target: "zone::payload", %account, ?result, "Prewarm fetch failed");
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
    async fn prewarm_reader_serves_cache_and_queues_misses() {
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
        let (fetches, mut sent) = mpsc::unbounded_channel();
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
        assert_eq!(
            std::iter::from_fn(|| sent.try_recv().ok()).collect::<Vec<_>>(),
            [fresh, fresh]
        );
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
            reader.fetches.send(account).unwrap();
        }
        drop(reader);

        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap();

        let mut cache = provider.cache().lock();
        assert_eq!(cache.get_commitment(failed, TEMPO_BLOCK), None);
        assert_eq!(cache.get_commitment(fetched, TEMPO_BLOCK), Some(commitment));
    }
}
