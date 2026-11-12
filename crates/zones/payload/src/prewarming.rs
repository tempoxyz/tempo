//! Builder-local L1 cache prewarming.
//!
//! Deposits and pool transactions are executed in independent throwaway Zone builders. Execution
//! output is discarded; only L1 reads populate the cache shared with canonical execution.
//!
//! Pool transactions run on the bare EVM, since the Zone block executor rejects anything before
//! the block's `advanceTempo`, which would end the simulation before any account is read.

use crate::builder::build_advance_tempo_tx_owned;
use alloy_primitives::{Address, B256, map::HashSet};
use futures::{
    Stream, StreamExt as _,
    channel::{mpsc, oneshot},
    future::{Either, ready, select},
};
use reth_evm::{
    BlockExecutor as _, ConfigureEvm, database::StateProviderDatabase, execute::BlockBuilder,
};
use reth_primitives_traits::{Recovered, SealedHeader};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_tasks::{TaskExecutor, cancel::ManualCancel};
use reth_transaction_pool::ValidPoolTransaction;
use std::{error::Error, future::Future, sync::Arc};
use tempo_contracts::zones::DepositType;
use tempo_evm::{TempoNextBlockEnvAttributes, TempoTxEnv};
use tempo_primitives::{TempoHeader, TempoTxEnvelope};
use tempo_transaction_pool::transaction::TempoPooledTransaction;
use tracing::{debug, trace};
use zone_evm::ZoneEvmConfig;
use zone_l1::{PreparedL1Block, state::L1StateProvider};
use zone_precompiles::{L1StateError, L1StorageReader};

/// Most Tempo commitment fetches in flight while prewarming one Zone block.
const MAX_COMMITMENT_FETCHES: usize = 64;

/// A throwaway builder for the next block on the parent state. A macro, since the builder's type
/// is opaque and a helper returning it would hide its EVM's transaction type.
macro_rules! prewarm_worker {
    ($context:expr) => {
        $context.evm_config.builder_for_next_block(
            StateProviderDatabase::new(
                $context
                    .provider
                    .state_by_block_hash($context.parent_header.hash())?
                    .into_evm_state_provider(),
            ),
            &$context.parent_header,
            $context.next_block_env_attributes.clone(),
        )?
    };
}

/// A prewarm simulation's outcome; only its L1 reads matter.
type SimulationResult = Result<(), Box<dyn Error + Send + Sync>>;

/// Immutable canonical inputs used to construct isolated prewarming workers.
pub(crate) struct PrewarmingExecutionContext<Provider> {
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
        task_executor: &TaskExecutor,
        provider: Provider,
        evm_config: &ZoneEvmConfig,
        parent_header: SealedHeader<TempoHeader>,
        next_block_env_attributes: TempoNextBlockEnvAttributes,
        chain_id: u64,
        l1_block_number: u64,
    ) -> Arc<Self> {
        let (reader, fetch_task) =
            L1StoragePrewarmer::new(evm_config.l1_reader().clone(), l1_block_number);
        task_executor.spawn_task(fetch_task);
        let evm_config = ZoneEvmConfig::new(
            evm_config.chain_spec().clone(),
            reader,
            evm_config.portal_address(),
        );
        Arc::new(Self {
            provider,
            evm_config,
            parent_header,
            next_block_env_attributes,
            chain_id,
        })
    }

    /// Enqueues one disposable simulation per deposit.
    pub(crate) fn start(
        self: &Arc<Self>,
        task_executor: &TaskExecutor,
        prepared: &PreparedL1Block,
    ) -> Prewarming {
        let mut decryptions = prepared.decryptions.iter();
        let partials = prepared.queued_deposits.iter().map(|deposit| {
            let decryptions = (deposit.depositType == DepositType::Deposit)
                .then(|| decryptions.next().cloned())
                .flatten()
                .into_iter()
                .collect();
            PreparedL1Block {
                header: prepared.header.clone(),
                enabled_tokens: prepared.enabled_tokens.clone(),
                queued_deposits: vec![deposit.clone()],
                decryptions,
                recipients: Vec::new(),
                follows_checkpoint_blocks: false,
            }
        });
        // Queue-hash validation may fail, but earlier reads have already warmed the cache.
        let handle = Prewarming::default();
        for partial in partials {
            self.spawn(task_executor, &handle, partial, |partial, context| {
                context.execute_opening(build_advance_tempo_tx_owned(partial, context.chain_id))
            });
        }
        handle
    }

    /// Enqueues one disposable simulation per pool transaction, then one per transaction that
    /// enters the pending pool until the returned handle is dropped.
    ///
    /// A build can outlast many pool arrivals while canonical execution waits on serial L1 reads;
    /// following the pool lets those later transactions warm the cache ahead of execution.
    pub(crate) fn start_pool(
        self: &Arc<Self>,
        task_executor: &TaskExecutor,
        transactions: impl IntoIterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        mut arrivals: impl Stream<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>
        + Send
        + Unpin
        + 'static,
    ) -> Prewarming {
        let mut handle = Prewarming::default();
        for transaction in transactions {
            self.spawn(task_executor, &handle, transaction, Self::execute_pool);
        }
        let (stop, mut stopped) = oneshot::channel::<()>();
        handle.stop = Some(stop);
        let (context, executor, follower) = (self.clone(), task_executor.clone(), handle.child());
        task_executor.spawn_task(async move {
            while let Either::Left((Some(transaction), pending)) =
                select(arrivals.next(), stopped).await
            {
                stopped = pending;
                context.spawn(&executor, &follower, transaction, Self::execute_pool);
            }
        });
        handle
    }

    /// Enqueues one simulation of `item` on the prewarming pool, skipped once `handle` is
    /// cancelled.
    fn spawn<T: Send + 'static>(
        self: &Arc<Self>,
        task_executor: &TaskExecutor,
        handle: &Prewarming,
        item: T,
        simulate: fn(T, &Self) -> SimulationResult,
    ) {
        let context = self.clone();
        let cancel = handle.cancel.clone();
        task_executor.prewarming_pool().spawn(move || {
            if !cancel.is_cancelled()
                && let Err(error) = simulate(item, &context)
            {
                // Failures are expected (queue-hash checks, parent-state nonces); reads before
                // the failure have already warmed the cache.
                trace!(target: "zone::payload", %error, "Prewarm simulation failed");
            }
        });
    }

    /// Executes the opening `advanceTempo` through the Zone block executor and discards the
    /// result.
    fn execute_opening(&self, transaction: Recovered<TempoTxEnvelope>) -> SimulationResult {
        let mut worker = prewarm_worker!(self);
        worker.apply_pre_execution_changes()?;
        worker
            .executor_mut()
            .execute_transaction_without_commit(transaction)?;
        Ok(())
    }

    /// Executes a pool transaction on the bare EVM and discards the result.
    fn execute_pool(
        transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        context: &Self,
    ) -> SimulationResult {
        let mut worker = prewarm_worker!(context);
        worker.apply_pre_execution_changes()?;
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
        Ok(())
    }
}

/// Cancels queued work that has not started, and stops following the pool, when dropped.
#[derive(Debug, Default)]
pub(crate) struct Prewarming {
    cancel: ManualCancel,
    /// Dropping it ends the task that follows new pool transactions.
    stop: Option<oneshot::Sender<()>>,
}

impl Prewarming {
    /// A handle sharing this one's cancellation, for work queued after it was created.
    fn child(&self) -> Self {
        Self {
            cancel: self.cancel.clone(),
            stop: None,
        }
    }
}

impl Drop for Prewarming {
    fn drop(&mut self) {
        self.cancel.clone().cancel();
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
        if let Err(error) = self.fetches.unbounded_send(account) {
            debug!(target: "zone::payload", %account, %error, "Commitment prewarm fetch task stopped");
        }
        Ok(B256::ZERO)
    }
}

impl L1StoragePrewarmer {
    /// Returns a reader whose commitment misses are fetched at `l1_block_number`, and the task
    /// that fetches each missed account once, up to [`MAX_COMMITMENT_FETCHES`] at a time.
    ///
    /// The task ends once every clone of the reader is dropped and its fetches finish.
    fn new(
        provider: L1StateProvider,
        l1_block_number: u64,
    ) -> (Self, impl Future<Output = ()> + Send + 'static) {
        let (fetches, accounts) = mpsc::unbounded();
        let reader = Self {
            provider: provider.clone(),
            l1_block_number,
            fetches,
        };
        let task = async move {
            let provider = &provider;
            let mut fetched = HashSet::<Address>::default();
            accounts
                .filter(move |account| ready(fetched.insert(*account)))
                .for_each_concurrent(MAX_COMMITMENT_FETCHES, |account| async move {
                    // A failed fetch is retried by canonical execution on its own cache miss.
                    if let Err(error) = provider
                        .read_l1_commitment_async(account, l1_block_number)
                        .await
                    {
                        debug!(target: "zone::payload", %account, %error, "Commitment prewarm fetch failed");
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
        let (fetches, sent) = mpsc::unbounded();
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
        assert_eq!(sent.collect::<Vec<_>>().await, vec![fresh, fresh]);
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
            reader.fetches.unbounded_send(account).unwrap();
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
