//! Builder-local L1 cache prewarming.
//!
//! Deposits and pool transactions are executed in independent throwaway Zone builders. Execution
//! output is discarded; only L1 reads populate the cache shared with canonical execution.

use crate::builder::build_advance_tempo_tx_owned;
use alloy_primitives::{Address, B256, map::HashSet};
use futures::{StreamExt as _, channel::mpsc, future::ready};
use reth_evm::{
    BlockExecutor as _, ConfigureEvm, database::StateProviderDatabase, execute::BlockBuilder,
};
use reth_primitives_traits::{Recovered, SealedHeader};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_tasks::{TaskExecutor, cancel::ManualCancel};
use reth_transaction_pool::ValidPoolTransaction;
use std::{error::Error, future::Future, sync::Arc};
use tempo_contracts::zones::DepositType;
use tempo_evm::TempoNextBlockEnvAttributes;
use tempo_primitives::{TempoHeader, TempoTxEnvelope};
use tempo_transaction_pool::transaction::TempoPooledTransaction;
use tracing::debug;
use zone_evm::ZoneEvmConfig;
use zone_l1::{PreparedL1Block, state::L1StateProvider};
use zone_precompiles::{L1StateError, L1StorageReader};

/// Most Tempo commitment fetches in flight while prewarming one Zone block.
const MAX_COMMITMENT_FETCHES: usize = 64;

/// Immutable canonical inputs used to construct isolated prewarming workers.
#[derive(Clone)]
pub(crate) struct PrewarmingExecutionContext<Provider, L1 = L1StateProvider> {
    pub(crate) provider: Provider,
    pub(crate) evm_config: ZoneEvmConfig<L1>,
    pub(crate) parent_hash: B256,
    pub(crate) parent_header: SealedHeader<TempoHeader>,
    pub(crate) next_block_env_attributes: TempoNextBlockEnvAttributes,
    pub(crate) chain_id: u64,
}

impl<Provider> PrewarmingExecutionContext<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    /// Enqueue one disposable simulation per deposit directly on the prewarming pool.
    pub(crate) fn start(
        self,
        task_executor: &TaskExecutor,
        prepared: &PreparedL1Block,
    ) -> Prewarming {
        let handle = Prewarming::default();
        if prepared.queued_deposits.is_empty() {
            return handle;
        }

        let context = Arc::new(self);
        let pool = task_executor.prewarming_pool();
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
            let context = context.clone();
            let cancel = handle.cancel.clone();
            pool.spawn(move || {
                if !cancel.is_cancelled() {
                    // Queue-hash validation may fail, but preceding reads have already warmed the
                    // shared cache.
                    let _ =
                        context.execute(build_advance_tempo_tx_owned(partial, context.chain_id));
                }
            });
        }

        handle
    }

    /// Enqueue one disposable simulation per pool transaction, reading commitments through a
    /// [`CommitmentPrewarmReader`].
    ///
    /// Commitments the simulations miss are fetched in parallel at `tempo_block_number`, the
    /// Tempo block the next Zone block's transactions read at.
    pub(crate) fn start_pool(
        self,
        task_executor: &TaskExecutor,
        transactions: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        tempo_block_number: u64,
    ) -> Prewarming {
        let handle = Prewarming::default();
        if transactions.is_empty() {
            return handle;
        }

        let evm_config = self.evm_config.map_l1_reader(|provider| {
            let (fetches, fetch_task) = commitment_fetches(provider.clone(), tempo_block_number);
            task_executor.spawn_task(fetch_task);
            CommitmentPrewarmReader {
                provider: provider.clone(),
                tempo_block_number,
                fetches,
            }
        });
        let context = Arc::new(PrewarmingExecutionContext {
            provider: self.provider,
            evm_config,
            parent_hash: self.parent_hash,
            parent_header: self.parent_header,
            next_block_env_attributes: self.next_block_env_attributes,
            chain_id: self.chain_id,
        });
        let pool = task_executor.prewarming_pool();
        for transaction in transactions {
            let context = context.clone();
            let cancel = handle.cancel.clone();
            pool.spawn(move || {
                if !cancel.is_cancelled() {
                    // Pool transactions may be invalid on the parent state; the reads before the
                    // failure still count.
                    let _ = context.execute(transaction.to_consensus());
                }
            });
        }

        handle
    }
}

impl<Provider, L1> PrewarmingExecutionContext<Provider, L1>
where
    Provider: StateProviderFactory + Clone + 'static,
    L1: L1StorageReader + Unpin,
{
    /// Executes `transaction` alone on the parent state and discards the result.
    fn execute(
        &self,
        transaction: Recovered<TempoTxEnvelope>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let state = StateProviderDatabase::new(
            self.provider
                .state_by_block_hash(self.parent_hash)?
                .into_evm_state_provider(),
        );

        let mut worker = self.evm_config.builder_for_next_block(
            state,
            &self.parent_header,
            self.next_block_env_attributes.clone(),
        )?;
        worker.apply_pre_execution_changes()?;
        worker
            .executor_mut()
            .execute_transaction_without_commit(transaction)?;
        Ok(())
    }
}

/// Cancels queued work that has not started when dropped.
#[derive(Debug, Default)]
pub(crate) struct Prewarming {
    cancel: ManualCancel,
}

impl Drop for Prewarming {
    fn drop(&mut self) {
        self.cancel.clone().cancel();
    }
}

/// An [`L1StorageReader`] for prewarming simulations that never blocks on a Tempo commitment.
///
/// A cached commitment is returned as is. On a miss the account is sent for a parallel fetch and
/// the read returns zero, which is exact for accounts never configured on Tempo, such as fresh
/// addresses. Storage reads go to the cache-backed provider unchanged.
#[derive(Clone)]
struct CommitmentPrewarmReader {
    provider: L1StateProvider,
    /// Tempo block the next Zone block's transactions read commitments at.
    tempo_block_number: u64,
    fetches: mpsc::UnboundedSender<Address>,
}

impl L1StorageReader for CommitmentPrewarmReader {
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
            .get_commitment(account, self.tempo_block_number)
        {
            return Ok(commitment);
        }
        if let Err(error) = self.fetches.unbounded_send(account) {
            debug!(target: "zone::payload", %account, %error, "Commitment prewarm fetch task stopped");
        }
        Ok(B256::ZERO)
    }
}

/// Returns a sender for accounts whose commitments to cache at `tempo_block_number`, and the
/// task that fetches each account once, up to [`MAX_COMMITMENT_FETCHES`] at a time.
///
/// The task ends once every sender is dropped and its fetches finish.
fn commitment_fetches(
    provider: L1StateProvider,
    tempo_block_number: u64,
) -> (
    mpsc::UnboundedSender<Address>,
    impl Future<Output = ()> + Send + 'static,
) {
    let (sender, accounts) = mpsc::unbounded();
    let task = async move {
        let provider = &provider;
        let mut fetched = HashSet::<Address>::default();
        accounts
            .filter(move |account| ready(fetched.insert(*account)))
            .for_each_concurrent(MAX_COMMITMENT_FETCHES, |account| async move {
                // A failed fetch is retried by canonical execution on its own cache miss.
                if let Err(error) = provider
                    .read_l1_commitment_async(account, tempo_block_number)
                    .await
                {
                    debug!(target: "zone::payload", %account, %error, "Commitment prewarm fetch failed");
                }
            })
            .await;
    };
    (sender, task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_provider::{Provider as _, ProviderBuilder, mock::Asserter};
    use alloy_rpc_types_eth::AccountInfo;
    use tempo_alloy::TempoNetwork;
    use tempo_primitives::account::encode_config_commitment;
    use zone_l1::{
        L1StateCache,
        state::{L1StateProvider, L1StateProviderConfig},
    };

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
        let reader = CommitmentPrewarmReader {
            provider,
            tempo_block_number: TEMPO_BLOCK,
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
        // The reader, and with it the sender, is dropped, so the channel ends. The fetch task
        // deduplicates.
        assert_eq!(sent.collect::<Vec<_>>().await, vec![fresh, fresh]);
    }

    #[tokio::test]
    async fn commitment_fetches_cache_each_sent_account_once() {
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
        let (sender, task) = commitment_fetches(provider.clone(), TEMPO_BLOCK);
        for account in [failed, failed, fetched] {
            sender.unbounded_send(account).unwrap();
        }
        drop(sender);

        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap();

        let mut cache = provider.cache().lock();
        assert_eq!(cache.get_commitment(failed, TEMPO_BLOCK), None);
        assert_eq!(cache.get_commitment(fetched, TEMPO_BLOCK), Some(commitment));
    }
}
