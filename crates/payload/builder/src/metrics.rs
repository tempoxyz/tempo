use alloy_primitives::{Address, B256, BlockNumber, Bytes, StorageKey, StorageValue};
use metrics::Gauge;
use reth_errors::ProviderResult;
use reth_metrics::{Metrics, metrics::Histogram};
use reth_primitives_traits::{Account, Bytecode};
use reth_storage_api::{
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, StateProofProvider,
    StateProvider, StateRootProvider, StorageRootProvider,
};
use reth_trie_common::{
    AccountProof, HashedPostState, HashedStorage, MultiProof, MultiProofTargets, StorageMultiProof,
    StorageProof, TrieInput, updates::TrieUpdates,
};
use std::time::Instant;
use tracing::debug_span;

#[derive(Metrics, Clone)]
#[metrics(scope = "tempo_payload_builder")]
pub(crate) struct TempoPayloadBuilderMetrics {
    /// Block time in milliseconds.
    pub(crate) block_time_millis: Histogram,
    /// Block time in milliseconds.
    pub(crate) block_time_millis_last: Gauge,
    /// Number of transactions in the payload.
    pub(crate) total_transactions: Histogram,
    /// Number of transactions in the payload.
    pub(crate) total_transactions_last: Gauge,
    /// Number of payment transactions in the payload.
    pub(crate) payment_transactions: Histogram,
    /// Number of payment transactions in the payload.
    pub(crate) payment_transactions_last: Gauge,
    /// Number of subblocks in the payload.
    pub(crate) subblocks: Histogram,
    /// Number of subblocks in the payload.
    pub(crate) subblocks_last: Gauge,
    /// Number of subblock transactions in the payload.
    pub(crate) subblock_transactions: Histogram,
    /// Number of subblock transactions in the payload.
    pub(crate) subblock_transactions_last: Gauge,
    /// Amount of gas used in the payload.
    pub(crate) gas_used: Histogram,
    /// Amount of gas used in the payload.
    pub(crate) gas_used_last: Gauge,
    /// Time to acquire the state provider and initialize the state DB.
    pub(crate) state_setup_duration_seconds: Histogram,
    /// The time it took to prepare system transactions in seconds.
    pub(crate) prepare_system_transactions_duration_seconds: Histogram,
    /// The time it took to execute one transaction in seconds.
    pub(crate) transaction_execution_duration_seconds: Histogram,
    /// The time it took to execute normal transactions in seconds.
    pub(crate) total_normal_transaction_execution_duration_seconds: Histogram,
    /// The time it took to execute subblock transactions in seconds.
    pub(crate) total_subblock_transaction_execution_duration_seconds: Histogram,
    /// Execution time for a single subblock.
    pub(crate) subblock_execution_duration_seconds: Histogram,
    /// Number of transactions in a single subblock.
    pub(crate) subblock_transaction_count: Histogram,
    /// The time it took to execute all transactions in seconds.
    pub(crate) total_transaction_execution_duration_seconds: Histogram,
    /// The time it took to execute system transactions in seconds.
    pub(crate) system_transactions_execution_duration_seconds: Histogram,
    /// The time it took to finalize the payload in seconds. Includes merging transitions and calculating the state root.
    pub(crate) payload_finalization_duration_seconds: Histogram,
    /// Total time it took to build the payload in seconds.
    pub(crate) payload_build_duration_seconds: Histogram,
    /// Gas per second calculated as gas_used / payload_build_duration.
    pub(crate) gas_per_second: Histogram,
    /// Gas per second for the last payload calculated as gas_used / payload_build_duration.
    pub(crate) gas_per_second_last: Gauge,
    /// RLP-encoded block size in bytes.
    pub(crate) rlp_block_size_bytes: Histogram,
    /// RLP-encoded block size in bytes for the last payload.
    pub(crate) rlp_block_size_bytes_last: Gauge,
    /// Time to compute the hashed post-state from the bundle state.
    pub(crate) hashed_post_state_duration_seconds: Histogram,
    /// Time to compute the state root and trie updates via `state_root_with_updates`.
    pub(crate) state_root_with_updates_duration_seconds: Histogram,
}

impl TempoPayloadBuilderMetrics {
    /// Increments the unified pool transaction skip counter with the given reason label.
    ///
    /// Note: `mark_invalid` may also prune descendant transactions from the iterator,
    /// so the skip count represents skip *events*, not total transactions removed.
    #[inline]
    pub(crate) fn inc_pool_tx_skipped(&self, reason: &'static str) {
        metrics::counter!("tempo_payload_builder_pool_transactions_skipped_total", "reason" => reason)
            .increment(1);
    }
}

/// Wraps a [`StateProvider`] reference to instrument `hashed_post_state` and
/// `state_root_with_updates` with tracing spans and histogram metrics during `builder.finish()`.
pub(crate) struct InstrumentedFinishProvider<'a> {
    pub(crate) inner: &'a dyn StateProvider,
    pub(crate) metrics: TempoPayloadBuilderMetrics,
}

impl<'a> AsRef<dyn StateProvider + 'a> for InstrumentedFinishProvider<'a> {
    fn as_ref(&self) -> &(dyn StateProvider + 'a) {
        self.inner
    }
}

reth_storage_api::delegate_impls_to_as_ref!(
    for InstrumentedFinishProvider<'_> =>
    AccountReader {
        fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>>;
    }
    BlockHashReader {
        fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>>;
        fn canonical_hashes_range(&self, start: BlockNumber, end: BlockNumber) -> ProviderResult<Vec<B256>>;
    }
    StateProvider {
        fn storage(&self, account: Address, storage_key: StorageKey) -> ProviderResult<Option<StorageValue>>;
    }
    BytecodeReader {
        fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>>;
    }
    StorageRootProvider {
        fn storage_root(&self, address: Address, storage: HashedStorage) -> ProviderResult<B256>;
        fn storage_proof(&self, address: Address, slot: B256, storage: HashedStorage) -> ProviderResult<StorageProof>;
        fn storage_multiproof(&self, address: Address, slots: &[B256], storage: HashedStorage) -> ProviderResult<StorageMultiProof>;
    }
    StateProofProvider {
        fn proof(&self, input: TrieInput, address: Address, slots: &[B256]) -> ProviderResult<AccountProof>;
        fn multiproof(&self, input: TrieInput, targets: MultiProofTargets) -> ProviderResult<MultiProof>;
        fn witness(&self, input: TrieInput, target: HashedPostState) -> ProviderResult<Vec<Bytes>>;
    }
);

impl HashedPostStateProvider for InstrumentedFinishProvider<'_> {
    fn hashed_post_state(&self, bundle_state: &reth_revm::db::BundleState) -> HashedPostState {
        let start = Instant::now();
        let _span = debug_span!(target: "payload_builder", "hashed_post_state").entered();
        let result = self.inner.hashed_post_state(bundle_state);
        drop(_span);
        self.metrics
            .hashed_post_state_duration_seconds
            .record(start.elapsed());
        result
    }
}

impl StateRootProvider for InstrumentedFinishProvider<'_> {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        let start = Instant::now();
        let _span = debug_span!(target: "payload_builder", "state_root").entered();
        let result = self.inner.state_root(hashed_state);
        drop(_span);
        self.metrics
            .state_root_with_updates_duration_seconds
            .record(start.elapsed());
        result
    }

    fn state_root_from_nodes(&self, input: TrieInput) -> ProviderResult<B256> {
        self.inner.state_root_from_nodes(input)
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        let start = Instant::now();
        let _span = debug_span!(target: "payload_builder", "state_root_with_updates").entered();
        let result = self.inner.state_root_with_updates(hashed_state);
        drop(_span);
        self.metrics
            .state_root_with_updates_duration_seconds
            .record(start.elapsed());
        result
    }

    fn state_root_from_nodes_with_updates(
        &self,
        input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner.state_root_from_nodes_with_updates(input)
    }
}
