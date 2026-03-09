use reth_metrics::{
    Metrics,
    metrics::{Counter, Gauge, Histogram},
};
use reth_trie_common::{HashedPostState, updates::TrieUpdates};
use std::time::{Duration, Instant};

/// RAII guard that records `payload_build_duration_seconds` on drop.
pub(super) struct BuildGuard<'a> {
    started_at: Instant,
    metrics: &'a TempoPayloadBuilderMetrics,
}

impl<'a> BuildGuard<'a> {
    pub(super) fn new(metrics: &'a TempoPayloadBuilderMetrics) -> Self {
        Self {
            started_at: Instant::now(),
            metrics,
        }
    }

    pub(super) fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }
}

impl Drop for BuildGuard<'_> {
    fn drop(&mut self) {
        self.metrics
            .payload_build_duration_seconds
            .record(self.started_at.elapsed());
    }
}

/// State-size statistics from a finalized payload, used to correlate with
/// `payload_finalization_duration_seconds` when diagnosing slow state root computation.
///
/// Full storage wipes (`storage_tries_wiped`) are tracked separately from explicit
/// slot changes (`storage_slots_modified`) — they are not mutually exclusive.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FinalizationStateStats {
    /// Distinct accounts in the hashed post-state diff (created, modified, or destroyed).
    pub accounts_modified: usize,
    /// Distinct storage slot entries in the hashed post-state diff across all accounts.
    pub storage_slots_modified: usize,
    /// Storage tries fully wiped (e.g. via SELFDESTRUCT), counted separately from slot changes.
    pub storage_tries_wiped: usize,
    /// Intermediate trie nodes changed (updated or removed) across account and storage tries.
    pub trie_nodes_changed: usize,
}

impl FinalizationStateStats {
    pub(crate) fn new(hashed_state: &HashedPostState, trie_updates: &TrieUpdates) -> Self {
        Self {
            accounts_modified: hashed_state.accounts.len(),
            storage_slots_modified: hashed_state
                .storages
                .values()
                .map(|s| s.storage.len())
                .sum(),
            storage_tries_wiped: hashed_state.storages.values().filter(|s| s.wiped).count(),
            trie_nodes_changed: trie_updates.account_nodes.len()
                + trie_updates.removed_nodes.len()
                + trie_updates
                    .storage_tries
                    .values()
                    .map(|s| s.storage_nodes.len() + s.removed_nodes.len())
                    .sum::<usize>(),
        }
    }
}

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
    /// The time it took to prepare system transactions in seconds.
    pub(crate) prepare_system_transactions_duration_seconds: Histogram,
    /// The time it took to execute one transaction in seconds.
    pub(crate) transaction_execution_duration_seconds: Histogram,
    /// The time it took to execute normal transactions in seconds.
    pub(crate) total_normal_transaction_execution_duration_seconds: Histogram,
    /// The time it took to execute subblock transactions in seconds.
    pub(crate) total_subblock_transaction_execution_duration_seconds: Histogram,
    /// The time it took to execute all transactions in seconds.
    pub(crate) total_transaction_execution_duration_seconds: Histogram,
    /// The time it took to execute system transactions in seconds.
    pub(crate) system_transactions_execution_duration_seconds: Histogram,
    /// The time it took to finalize the payload in seconds. Includes merging transitions and calculating the state root.
    pub(crate) payload_finalization_duration_seconds: Histogram,
    /// Distinct accounts in the hashed post-state diff.
    pub(crate) accounts_modified: Histogram,
    /// Distinct accounts modified in the latest payload.
    pub(crate) accounts_modified_last: Gauge,
    /// Distinct storage slot entries in the hashed post-state diff.
    pub(crate) storage_slots_modified: Histogram,
    /// Storage slots modified in the latest payload.
    pub(crate) storage_slots_modified_last: Gauge,
    /// Storage tries fully wiped (e.g. via SELFDESTRUCT), counted separately from slot changes.
    pub(crate) storage_tries_wiped: Histogram,
    /// Storage tries wiped in the latest payload.
    pub(crate) storage_tries_wiped_last: Gauge,
    /// Intermediate trie nodes changed (updated or removed) across account and storage tries.
    pub(crate) trie_nodes_changed: Histogram,
    /// Trie nodes changed in the latest payload.
    pub(crate) trie_nodes_changed_last: Gauge,
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
}

impl TempoPayloadBuilderMetrics {
    pub(crate) fn record_finalization_state_stats(&self, stats: &FinalizationStateStats) {
        self.accounts_modified
            .record(stats.accounts_modified as f64);
        self.accounts_modified_last
            .set(stats.accounts_modified as f64);

        self.storage_slots_modified
            .record(stats.storage_slots_modified as f64);
        self.storage_slots_modified_last
            .set(stats.storage_slots_modified as f64);

        self.storage_tries_wiped
            .record(stats.storage_tries_wiped as f64);
        self.storage_tries_wiped_last
            .set(stats.storage_tries_wiped as f64);

        self.trie_nodes_changed
            .record(stats.trie_nodes_changed as f64);
        self.trie_nodes_changed_last
            .set(stats.trie_nodes_changed as f64);
    }
}
