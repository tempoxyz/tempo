//! Transaction pool metrics for the AA2D pool.

use reth_metrics::{
    Metrics,
    metrics::{Counter, Gauge, Histogram},
};
use std::{sync::LazyLock, time::Instant};

/// Temporary admission-stage diagnostics for the public workload benchmark.
#[derive(Metrics)]
#[metrics(scope = "transaction_pool.admission")]
pub(crate) struct TempoPoolAdmissionMetrics {
    /// Validation service round trip, including queueing, in seconds.
    pub validation_wait_seconds: Histogram,
    /// Time executing a validation batch, excluding queueing and provider acquisition.
    pub validation_work_seconds: Histogram,
    /// Time acquiring the latest provider and its matching cache.
    pub provider_seconds: Histogram,
    /// Time inserting one validated transaction, including lock acquisition.
    pub insert_seconds: Histogram,
    /// Number of transactions per validation job.
    pub batch_size: Histogram,
}

pub(crate) static ADMISSION_METRICS: LazyLock<TempoPoolAdmissionMetrics> =
    LazyLock::new(TempoPoolAdmissionMetrics::default);

/// Records elapsed time on all return paths from a benchmark diagnostic stage.
pub(crate) struct AdmissionTimer {
    metric: &'static Histogram,
    started: Instant,
}

impl AdmissionTimer {
    pub(crate) fn new(metric: &'static Histogram) -> Self {
        Self {
            metric,
            started: Instant::now(),
        }
    }
}

impl Drop for AdmissionTimer {
    fn drop(&mut self) {
        self.metric.record(self.started.elapsed());
    }
}

/// AA2D pool metrics
#[derive(Metrics, Clone)]
#[metrics(scope = "transaction_pool.aa_2d")]
pub struct AA2dPoolMetrics {
    /// Total number of transactions in the AA2D pool
    pub total_transactions: Gauge,

    /// Number of pending (executable) transactions in the AA2D pool
    pub pending_transactions: Gauge,

    /// Number of queued (non-executable) transactions in the AA2D pool
    pub queued_transactions: Gauge,

    /// Total number of tracked (address, nonce_key) pairs
    pub tracked_nonce_keys: Gauge,

    /// Number of transactions inserted into the AA2D pool
    pub inserted_transactions: Counter,

    /// Number of transactions removed from the AA2D pool
    pub removed_transactions: Counter,

    /// Number of transactions promoted from queued to pending
    pub promoted_transactions: Counter,

    /// Number of transactions demoted from pending to queued
    pub demoted_transactions: Counter,
}

impl AA2dPoolMetrics {
    /// Update the transaction count metrics
    #[inline]
    pub fn set_transaction_counts(&self, total: usize, pending: usize, queued: usize) {
        self.total_transactions.set(total as f64);
        self.pending_transactions.set(pending as f64);
        self.queued_transactions.set(queued as f64);
    }

    /// Update the nonce key tracking metrics
    #[inline]
    pub fn inc_nonce_key_count(&self, nonce_keys: usize) {
        self.tracked_nonce_keys.increment(nonce_keys as f64);
    }

    /// Increment the inserted transactions counter
    #[inline]
    pub fn inc_inserted(&self) {
        self.inserted_transactions.increment(1);
    }

    /// Increment the removed transactions counter
    #[inline]
    pub fn inc_removed(&self, count: usize) {
        self.removed_transactions.increment(count as u64);
    }

    /// Increment the promoted transactions counter
    #[inline]
    pub fn inc_promoted(&self, count: usize) {
        self.promoted_transactions.increment(count as u64);
    }

    /// Increment the demoted transactions counter
    #[inline]
    pub fn inc_demoted(&self, count: usize) {
        self.demoted_transactions.increment(count as u64);
    }
}

/// Metrics for the Tempo pool maintenance task.
#[derive(Metrics, Clone)]
#[metrics(scope = "transaction_pool.maintenance")]
pub struct TempoPoolMaintenanceMetrics {
    /// Total time spent processing a block update in seconds.
    pub block_update_duration_seconds: Histogram,

    /// Time spent evicting expired AA transactions in seconds.
    pub expired_eviction_duration_seconds: Histogram,

    /// Time spent evicting invalidated transactions (revoked keys, validator tokens, blacklist) in seconds.
    pub invalidation_eviction_duration_seconds: Histogram,

    /// Time spent updating the AMM liquidity cache in seconds.
    pub amm_cache_update_duration_seconds: Histogram,

    /// Time spent updating the 2D nonce pool in seconds.
    pub nonce_pool_update_duration_seconds: Histogram,

    /// Number of transactions evicted due to invalidation events.
    pub transactions_invalidated: Counter,

    /// Number of transactions re-validated due to transfer policy updates.
    pub transfer_policy_revalidated: Counter,

    /// Number of transactions re-validated due to quote token updates.
    pub quote_token_revalidated: Counter,
}
