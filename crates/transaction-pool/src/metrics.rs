//! Transaction pool metrics for the AA2D pool.

use reth_metrics::{
    Metrics,
    metrics::{Counter, Gauge, Histogram},
};
use std::time::Duration;

/// Metrics for the transaction ingress path before transactions are visible to builders.
#[derive(Metrics, Clone)]
#[metrics(scope = "transaction_pool.tempo_ingress")]
pub struct TempoPoolIngressMetrics {
    /// Number of raw transactions currently being decoded and sender-recovered.
    pub raw_decode_recovery_active: Gauge,
    /// Total number of raw transactions submitted for decode/recovery.
    pub raw_decode_recovery_total: Counter,
    /// Total number of raw transactions successfully decoded and recovered.
    pub raw_decode_recovery_success: Counter,
    /// Total number of raw transactions rejected during decode/recovery.
    pub raw_decode_recovery_error: Counter,
    /// Decode/recovery input byte length.
    pub raw_decode_recovery_input_bytes: Histogram,
    /// Time spent decoding and recovering a raw transaction.
    pub raw_decode_recovery_duration_seconds: Histogram,

    /// Number of validation batches currently being processed by the Tempo validator.
    pub validation_active_batches: Gauge,
    /// Number of transactions currently inside Tempo validation batches.
    pub validation_active_transactions: Gauge,
    /// Total transactions submitted to Tempo validation.
    pub validation_total_transactions: Counter,
    /// Total transactions accepted by Tempo validation.
    pub validation_valid_transactions: Counter,
    /// Total transactions rejected by Tempo validation.
    pub validation_invalid_transactions: Counter,
    /// Total transactions that failed validation due to validator/provider errors.
    pub validation_error_transactions: Counter,
    /// Number of transactions per Tempo validation batch.
    pub validation_batch_size: Histogram,
    /// Time spent validating a Tempo validation batch.
    pub validation_batch_duration_seconds: Histogram,

    /// Number of validated transactions currently being inserted into the pool.
    pub pool_insert_active_transactions: Gauge,
    /// Total validated transaction outcomes submitted to pool insertion.
    pub pool_insert_total_transactions: Counter,
    /// Time spent inserting one validated transaction outcome into the pool.
    pub pool_insert_duration_seconds: Histogram,
}

impl TempoPoolIngressMetrics {
    /// Records entry into raw transaction decode/recovery.
    #[inline]
    pub fn start_raw_decode_recovery(&self, len: usize) -> MetricGaugeGuard {
        self.raw_decode_recovery_active.increment(1.0);
        self.raw_decode_recovery_total.increment(1);
        self.raw_decode_recovery_input_bytes.record(len as f64);
        MetricGaugeGuard::new(self.raw_decode_recovery_active.clone(), 1.0)
    }

    /// Records raw transaction decode/recovery completion.
    #[inline]
    pub fn record_raw_decode_recovery_result(&self, duration: Duration, success: bool) {
        if success {
            self.raw_decode_recovery_success.increment(1);
        } else {
            self.raw_decode_recovery_error.increment(1);
        }
        self.raw_decode_recovery_duration_seconds.record(duration);
    }

    /// Records entry into a Tempo validation batch.
    #[inline]
    pub fn start_validation_batch(&self, tx_count: usize) -> ValidationMetricsGuard {
        self.validation_active_batches.increment(1.0);
        self.validation_active_transactions
            .increment(tx_count as f64);
        self.validation_total_transactions
            .increment(tx_count as u64);
        self.validation_batch_size.record(tx_count as f64);
        ValidationMetricsGuard {
            batches: MetricGaugeGuard::new(self.validation_active_batches.clone(), 1.0),
            transactions: MetricGaugeGuard::new(
                self.validation_active_transactions.clone(),
                tx_count as f64,
            ),
        }
    }

    /// Records Tempo validation batch completion.
    #[inline]
    pub fn record_validation_batch_result(
        &self,
        duration: Duration,
        valid: usize,
        invalid: usize,
        error: usize,
    ) {
        self.validation_valid_transactions.increment(valid as u64);
        self.validation_invalid_transactions
            .increment(invalid as u64);
        self.validation_error_transactions.increment(error as u64);
        self.validation_batch_duration_seconds.record(duration);
    }

    /// Records entry into pool insertion of one validated transaction outcome.
    #[inline]
    pub fn start_pool_insert(&self) -> MetricGaugeGuard {
        self.pool_insert_active_transactions.increment(1.0);
        self.pool_insert_total_transactions.increment(1);
        MetricGaugeGuard::new(self.pool_insert_active_transactions.clone(), 1.0)
    }

    /// Records pool insertion completion.
    #[inline]
    pub fn record_pool_insert_duration(&self, duration: Duration) {
        self.pool_insert_duration_seconds.record(duration);
    }
}

/// Decrements a gauge when the measured scope exits.
pub struct MetricGaugeGuard {
    gauge: Gauge,
    amount: f64,
}

impl MetricGaugeGuard {
    fn new(gauge: Gauge, amount: f64) -> Self {
        Self { gauge, amount }
    }
}

impl Drop for MetricGaugeGuard {
    fn drop(&mut self) {
        self.gauge.decrement(self.amount);
    }
}

/// Keeps validation batch gauges alive for the duration of the batch.
pub struct ValidationMetricsGuard {
    batches: MetricGaugeGuard,
    transactions: MetricGaugeGuard,
}

impl ValidationMetricsGuard {
    /// Touches the guard so both fields count as read while drop semantics remain implicit.
    #[inline]
    pub fn keep(&self) {
        let _ = (&self.batches, &self.transactions);
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

    /// Number of live-update transactions received by active best-transaction iterators.
    pub best_live_updates_received: Counter,

    /// Number of times an active best-transaction iterator found no live updates waiting.
    pub best_live_updates_empty: Counter,

    /// Number of broadcast lag events seen by active best-transaction iterators.
    pub best_live_updates_lagged_events: Counter,

    /// Number of live-update transactions skipped by broadcast lag.
    pub best_live_updates_lagged_skipped: Counter,

    /// Number of live updates processed into active best-transaction iterators.
    pub best_live_updates_processed: Counter,

    /// Number of live updates stashed to preserve iterator ordering.
    pub best_live_updates_stashed: Counter,

    /// Number of expiring nonce live updates inserted into active iterator ordering.
    pub best_live_updates_expiring_inserted: Counter,

    /// Number of expiring nonce live updates skipped because they were underpriced.
    pub best_live_updates_expiring_underpriced: Counter,

    /// Number of times a best-transaction iterator returned empty.
    pub best_iterator_empty: Counter,

    /// Local regular pending transaction count when a best-transaction iterator last returned empty.
    pub best_iterator_empty_regular_pending_last: Gauge,

    /// Local expiring nonce order count when a best-transaction iterator last returned empty.
    pub best_iterator_empty_expiring_order_last: Gauge,

    /// Live-update receiver count when a best-transaction iterator last returned empty.
    pub best_iterator_empty_receivers_last: Gauge,
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

    /// Increment best-iterator live-update receive count.
    #[inline]
    pub fn inc_best_live_update_received(&self) {
        self.best_live_updates_received.increment(1);
    }

    /// Increment best-iterator live-update empty count.
    #[inline]
    pub fn inc_best_live_update_empty(&self) {
        self.best_live_updates_empty.increment(1);
    }

    /// Increment best-iterator live-update lag counters.
    #[inline]
    pub fn inc_best_live_update_lagged(&self, skipped: u64) {
        self.best_live_updates_lagged_events.increment(1);
        self.best_live_updates_lagged_skipped.increment(skipped);
    }

    /// Increment best-iterator live-update processing count.
    #[inline]
    pub fn inc_best_live_update_processed(&self) {
        self.best_live_updates_processed.increment(1);
    }

    /// Increment best-iterator live-update stashed count.
    #[inline]
    pub fn inc_best_live_update_stashed(&self) {
        self.best_live_updates_stashed.increment(1);
    }

    /// Increment best-iterator expiring nonce insert count.
    #[inline]
    pub fn inc_best_live_update_expiring_inserted(&self) {
        self.best_live_updates_expiring_inserted.increment(1);
    }

    /// Increment best-iterator expiring nonce underpriced count.
    #[inline]
    pub fn inc_best_live_update_expiring_underpriced(&self) {
        self.best_live_updates_expiring_underpriced.increment(1);
    }

    /// Record that a best-transaction iterator returned empty.
    #[inline]
    pub fn record_best_iterator_empty(
        &self,
        regular_pending: usize,
        expiring_order: usize,
        receivers: usize,
    ) {
        self.best_iterator_empty.increment(1);
        self.best_iterator_empty_regular_pending_last
            .set(regular_pending as f64);
        self.best_iterator_empty_expiring_order_last
            .set(expiring_order as f64);
        self.best_iterator_empty_receivers_last
            .set(receivers as f64);
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

    /// Time spent processing fee token pause/unpause events in seconds.
    pub pause_events_duration_seconds: Histogram,

    /// Time spent evicting invalidated transactions (revoked keys, validator tokens, blacklist) in seconds.
    pub invalidation_eviction_duration_seconds: Histogram,

    /// Time spent updating the AMM liquidity cache in seconds.
    pub amm_cache_update_duration_seconds: Histogram,

    /// Time spent updating the 2D nonce pool in seconds.
    pub nonce_pool_update_duration_seconds: Histogram,

    /// Number of expired transactions evicted.
    pub expired_transactions_evicted: Counter,

    /// Number of transactions moved to the paused pool.
    pub transactions_paused: Counter,

    /// Number of transactions restored from the paused pool.
    pub transactions_unpaused: Counter,

    /// Number of transactions evicted due to invalidation events.
    pub transactions_invalidated: Counter,

    /// Number of paused transactions evicted due to the global cap.
    pub paused_pool_cap_evicted: Counter,

    /// Number of transactions re-validated due to transfer policy updates.
    pub transfer_policy_revalidated: Counter,

    /// Number of transactions re-validated due to quote token updates.
    pub quote_token_revalidated: Counter,
}
