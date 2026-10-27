//! Internal metrics definitions for L1 ingestion.

use reth_metrics::{
    Metrics,
    metrics::{Counter, Gauge, Histogram},
};
use zone_precompiles::tx_context::ExecutionOrigin;

/// Metrics emitted by the L1 subscriber / deposit ingestion pipeline.
#[derive(Metrics, Clone)]
#[metrics(scope = "tempo_zone_l1_subscriber")]
pub(crate) struct L1SubscriberMetrics {
    /// Duration of a backfill run in seconds.
    pub backfill_duration_seconds: Histogram,

    /// Most recent finalized L1 block number observed by the subscriber.
    pub latest_l1_block_seen: Gauge,

    /// Current lag between the subscriber cursor and the finalized L1 head, in blocks.
    pub current_l1_lag_blocks: Gauge,

    /// Number of L1 blocks accepted into the deposit queue.
    pub blocks_enqueued: Counter,

    /// Number of withdrawal bounce-back entries observed on L1.
    pub withdrawal_bounce_back_events: Counter,

    /// Number of user deposit events observed on L1.
    pub deposit_events: Counter,

    /// Number of `TokenEnabled` events observed on L1.
    pub token_enabled_events: Counter,

    /// Number of `LeaderUpdated` events observed on L1.
    pub leader_updated_events: Counter,

    /// Number of times L1 block was rejected because a  portal event failed to decode.
    pub decode_fence_failures: Counter,

    /// Number of failed L1 block preparation fetches.
    pub fetch_failures: Counter,

    /// Number of reconnect attempts after the subscriber exits or errors.
    pub reconnects: Counter,
}

/// Metrics for Tempo L1 storage reads made during Zone execution, labelled by `origin`.
#[derive(Metrics, Clone)]
#[metrics(scope = "tempo_zone_l1_state")]
pub(crate) struct L1StateMetrics {
    /// Number of L1 storage reads that missed the cache and were fetched over RPC.
    pub cache_misses: Counter,
}

/// [`L1StateMetrics`] for each [`ExecutionOrigin`], so prewarming misses can be told apart from
/// the canonical misses they are meant to prevent.
#[derive(Debug, Clone)]
pub(crate) struct L1StateMetricsByOrigin {
    canonical: L1StateMetrics,
    prewarming: L1StateMetrics,
    simulation: L1StateMetrics,
}

impl L1StateMetricsByOrigin {
    pub(crate) fn new() -> Self {
        let labelled = |origin| L1StateMetrics::new_with_labels(&[("origin", origin)]);
        Self {
            canonical: labelled("canonical"),
            prewarming: labelled("prewarming"),
            simulation: labelled("simulation"),
        }
    }

    pub(crate) fn record_cache_miss(&self, origin: ExecutionOrigin) {
        let metrics = match origin {
            ExecutionOrigin::Canonical => &self.canonical,
            ExecutionOrigin::Prewarming => &self.prewarming,
            ExecutionOrigin::Simulation => &self.simulation,
        };
        metrics.cache_misses.increment(1);
    }
}
