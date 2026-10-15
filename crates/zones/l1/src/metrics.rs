//! Internal metrics definitions for L1 ingestion.

use reth_metrics::{
    Metrics,
    metrics::{Counter, Gauge, Histogram},
};

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
