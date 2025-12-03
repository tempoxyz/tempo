use metrics::Gauge;
use reth_metrics::{Metrics, metrics::Histogram};

#[derive(Metrics, Clone)]
#[metrics(scope = "tempo_payload_builder")]
pub(crate) struct TempoPayloadBuilderMetrics {
    /// Block time in milliseconds.
    pub(crate) block_time_millis: Histogram,
    /// Block time in milliseconds.
    pub(crate) block_time_millis_last: Gauge,
    /// Number of transactions in the payload.
    pub(crate) total_transactions: Histogram,
    /// Number of payment transactions in the payload.
    pub(crate) payment_transactions: Histogram,
    /// Amount of gas used in the payload.
    pub(crate) gas_used: Histogram,
    /// The time it took to prepare system transactions in seconds.
    pub(crate) prepare_system_transactions_duration_seconds: Histogram,
    /// The time it took to execute start-of-block system transactions in seconds.
    pub(crate) start_block_txs_execution_duration_seconds: Histogram,
    /// The time it took to execute one transaction in seconds.
    pub(crate) transaction_execution_duration_seconds: Histogram,
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
}
