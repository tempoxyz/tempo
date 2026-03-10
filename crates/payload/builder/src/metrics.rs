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
    /// Time to create the EVM/block builder.
    pub(crate) create_evm_duration_seconds: Histogram,
    /// Time to apply pre-execution changes.
    pub(crate) pre_execution_duration_seconds: Histogram,
    /// The time it took to prepare system transactions in seconds.
    pub(crate) prepare_system_transactions_duration_seconds: Histogram,
    /// The time it took to execute one transaction in seconds.
    pub(crate) transaction_execution_duration_seconds: Histogram,
    /// The time it took to select the next candidate transaction from the pool.
    pub(crate) best_txs_next_duration_seconds: Histogram,
    /// Wall-clock duration of the pool tx selection + execution loop.
    pub(crate) block_fill_duration_seconds: Histogram,
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
}

/// Increments the unified pool transaction skip counter with the given reason label.
#[inline]
pub(crate) fn inc_pool_tx_skipped(reason: &'static str) {
    metrics::counter!("tempo_payload_builder_pool_transactions_skipped_total", "reason" => reason)
        .increment(1);
}
