use metrics::Gauge;
use reth_metrics::{
    Metrics,
    metrics::{Counter, Histogram},
};

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
    /// Time spent fetching the parent state provider.
    pub(crate) state_provider_duration_seconds: Histogram,
    /// Time spent constructing the state DB wrapper.
    pub(crate) build_state_db_duration_seconds: Histogram,
    /// Time spent creating the EVM/block builder.
    pub(crate) create_evm_duration_seconds: Histogram,
    /// Time spent applying pre-execution changes.
    pub(crate) pre_execution_duration_seconds: Histogram,
    /// The time it took to prepare system transactions in seconds.
    pub(crate) prepare_system_transactions_duration_seconds: Histogram,
    /// The time it took to execute one transaction in seconds.
    pub(crate) transaction_execution_duration_seconds: Histogram,
    /// The time it took to select the next candidate transaction from the pool.
    pub(crate) transaction_selection_duration_seconds: Histogram,
    /// Number of candidate pool transactions considered per payload attempt.
    pub(crate) pool_transactions_considered: Histogram,
    /// Number of candidate pool transactions considered for the latest payload attempt.
    pub(crate) pool_transactions_considered_last: Gauge,
    /// Number of pool transactions successfully executed per payload attempt.
    pub(crate) pool_transactions_executed: Histogram,
    /// Number of pool transactions successfully executed for the latest payload attempt.
    pub(crate) pool_transactions_executed_last: Gauge,
    /// Number of pool transactions skipped per payload attempt.
    pub(crate) pool_transactions_skipped: Histogram,
    /// Number of pool transactions skipped for the latest payload attempt.
    pub(crate) pool_transactions_skipped_last: Gauge,
    /// Number of pool transactions skipped because they exceed the non-shared gas limit.
    pub(crate) pool_transactions_skipped_exceeds_non_shared_gas_limit: Counter,
    /// Number of pool transactions skipped because they exceed the non-payment gas limit.
    pub(crate) pool_transactions_skipped_exceeds_non_payment_gas_limit: Counter,
    /// Number of pool transactions skipped because they would exceed the max block RLP size.
    pub(crate) pool_transactions_skipped_oversized_block: Counter,
    /// Number of pool transactions skipped because the nonce is too low.
    pub(crate) pool_transactions_skipped_nonce_too_low: Counter,
    /// Number of pool transactions skipped because of other validation failures.
    pub(crate) pool_transactions_skipped_invalid_tx: Counter,
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
