//! Internal metrics definitions for zone observability.

use reth_metrics::{
    Metrics,
    metrics::{Counter, Gauge, Histogram},
};

/// Metrics emitted for the sequencer account.
#[derive(Metrics, Clone)]
#[metrics(scope = "tempo_zone_sequencer")]
pub(crate) struct SequencerMetrics {
    /// Current PathUSD balance of the sequencer account on Tempo L1, in base units.
    pub(crate) pathusd_balance: Gauge,
}

/// Metrics emitted by the prover.
#[derive(Metrics, Clone)]
#[metrics(scope = "tempo_zone_prover")]
pub(crate) struct ProverMetrics {
    /// 1 when the current or next-72-hour chainspec hardfork has no configured prover endpoint.
    /// Refreshed every minute, independently of proving activity.
    pub(crate) missing_hardfork_prover: Gauge,

    /// Time a finalized batch candidate spends waiting for the prover worker.
    pub(crate) queue_duration_seconds: Histogram,

    /// End-to-end latency of a prover validation attempt in seconds.
    pub(crate) validation_duration_seconds: Histogram,

    /// Time spent loading and decoding canonical Zone blocks.
    pub(crate) zone_inputs_duration_seconds: Histogram,

    /// Time spent generating and combining Zone and Tempo execution witnesses.
    pub(crate) zone_witness_duration_seconds: Histogram,

    /// Time spent fetching and validating Tempo checkpoints and ancestry.
    pub(crate) tempo_headers_duration_seconds: Histogram,

    /// Time spent verifying a generated batch witness locally or remotely.
    pub(crate) spf_execution_duration_seconds: Histogram,

    /// Time spent establishing a TCP connection to the remote prover.
    pub(crate) spf_remote_connect_duration_seconds: Histogram,

    /// Time spent serializing and sending a request to the remote prover.
    pub(crate) spf_remote_request_send_duration_seconds: Histogram,

    /// Time from sending a remote prover request until the first response byte arrives.
    pub(crate) spf_remote_response_wait_duration_seconds: Histogram,

    /// Time from the first response byte until the response is fully read and decoded.
    pub(crate) spf_remote_response_receive_duration_seconds: Histogram,

    /// Time spent comparing SPF output with the finalized batch candidate.
    pub(crate) output_validation_duration_seconds: Histogram,

    /// Time spent verifying a Nitro proof locally or through the L1 verifier.
    pub(crate) proof_verification_duration_seconds: Histogram,
    /// Nitro proofs accepted by the configured local or L1 verifier.
    pub(crate) proof_verification_success_total: Counter,
    /// Nitro proofs rejected by the verifier.
    pub(crate) proof_verification_failure_total: Counter,
    /// Proof verification attempts interrupted by setup, RPC, budget, or worker errors.
    pub(crate) proof_verification_error_total: Counter,
    /// Remote proof checks skipped because the L1 verifier is not active before T13.
    pub(crate) proof_verification_skipped_total: Counter,

    /// Number of prover attempts that failed, regardless of whether validation rejected
    /// the candidate or an operational error prevented completion.
    pub(crate) failure_total: Counter,

    /// Number of finalized batch candidates that passed prover validation.
    pub(crate) validation_success_total: Counter,

    /// Encoded witness size for a successfully validated batch candidate.
    pub(crate) witness_bytes: Histogram,

    /// Encoded witness size for the latest successfully validated batch candidate.
    pub(crate) witness_bytes_last: Gauge,

    /// Number of Zone blocks in a successfully validated batch witness.
    pub(crate) batch_size_blocks: Histogram,

    /// Number of Zone blocks in the latest successfully validated batch witness.
    pub(crate) batch_size_blocks_last: Gauge,

    /// Number of deposits in a successfully validated batch witness.
    pub(crate) deposits_per_batch: Histogram,

    /// Number of deposits in the latest successfully validated batch witness.
    pub(crate) deposits_per_batch_last: Gauge,

    /// Number of withdrawals in a successfully validated batch witness.
    pub(crate) withdrawals_per_batch: Histogram,

    /// Number of withdrawals in the latest successfully validated batch witness.
    pub(crate) withdrawals_per_batch_last: Gauge,

    /// Number of user transactions in a successfully validated batch witness.
    pub(crate) transactions_per_batch: Histogram,

    /// Number of user transactions in the latest successfully validated batch witness.
    pub(crate) transactions_per_batch_last: Gauge,

    /// Number of Zone state trie nodes in a successfully validated batch witness.
    pub(crate) zone_state_nodes: Histogram,

    /// Number of Zone state trie nodes in the latest successfully validated batch witness.
    pub(crate) zone_state_nodes_last: Gauge,

    /// Number of Tempo state trie nodes in a successfully validated batch witness.
    pub(crate) tempo_state_nodes: Histogram,

    /// Number of Tempo state trie nodes in the latest successfully validated batch witness.
    pub(crate) tempo_state_nodes_last: Gauge,
}

/// Metrics emitted by the withdrawal processor.
#[derive(Metrics, Clone)]
#[metrics(scope = "tempo_zone_withdrawal_processor")]
pub(crate) struct WithdrawalProcessorMetrics {
    /// Current portal withdrawal queue head slot.
    pub(crate) portal_queue_head: Gauge,

    /// Current portal withdrawal queue tail slot.
    pub(crate) portal_queue_tail: Gauge,

    /// Number of pending portal withdrawal queue slots.
    pub(crate) portal_queue_pending_slots: Gauge,

    /// Number of withdrawal batches currently stored in memory.
    pub(crate) store_batch_count: Gauge,

    /// Number of withdrawals submitted in `processWithdrawals` transactions.
    pub(crate) withdrawals_processed_total: Counter,

    /// Number of withdrawals packed into each `processWithdrawals` transaction.
    pub(crate) withdrawals_per_batch: Histogram,

    /// Number of withdrawals confirmed on L1.
    pub(crate) withdrawals_confirmed_total: Counter,

    /// Number of `processWithdrawals` transactions confirmed on L1.
    pub(crate) batches_confirmed_total: Counter,

    /// Number of withdrawals that failed to send, confirm, or reverted after inclusion.
    pub(crate) withdrawals_failed_total: Counter,

    /// Number of withdrawals in `processWithdrawals` transactions that reverted on L1.
    pub(crate) withdrawals_reverted_total: Counter,

    /// Time spent processing a withdrawal queue slot.
    pub(crate) slot_processing_duration_seconds: Histogram,
}

/// Metrics emitted by the zone monitor and batch submitter.
#[derive(Metrics, Clone)]
#[metrics(scope = "tempo_zone_monitor")]
pub(crate) struct ZoneMonitorMetrics {
    /// Most recent zone block observed on L2.
    pub latest_zone_block_observed: Gauge,

    /// Most recent zone block successfully submitted to L1.
    pub latest_zone_block_submitted_to_l1: Gauge,

    /// Gap between the latest observed zone block and the latest submitted zone block.
    pub zone_to_l1_submission_lag_blocks: Gauge,

    /// Number of zone blocks included in a batch submission.
    pub batch_size_blocks: Histogram,

    /// Number of withdrawals included in a batch submission.
    pub withdrawals_per_batch: Histogram,

    /// End-to-end latency of a batch submission attempt in seconds.
    pub batch_submit_latency_seconds: Histogram,

    /// Successful batch submissions.
    pub batch_submit_success_total: Counter,

    /// Failed batch submissions after exhausting retries.
    pub batch_submit_failure_total: Counter,

    /// Retry attempts for batch submissions.
    pub batch_submit_retry_total: Counter,

    /// Settlement attempts rebuilt because the live L1 prover hardfork changed.
    pub prover_hardfork_rebuild_total: Counter,

    /// Batches that selected the proofless verifier after proving or preflight failed.
    pub batch_no_proof_fallback_total: Counter,

    /// Failed attempts to rebuild the in-memory withdrawal store from chain state.
    pub withdrawal_store_restore_failure_total: Counter,

    /// Head-page refills requested by the withdrawal processor.
    pub withdrawal_store_refill_total: Counter,
}
