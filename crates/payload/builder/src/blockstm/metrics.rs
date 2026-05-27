//! Production metrics for the Block-STM builder path.

use crate::blockstm::stats::BlockStmExecutionStats;

/// Metrics emitter for Block-STM production execution.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockStmMetrics;

impl BlockStmMetrics {
    /// Emits the summary counters for one built block.
    pub fn emit_block(&self, stats: BlockStmExecutionStats) {
        metrics::counter!("tempo_payload_builder_blockstm_enabled_total").increment(1);
        metrics::counter!("tempo_payload_builder_blockstm_speculative_executions_total")
            .increment(stats.speculative_executions_total);
        metrics::counter!("tempo_payload_builder_blockstm_committed_txs_total")
            .increment(stats.committed_txs_total);
        metrics::counter!("tempo_payload_builder_blockstm_conflicts_total")
            .increment(stats.conflicts_total);
        metrics::counter!("tempo_payload_builder_blockstm_reused_speculative_results_total")
            .increment(stats.reused_speculative_results_total);
        metrics::counter!("tempo_payload_builder_blockstm_reexecutions_total")
            .increment(stats.reexecutions_total);
        metrics::counter!("tempo_payload_builder_blockstm_built_blocks_total")
            .increment(stats.built_blocks_total);
        metrics::gauge!("tempo_payload_builder_blockstm_max_in_flight_real_evm_executions")
            .set(stats.max_in_flight_real_evm_executions as f64);
        metrics::counter!("tempo_payload_builder_blockstm_serial_fallback_total")
            .increment(stats.serial_fallback_total);
        metrics::counter!("tempo_payload_builder_blockstm_semantic_actions_total")
            .increment(stats.semantic_actions_total);
    }
}
