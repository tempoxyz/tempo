//! Block-STM execution counters.

use std::ops::AddAssign;

/// In-memory execution counters used by tests and production metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockStmExecutionStats {
    /// Number of real speculative attempts.
    pub speculative_executions_total: u64,
    /// Number of committed transactions.
    pub committed_txs_total: u64,
    /// Number of read validation conflicts.
    pub conflicts_total: u64,
    /// Number of committed transactions that reused the first speculative worker result.
    pub reused_speculative_results_total: u64,
    /// Number of re-executions after conflict.
    pub reexecutions_total: u64,
    /// Number of blocks built through the Block-STM production path.
    pub built_blocks_total: u64,
    /// Maximum concurrent real EVM executions observed.
    pub max_in_flight_real_evm_executions: u64,
    /// Legacy standalone executor fallback counter; production builder should keep this zero.
    pub serial_fallback_total: u64,
    /// Number of ordered semantic actions replayed into committed results.
    pub semantic_actions_total: u64,
}

impl AddAssign for BlockStmExecutionStats {
    fn add_assign(&mut self, rhs: Self) {
        self.speculative_executions_total += rhs.speculative_executions_total;
        self.committed_txs_total += rhs.committed_txs_total;
        self.conflicts_total += rhs.conflicts_total;
        self.reused_speculative_results_total += rhs.reused_speculative_results_total;
        self.reexecutions_total += rhs.reexecutions_total;
        self.built_blocks_total += rhs.built_blocks_total;
        self.max_in_flight_real_evm_executions = self
            .max_in_flight_real_evm_executions
            .max(rhs.max_in_flight_real_evm_executions);
        self.serial_fallback_total += rhs.serial_fallback_total;
        self.semantic_actions_total += rhs.semantic_actions_total;
    }
}
