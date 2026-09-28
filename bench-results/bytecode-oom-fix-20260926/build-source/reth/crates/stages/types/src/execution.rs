use core::time::Duration;

/// The thresholds at which the execution stage writes state changes to the database.
///
/// If any of the thresholds (`max_blocks`, `max_changes`, `max_cumulative_gas`, `max_duration`,
/// or `max_cached_bytecode_bytes`)
/// are hit, then the execution stage commits all pending changes to the database.
#[derive(Debug, Clone)]
pub struct ExecutionStageThresholds {
    /// The maximum number of blocks to execute before the execution stage commits.
    pub max_blocks: Option<u64>,
    /// The maximum number of state changes to keep in memory before the execution stage commits.
    pub max_changes: Option<u64>,
    /// Maximum cached bytecode buffer bytes before committing, checked between blocks.
    /// This includes read-only bytecode, which is not counted by `max_changes`.
    pub max_cached_bytecode_bytes: Option<u64>,
    /// The maximum cumulative amount of gas to process before the execution stage commits.
    pub max_cumulative_gas: Option<u64>,
    /// The maximum spent on blocks processing before the execution stage commits.
    pub max_duration: Option<Duration>,
}

impl Default for ExecutionStageThresholds {
    fn default() -> Self {
        Self {
            max_blocks: Some(500_000),
            max_changes: Some(5_000_000),
            max_cached_bytecode_bytes: Some(512 * 1024 * 1024),
            // 50k full blocks of 30M gas
            max_cumulative_gas: Some(30_000_000 * 50_000),
            // 10 minutes
            max_duration: Some(Duration::from_secs(10 * 60)),
        }
    }
}

impl ExecutionStageThresholds {
    /// Whether cached bytecode alone requires ending the batch.
    ///
    /// This is a soft limit: one block can exceed it. It does not cap total process memory.
    pub fn is_bytecode_cache_full(&self, cached_bytecode_bytes: u64) -> bool {
        self.max_cached_bytecode_bytes.is_some_and(|limit| cached_bytecode_bytes >= limit)
    }

    /// Check if the batch thresholds have been hit.
    #[inline]
    pub fn is_end_of_batch(
        &self,
        blocks_processed: u64,
        changes_processed: u64,
        cumulative_gas_used: u64,
        elapsed: Duration,
    ) -> bool {
        blocks_processed >= self.max_blocks.unwrap_or(u64::MAX) ||
            changes_processed >= self.max_changes.unwrap_or(u64::MAX) ||
            cumulative_gas_used >= self.max_cumulative_gas.unwrap_or(u64::MAX) ||
            elapsed >= self.max_duration.unwrap_or(Duration::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytecode_limit_is_independent_of_state_changes() {
        let mut thresholds = ExecutionStageThresholds::default();
        let limit = thresholds.max_cached_bytecode_bytes.unwrap();
        assert!(!thresholds.is_end_of_batch(1, 0, 1, Duration::ZERO));
        assert!(!thresholds.is_bytecode_cache_full(limit - 1));
        assert!(thresholds.is_bytecode_cache_full(limit));
        assert!(thresholds.is_bytecode_cache_full(limit + 1));
        thresholds.max_cached_bytecode_bytes = None;
        assert!(!thresholds.is_bytecode_cache_full(u64::MAX));
    }
}
