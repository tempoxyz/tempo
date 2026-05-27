//! Block-STM payload builder configuration.

/// Runtime configuration for the Block-STM payload builder path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockStmConfig {
    /// Enables the production Block-STM builder path for normal pool transactions.
    pub enabled: bool,
    /// Number of bounded speculative workers.
    pub workers: usize,
    /// Enables semantic action replay for the pure TIP20 fast path.
    pub tip20_actions: bool,
    /// Maximum re-execution attempts for one transaction before returning an error.
    pub max_retries_per_tx: usize,
    /// Per-domain conflict threshold before adaptive serial fallback is selected.
    pub adaptive_conflict_threshold: usize,
}

impl Default for BlockStmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            workers: std::thread::available_parallelism().map_or(1, usize::from),
            tip20_actions: false,
            max_retries_per_tx: 16,
            adaptive_conflict_threshold: 64,
        }
    }
}

impl BlockStmConfig {
    /// Returns a config suitable for deterministic single-threaded tests.
    pub const fn test() -> Self {
        Self {
            enabled: true,
            workers: 1,
            tip20_actions: true,
            max_retries_per_tx: 16,
            adaptive_conflict_threshold: 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blockstm_config_defaults_to_disabled() {
        let config = BlockStmConfig::default();
        assert!(!config.enabled);
        assert!(config.workers >= 1);
        assert!(!config.tip20_actions);
    }
}
