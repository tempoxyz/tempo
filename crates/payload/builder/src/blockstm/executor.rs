//! Core Block-STM executor.

use crate::blockstm::{
    config::BlockStmConfig,
    overlay::{BlockStmOverlay, BlockStmVersion},
    rw_set::{BlockStmReadSet, BlockStmWriteSet},
    stats::BlockStmExecutionStats,
};
use std::{error::Error, fmt};

/// Result of one speculative execution attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStmAttempt<T> {
    /// Transaction index in the builder-selected order.
    pub tx_index: usize,
    /// Attempt number for this transaction.
    pub attempt: usize,
    /// Captured reads.
    pub read_set: BlockStmReadSet,
    /// Captured writes.
    pub write_set: BlockStmWriteSet,
    /// Runner output.
    pub output: T,
}

/// Error returned by the core executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockStmExecutorError {
    /// The runner did not produce an attempt for a requested transaction.
    MissingAttempt { tx_index: usize },
    /// The runner returned output for a different transaction incarnation.
    StaleAttempt {
        tx_index: usize,
        expected_attempt: usize,
        actual_tx_index: usize,
        actual_attempt: usize,
    },
    /// Validation never stabilized within the retry budget.
    RetryBudgetExceeded { tx_index: usize, attempts: usize },
    /// Runner-specific deterministic error.
    Runner(String),
}

impl fmt::Display for BlockStmExecutorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAttempt { tx_index } => {
                write!(f, "missing Block-STM attempt for tx {tx_index}")
            }
            Self::StaleAttempt {
                tx_index,
                expected_attempt,
                actual_tx_index,
                actual_attempt,
            } => write!(
                f,
                "stale Block-STM attempt for tx {tx_index} incarnation {expected_attempt}: got tx {actual_tx_index} incarnation {actual_attempt}"
            ),
            Self::RetryBudgetExceeded { tx_index, attempts } => {
                write!(
                    f,
                    "retry budget exceeded for tx {tx_index} after {attempts} attempts"
                )
            }
            Self::Runner(err) => f.write_str(err),
        }
    }
}

impl Error for BlockStmExecutorError {}

/// Production Block-STM executor shell plus reusable core execution loop.
#[derive(Debug, Clone)]
pub struct BlockStmExecutor {
    config: BlockStmConfig,
}

/// Production payload-builder adapter.
#[derive(Debug, Clone)]
pub struct ParallelTempoBlockExecutor {
    inner: BlockStmExecutor,
}

impl BlockStmExecutor {
    /// Creates an executor with the provided configuration.
    pub const fn new(config: BlockStmConfig) -> Self {
        Self { config }
    }

    /// Returns the configured retry budget.
    pub const fn max_retries_per_tx(&self) -> usize {
        self.config.max_retries_per_tx
    }

    /// Executes a deterministic batch with Block-STM validation and ordered commit.
    pub fn execute<T, E, F>(
        &self,
        tx_count: usize,
        overlay: &mut BlockStmOverlay,
        mut run_attempt: F,
    ) -> Result<(Vec<T>, BlockStmExecutionStats), BlockStmExecutorError>
    where
        F: FnMut(usize, usize, &BlockStmOverlay) -> Result<BlockStmAttempt<T>, E>,
        E: fmt::Display,
    {
        if tx_count == 0 {
            return Ok((Vec::new(), BlockStmExecutionStats::default()));
        }

        let mut stats = BlockStmExecutionStats::default();
        let mut attempts: Vec<Option<BlockStmAttempt<T>>> =
            std::iter::repeat_with(|| None).take(tx_count).collect();
        let mut attempt_counts = vec![0usize; tx_count];

        for (tx_index, slot) in attempts.iter_mut().enumerate() {
            let attempt = run_attempt(tx_index, attempt_counts[tx_index], overlay)
                .map_err(|err| BlockStmExecutorError::Runner(err.to_string()))?;
            Self::validate_attempt_identity(tx_index, attempt_counts[tx_index], &attempt)?;
            attempt_counts[tx_index] += 1;
            stats.speculative_executions_total += 1;
            *slot = Some(attempt);
        }

        let mut committed = Vec::with_capacity(tx_count);
        for tx_index in 0..tx_count {
            loop {
                let attempt = attempts[tx_index]
                    .take()
                    .ok_or(BlockStmExecutorError::MissingAttempt { tx_index })?;
                if overlay.validate_reads(tx_index, &attempt.read_set).is_ok() {
                    overlay.commit_version(
                        BlockStmVersion::new(tx_index, attempt.attempt),
                        &attempt.write_set,
                    );
                    stats.committed_txs_total += 1;
                    committed.push(attempt.output);
                    break;
                }

                stats.conflicts_total += 1;
                stats.reexecutions_total += 1;
                overlay.mark_estimate(
                    BlockStmVersion::new(tx_index, attempt.attempt),
                    &attempt.write_set,
                );
                if attempt_counts[tx_index] >= self.config.max_retries_per_tx {
                    return Err(BlockStmExecutorError::RetryBudgetExceeded {
                        tx_index,
                        attempts: attempt_counts[tx_index],
                    });
                }

                let attempt = run_attempt(tx_index, attempt_counts[tx_index], overlay)
                    .map_err(|err| BlockStmExecutorError::Runner(err.to_string()))?;
                Self::validate_attempt_identity(tx_index, attempt_counts[tx_index], &attempt)?;
                attempt_counts[tx_index] += 1;
                stats.speculative_executions_total += 1;
                attempts[tx_index] = Some(attempt);
            }
        }

        Ok((committed, stats))
    }

    fn validate_attempt_identity<T>(
        tx_index: usize,
        expected_attempt: usize,
        attempt: &BlockStmAttempt<T>,
    ) -> Result<(), BlockStmExecutorError> {
        if attempt.tx_index == tx_index && attempt.attempt == expected_attempt {
            return Ok(());
        }

        Err(BlockStmExecutorError::StaleAttempt {
            tx_index,
            expected_attempt,
            actual_tx_index: attempt.tx_index,
            actual_attempt: attempt.attempt,
        })
    }
}

impl ParallelTempoBlockExecutor {
    /// Creates the production adapter.
    pub const fn new(config: BlockStmConfig) -> Self {
        Self {
            inner: BlockStmExecutor::new(config),
        }
    }

    /// Returns the reusable core executor.
    pub const fn inner(&self) -> &BlockStmExecutor {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstm::{
        overlay::BlockStmVersion,
        rw_set::{BlockStmAccessKey, BlockStmValue},
        state_view::BlockStmStateView,
    };
    use alloy_primitives::{Address, B256, U256};

    fn addr(n: u64) -> Address {
        Address::from_word(B256::from(U256::from(n)))
    }

    fn account(n: u64) -> BlockStmAccessKey {
        BlockStmAccessKey::Account(addr(n))
    }

    fn code(n: u64) -> BlockStmAccessKey {
        BlockStmAccessKey::Code { address: addr(n) }
    }

    fn storage(n: u64) -> BlockStmAccessKey {
        BlockStmAccessKey::Storage {
            address: addr(1),
            slot: U256::from(n),
        }
    }

    fn attempt(
        tx_index: usize,
        attempt: usize,
        reads: impl IntoIterator<Item = (BlockStmAccessKey, u64)>,
        writes: impl IntoIterator<Item = (BlockStmAccessKey, u64)>,
        output: u64,
    ) -> BlockStmAttempt<u64> {
        let mut read_set = BlockStmReadSet::default();
        let mut write_set = BlockStmWriteSet::default();
        for (key, value) in reads {
            read_set.record(key, value);
        }
        for (key, value) in writes {
            write_set.record(key, value);
        }
        BlockStmAttempt {
            tx_index,
            attempt,
            read_set,
            write_set,
            output,
        }
    }

    #[test]
    fn blockstm_core_empty_batch_returns_no_commits() {
        let executor = BlockStmExecutor::new(BlockStmConfig::test());
        let mut overlay = BlockStmOverlay::default();
        let (committed, stats) = executor
            .execute::<u64, &str, _>(0, &mut overlay, |_, _, _| unreachable!())
            .unwrap();

        assert!(committed.is_empty());
        assert_eq!(stats, BlockStmExecutionStats::default());
        assert!(overlay.commit_order().is_empty());
    }

    #[test]
    fn blockstm_core_preserves_fixed_commit_order_for_independent_results() {
        let executor = BlockStmExecutor::new(BlockStmConfig::test());
        let mut overlay = BlockStmOverlay::default();
        let (committed, stats) = executor
            .execute::<u64, &str, _>(4, &mut overlay, |tx_index, attempt_no, _| {
                Ok(attempt(tx_index, attempt_no, [], [], tx_index as u64))
            })
            .unwrap();

        assert_eq!(committed, vec![0, 1, 2, 3]);
        assert_eq!(stats.speculative_executions_total, 4);
        assert_eq!(stats.committed_txs_total, 4);
        assert_eq!(stats.conflicts_total, 0);
    }

    #[test]
    fn blockstm_core_validation_detects_storage_conflict() {
        let key = storage(0);
        let mut overlay = BlockStmOverlay::default();
        let mut writes = BlockStmWriteSet::default();
        writes.record(key, 1u64);
        overlay.commit(0, &writes);
        let mut reads = BlockStmReadSet::default();
        reads.record(key, 0u64);

        assert_eq!(overlay.validate_reads(1, &reads), Err(key));
    }

    #[test]
    fn blockstm_core_validation_detects_account_conflict() {
        let key = account(1);
        let mut overlay = BlockStmOverlay::default();
        let mut writes = BlockStmWriteSet::default();
        writes.record(key, 1u64);
        overlay.commit(0, &writes);
        let mut reads = BlockStmReadSet::default();
        reads.record(key, 0u64);

        assert_eq!(overlay.validate_reads(1, &reads), Err(key));
    }

    #[test]
    fn blockstm_core_validation_detects_code_conflict() {
        let key = code(1);
        let mut overlay = BlockStmOverlay::default();
        let mut writes = BlockStmWriteSet::default();
        writes.record(key, 1u64);
        overlay.commit(0, &writes);
        let mut reads = BlockStmReadSet::default();
        reads.record(key, 0u64);

        assert_eq!(overlay.validate_reads(1, &reads), Err(key));
    }

    #[test]
    fn blockstm_core_reexecution_replaces_stale_result() {
        let key = storage(0);
        let executor = BlockStmExecutor::new(BlockStmConfig::test());
        let mut overlay = BlockStmOverlay::new([(key, BlockStmValue::from(0u64))]);
        let (committed, stats) = executor
            .execute::<u64, &str, _>(2, &mut overlay, |tx_index, attempt_no, overlay| {
                Ok(match (tx_index, attempt_no) {
                    (0, _) => attempt(tx_index, attempt_no, [], [(key, 7)], 7),
                    (1, 0) => attempt(tx_index, attempt_no, [(key, 0)], [], 0),
                    (1, _) => {
                        let mut view = BlockStmStateView::new(tx_index, overlay);
                        let value = view.read(key);
                        let (read_set, write_set) = view.finish();
                        BlockStmAttempt {
                            tx_index,
                            attempt: attempt_no,
                            read_set,
                            write_set,
                            output: U256::from_be_bytes(value.0.0).to::<u64>(),
                        }
                    }
                    _ => unreachable!(),
                })
            })
            .unwrap();

        assert_eq!(committed, vec![7, 7]);
        assert_eq!(stats.conflicts_total, 1);
        assert_eq!(stats.reexecutions_total, 1);
    }

    #[test]
    fn blockstm_core_rejects_stale_incarnation_output() {
        let executor = BlockStmExecutor::new(BlockStmConfig::test());
        let mut overlay = BlockStmOverlay::default();
        let err = executor
            .execute::<u64, &str, _>(1, &mut overlay, |tx_index, _attempt_no, _| {
                Ok(attempt(tx_index, 7, [], [], 0))
            })
            .unwrap_err();

        assert_eq!(
            err,
            BlockStmExecutorError::StaleAttempt {
                tx_index: 0,
                expected_attempt: 0,
                actual_tx_index: 0,
                actual_attempt: 7,
            }
        );
    }

    #[test]
    fn blockstm_core_marks_failed_incarnation_writes_as_estimates() {
        let key = storage(0);
        let executor = BlockStmExecutor::new(BlockStmConfig::test());
        let mut overlay = BlockStmOverlay::new([(key, BlockStmValue::from(0u64))]);
        let (_committed, stats) = executor
            .execute::<u64, &str, _>(2, &mut overlay, |tx_index, attempt_no, overlay| {
                Ok(match (tx_index, attempt_no) {
                    (0, _) => attempt(tx_index, attempt_no, [], [(key, 2)], 2),
                    (1, 0) => attempt(tx_index, attempt_no, [(key, 0)], [(key, 1)], 1),
                    (1, 1) => {
                        let mut view = BlockStmStateView::new(tx_index, overlay);
                        let value = view.read(key);
                        view.write(key, value.as_u256() + U256::from(1));
                        let (read_set, write_set) = view.finish();
                        attempt(
                            tx_index,
                            attempt_no,
                            read_set.iter().map(|(k, v)| (*k, v.as_u256().to::<u64>())),
                            write_set.iter().map(|(k, v)| (*k, v.as_u256().to::<u64>())),
                            3,
                        )
                    }
                    _ => unreachable!(),
                })
            })
            .unwrap();

        assert_eq!(stats.reexecutions_total, 1);
        let committed = overlay.committed_value(&key).unwrap();
        assert_eq!(committed.version, BlockStmVersion::new(1, 1));
        assert_eq!(committed.value, 3u64.into());
    }

    #[test]
    fn blockstm_core_transitive_conflict_chain_reexecutes_until_stable() {
        let a = storage(1);
        let b = storage(2);
        let executor = BlockStmExecutor::new(BlockStmConfig::test());
        let mut overlay = BlockStmOverlay::new([(a, 0u64.into()), (b, 0u64.into())]);
        let (committed, stats) = executor
            .execute::<u64, &str, _>(3, &mut overlay, |tx_index, attempt_no, overlay| {
                Ok(match (tx_index, attempt_no) {
                    (0, _) => attempt(tx_index, attempt_no, [], [(a, 1)], 1),
                    (1, 0) => attempt(tx_index, attempt_no, [(a, 0)], [(b, 1)], 1),
                    (1, _) => {
                        let mut view = BlockStmStateView::new(tx_index, overlay);
                        let value = view.read(a);
                        view.write(b, U256::from_be_bytes(value.0.0) + U256::from(1));
                        let (read_set, write_set) = view.finish();
                        attempt(
                            tx_index,
                            attempt_no,
                            read_set
                                .iter()
                                .map(|(k, v)| (*k, U256::from_be_bytes(v.0.0).to::<u64>())),
                            write_set
                                .iter()
                                .map(|(k, v)| (*k, U256::from_be_bytes(v.0.0).to::<u64>())),
                            2,
                        )
                    }
                    (2, 0) => attempt(tx_index, attempt_no, [(b, 0)], [], 0),
                    (2, _) => {
                        let mut view = BlockStmStateView::new(tx_index, overlay);
                        let value = view.read(b);
                        let (read_set, write_set) = view.finish();
                        BlockStmAttempt {
                            tx_index,
                            attempt: attempt_no,
                            read_set,
                            write_set,
                            output: U256::from_be_bytes(value.0.0).to::<u64>(),
                        }
                    }
                    _ => unreachable!(),
                })
            })
            .unwrap();

        assert_eq!(committed, vec![1, 2, 2]);
        assert_eq!(stats.conflicts_total, 2);
        assert_eq!(stats.reexecutions_total, 2);
    }

    #[test]
    fn blockstm_core_retry_budget_requires_forward_progress() {
        let key = storage(0);
        let executor = BlockStmExecutor::new(BlockStmConfig {
            max_retries_per_tx: 2,
            ..BlockStmConfig::test()
        });
        let mut overlay = BlockStmOverlay::default();
        let err = executor
            .execute::<u64, &str, _>(2, &mut overlay, |tx_index, attempt_no, _| {
                Ok(match tx_index {
                    0 => attempt(tx_index, attempt_no, [], [(key, 1)], 1),
                    1 => attempt(tx_index, attempt_no, [(key, 0)], [], 0),
                    _ => unreachable!(),
                })
            })
            .unwrap_err();

        assert_eq!(
            err,
            BlockStmExecutorError::RetryBudgetExceeded {
                tx_index: 1,
                attempts: 2
            }
        );
        assert_eq!(overlay.commit_order().len(), 1);
    }

    #[test]
    fn blockstm_core_metrics_count_attempts_conflicts_reexecs_commits() {
        let key = storage(0);
        let executor = BlockStmExecutor::new(BlockStmConfig::test());
        let mut overlay = BlockStmOverlay::default();
        let (_committed, stats) = executor
            .execute::<u64, &str, _>(3, &mut overlay, |tx_index, attempt_no, overlay| {
                Ok(match (tx_index, attempt_no) {
                    (0, _) => attempt(tx_index, attempt_no, [], [], 0),
                    (1, _) => attempt(tx_index, attempt_no, [], [(key, 1)], 1),
                    (2, 0) => attempt(tx_index, attempt_no, [(key, 0)], [], 0),
                    (2, _) => {
                        let mut view = BlockStmStateView::new(tx_index, overlay);
                        let value = view.read(key);
                        let (read_set, write_set) = view.finish();
                        BlockStmAttempt {
                            tx_index,
                            attempt: attempt_no,
                            read_set,
                            write_set,
                            output: U256::from_be_bytes(value.0.0).to::<u64>(),
                        }
                    }
                    _ => unreachable!(),
                })
            })
            .unwrap();

        assert_eq!(stats.speculative_executions_total, 4);
        assert_eq!(stats.conflicts_total, 1);
        assert_eq!(stats.reexecutions_total, 1);
        assert_eq!(stats.committed_txs_total, 3);
    }
}
