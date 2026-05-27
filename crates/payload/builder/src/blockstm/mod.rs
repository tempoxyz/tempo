//! Block-STM payload builder support.

pub mod action;
pub mod commit;
pub mod config;
pub mod executor;
pub mod metrics;
pub mod overlay;
pub mod policy;
pub mod rw_set;
pub mod scheduler;
pub mod state_view;
pub mod stats;

pub use action::{BlockStmAction, BlockStmActionKind, BlockStmActionLog, BlockStmResource};
pub use config::BlockStmConfig;
pub use executor::{BlockStmExecutor, ParallelTempoBlockExecutor};
pub use metrics::BlockStmMetrics;
pub use overlay::{BlockStmOverlay, BlockStmOverlayStatus, BlockStmOverlayValue, BlockStmVersion};
pub use policy::{BlockStmConflictPolicy, BlockStmDependencyDomain, BlockStmStrategy};
pub use rw_set::{BlockStmAccessKey, BlockStmReadSet, BlockStmValue, BlockStmWriteSet};
pub use scheduler::{BlockStmScheduledTask, BlockStmScheduler, BlockStmTaskKind};
pub use state_view::BlockStmStateView;
pub use stats::BlockStmExecutionStats;

#[cfg(test)]
mod required_prefix_tests {
    use super::*;
    use alloy_primitives::{Address, U256};

    fn key(slot: u64) -> BlockStmAccessKey {
        BlockStmAccessKey::Storage {
            address: Address::repeat_byte(0x20),
            slot: U256::from(slot),
        }
    }

    fn attempt(
        tx_index: usize,
        attempt_no: usize,
        read_key: Option<(BlockStmAccessKey, u64)>,
        write_key: Option<(BlockStmAccessKey, u64)>,
        output: u64,
    ) -> executor::BlockStmAttempt<u64> {
        let mut read_set = BlockStmReadSet::default();
        let mut write_set = BlockStmWriteSet::default();
        if let Some((key, value)) = read_key {
            read_set.record(key, value);
        }
        if let Some((key, value)) = write_key {
            write_set.record(key, value);
        }
        executor::BlockStmAttempt {
            tx_index,
            attempt: attempt_no,
            read_set,
            write_set,
            output,
        }
    }

    #[test]
    fn blockstm_dependency_inventory_covers_known_tempo_domains() {
        let domains = BlockStmConflictPolicy::known_domains();

        assert!(domains.contains(&BlockStmDependencyDomain::SenderNonce));
        assert!(domains.contains(&BlockStmDependencyDomain::ExpiringNonce));
        assert!(domains.contains(&BlockStmDependencyDomain::FeePayerBalance));
        assert!(domains.contains(&BlockStmDependencyDomain::ValidatorFeeCredit));
        assert!(domains.contains(&BlockStmDependencyDomain::Tip20Balance));
        assert!(domains.contains(&BlockStmDependencyDomain::AmmPoolLiquidity));
        assert!(domains.contains(&BlockStmDependencyDomain::LimitOrderBook));
        assert!(domains.contains(&BlockStmDependencyDomain::BuilderLimitsAndPoolFeedback));
        assert_eq!(domains.len(), 17);
    }

    #[test]
    fn blockstm_conflict_policy_unknown_contract_storage_defaults_to_reexecute() {
        let policy = BlockStmConflictPolicy::default();

        assert_eq!(
            policy.strategy_for(BlockStmDependencyDomain::UnknownContractStorage),
            BlockStmStrategy::AlwaysReexecute
        );
        assert_ne!(
            policy.strategy_for(BlockStmDependencyDomain::UnknownContractStorage),
            BlockStmStrategy::DirectSlotResolver
        );
    }

    #[test]
    fn blockstm_result_reuse_rejected_for_evm_read_conflict() {
        let storage_key = key(0);
        let mut overlay = BlockStmOverlay::default();
        let mut writes = BlockStmWriteSet::default();
        writes.record(storage_key, 7u64);
        overlay.commit(0, &writes);

        let mut stale_reads = BlockStmReadSet::default();
        stale_reads.record(storage_key, 0u64);

        assert_eq!(overlay.validate_reads(1, &stale_reads), Err(storage_key));
    }

    #[test]
    fn blockstm_direct_slot_resolver_disabled_for_unknown_slots() {
        let policy = BlockStmConflictPolicy::default();

        assert_eq!(
            policy.strategy_for(BlockStmDependencyDomain::UnknownContractStorage),
            BlockStmStrategy::AlwaysReexecute
        );
    }

    #[test]
    fn blockstm_executor_single_real_tx_matches_serial() {
        let executor = ParallelTempoBlockExecutor::new(BlockStmConfig::test());
        let mut overlay = BlockStmOverlay::default();
        let (committed, stats) = executor
            .inner()
            .execute::<u64, &str, _>(1, &mut overlay, |tx_index, attempt_no, _| {
                Ok(attempt(tx_index, attempt_no, None, Some((key(1), 11)), 11))
            })
            .unwrap();

        assert_eq!(committed, vec![11]);
        assert_eq!(stats.speculative_executions_total, 1);
        assert_eq!(stats.committed_txs_total, 1);
        assert_eq!(stats.conflicts_total, 0);
        assert_eq!(
            overlay.committed_value(&key(1)).unwrap().value,
            11u64.into()
        );
    }

    #[test]
    fn blockstm_builder_flag_off_leaves_serial_path_and_zero_counters() {
        let config = BlockStmConfig::default();
        let stats = BlockStmExecutionStats::default();

        assert!(!config.enabled);
        assert_eq!(stats.speculative_executions_total, 0);
        assert_eq!(stats.committed_txs_total, 0);
        assert_eq!(stats.built_blocks_total, 0);
    }

    #[test]
    fn blockstm_metrics_count_conflicts_reexec_commits_and_blocks() {
        let stats = BlockStmExecutionStats {
            speculative_executions_total: 3,
            committed_txs_total: 2,
            conflicts_total: 1,
            reexecutions_total: 1,
            built_blocks_total: 1,
            semantic_actions_total: 5,
            ..Default::default()
        };

        BlockStmMetrics.emit_block(stats);
        assert_eq!(stats.committed_txs_total, 2);
        assert_eq!(stats.conflicts_total, 1);
        assert_eq!(stats.reexecutions_total, 1);
        assert_eq!(stats.built_blocks_total, 1);
    }

    #[test]
    fn blockstm_randomized_serial_equivalence_for_small_batches() {
        let storage_key = key(99);
        for seed in 0..8u64 {
            let initial = seed % 3;
            let mut serial_value = initial;
            let serial = (0..5)
                .map(|index| {
                    serial_value += index + 1;
                    serial_value
                })
                .collect::<Vec<_>>();

            let executor = BlockStmExecutor::new(BlockStmConfig::test());
            let mut overlay = BlockStmOverlay::new([(storage_key, BlockStmValue::from(initial))]);
            let (committed, stats) = executor
                .execute::<u64, &str, _>(5, &mut overlay, |tx_index, attempt_no, overlay| {
                    if attempt_no == 0 {
                        Ok(attempt(
                            tx_index,
                            attempt_no,
                            Some((storage_key, initial)),
                            Some((storage_key, initial + tx_index as u64 + 1)),
                            initial + tx_index as u64 + 1,
                        ))
                    } else {
                        let prefix = overlay.read(storage_key, tx_index).as_u256().to::<u64>();
                        let next = prefix + tx_index as u64 + 1;
                        Ok(attempt(
                            tx_index,
                            attempt_no,
                            Some((storage_key, prefix)),
                            Some((storage_key, next)),
                            next,
                        ))
                    }
                })
                .unwrap();

            assert_eq!(committed, serial, "seed {seed}");
            assert_eq!(stats.committed_txs_total, 5);
            assert!(stats.reexecutions_total >= 4);
        }
    }
}
