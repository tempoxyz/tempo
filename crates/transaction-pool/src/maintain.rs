//! Transaction pool maintenance tasks.

use crate::{
    TempoTransactionPool, invalidation::Invalidations, metrics::TempoPoolMaintenanceMetrics,
    transaction::TempoPooledTransaction, validator::ConfigureTempoPoolEvm,
};
use alloy_primitives::{
    Address, Log, TxHash,
    map::{AddressMap, B256Set},
};
use alloy_sol_types::SolEvent;
use futures::StreamExt;
use itertools::{Either, Itertools};
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions, Chain, HeaderProvider};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{AllPoolTransactions, TransactionPool};
use std::{sync::Arc, time::Instant};
use tempo_chainspec::hardfork::TempoHardforks;
use tempo_contracts::precompiles::IFeeManager;
use tempo_precompiles::TIP_FEE_MANAGER_ADDRESS;
use tempo_primitives::{TempoHeader, TempoPrimitives};
use tracing::{debug, error};

/// Evict transactions this many seconds before they expire to reduce propagation
/// of near-expiry transactions that are likely to fail validation on peers.
const EVICTION_BUFFER_SECS: u64 = 3;

/// Block-level events pool maintenance acts on.
#[derive(Debug, Default)]
pub struct TempoPoolUpdates {
    /// Validator token preference changes: validator to new_token (last-write-wins).
    /// Uses `AddressMap` to deduplicate by validator, preventing resource amplification
    /// when a validator emits multiple `ValidatorTokenSet` events in the same block.
    pub validator_token_changes: AddressMap<Address>,
}

impl TempoPoolUpdates {
    /// Creates a new empty `TempoPoolUpdates`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if there are no updates to process.
    pub fn is_empty(&self) -> bool {
        self.validator_token_changes.is_empty()
    }

    /// Extracts pool updates from a committed chain segment.
    pub fn from_chain(chain: &Chain<TempoPrimitives>) -> Self {
        let mut updates = Self::new();
        for log in chain
            .execution_outcome()
            .receipts()
            .iter()
            .flatten()
            .flat_map(|receipt| &receipt.logs)
        {
            updates.apply_log(log);
        }
        updates
    }

    /// Records the event `log` carries, if pool maintenance acts on it.
    pub(crate) fn apply_log(&mut self, log: &Log) {
        if log.address == TIP_FEE_MANAGER_ADDRESS
            && log.topics().first() == Some(&IFeeManager::ValidatorTokenSet::SIGNATURE_HASH)
            && let Ok(event) = IFeeManager::ValidatorTokenSet::decode_log(log)
        {
            self.validator_token_changes
                .insert(event.validator, event.token);
        }
    }
}

/// Default interval for pending transaction staleness checks (30 minutes).
/// Transactions that remain pending across two consecutive snapshots will be evicted.
const DEFAULT_PENDING_STALENESS_INTERVAL: u64 = 30 * 60;

/// Tracks pending transactions across snapshots to detect stale transactions.
///
/// Uses a simple snapshot comparison approach:
/// - Every interval, take a snapshot of current pending transactions
/// - Transactions present in both the previous and current snapshot are considered stale
/// - Stale transactions are evicted since they've been pending for at least one full interval
#[derive(Debug)]
struct PendingStalenessTracker {
    /// Previous snapshot of pending transaction hashes.
    previous_pending: B256Set,
    /// Timestamp of the last snapshot.
    last_snapshot_time: Option<u64>,
    /// Interval in seconds between staleness checks.
    interval_secs: u64,
}

impl PendingStalenessTracker {
    /// Creates a new tracker with the given check interval.
    fn new(interval_secs: u64) -> Self {
        Self {
            previous_pending: B256Set::default(),
            last_snapshot_time: None,
            interval_secs,
        }
    }

    /// Returns true if the staleness check interval has elapsed and a snapshot should be taken.
    fn should_check(&self, now: u64) -> bool {
        self.last_snapshot_time
            .is_none_or(|last| now.saturating_sub(last) >= self.interval_secs)
    }

    /// Checks for stale transactions and updates the snapshot.
    ///
    /// Returns transactions that have been pending across two consecutive snapshots
    /// (i.e., pending for at least one full interval).
    ///
    /// Call `should_check` first to avoid collecting the pending set on every block.
    fn check_and_update(&mut self, current_pending: B256Set, now: u64) -> Vec<TxHash> {
        let previous_pending = std::mem::take(&mut self.previous_pending);

        // Split the current snapshot into stale transactions to evict and fresh
        // transactions to track. A transaction is stale if it appears in both
        // the previous and current pending snapshots.
        let (stale, next_pending): (Vec<TxHash>, B256Set) =
            current_pending.into_iter().partition_map(|hash| {
                if previous_pending.contains(&hash) {
                    Either::Left(hash)
                } else {
                    Either::Right(hash)
                }
            });

        self.previous_pending = next_pending;
        self.last_snapshot_time = Some(now);

        stale
    }
}

impl Default for PendingStalenessTracker {
    fn default() -> Self {
        Self::new(DEFAULT_PENDING_STALENESS_INTERVAL)
    }
}

/// Unified maintenance task for the Tempo transaction pool.
///
/// Handles:
/// - Evicting expired AA transactions (`valid_before <= tip_timestamp`)
/// - Evicting transactions using expired keychain keys (`AuthorizedKey.expiry <= tip_timestamp`)
/// - Updating the AA 2D nonce pool from `NonceManager` changes
/// - Refreshing the AMM liquidity cache from `FeeManager` updates
/// - Removing transactions signed with revoked keychain keys
/// - Evicting transactions when their fee token is paused
///
/// Consolidates these operations into a single event loop to avoid multiple tasks
/// competing for canonical state updates and to minimize contention on pool locks.
pub async fn maintain_tempo_pool<Client, EvmConfig>(pool: TempoTransactionPool<Client, EvmConfig>)
where
    EvmConfig: ConfigureTempoPoolEvm,
    Client: StateProviderFactory
        + HeaderProvider<Header = TempoHeader>
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    let mut pending_staleness = PendingStalenessTracker::default();
    let metrics = TempoPoolMaintenanceMetrics::default();

    // Subscribe to canonical chain events.
    let mut chain_events = pool.client().canonical_state_stream();

    let amm_cache = pool.amm_liquidity_cache();

    // Process all maintenance operations on new block commit or reorg.
    while let Some(event) = chain_events.next().await {
        let new = match event {
            CanonStateNotification::Reorg { old: _, new } => {
                // Repopulate AMM liquidity cache from the new canonical chain
                // to invalidate stale entries from orphaned blocks.
                if let Err(err) = amm_cache.repopulate(pool.client()) {
                    error!(target: "txpool", ?err, "AMM liquidity cache repopulate after reorg failed");
                }

                new
            }
            CanonStateNotification::Commit { new } => new,
        };

        let block_update_start = Instant::now();

        let tip = &new;
        // Publish the block's changes first: a payload build may start on it before the pool
        // takes out what it invalidated.
        let tip_hash = tip.tip().hash();
        let invalidations = Arc::new(Invalidations::from_chain(tip));
        pool.recent_blocks().publish(
            tip.first().header().parent_hash(),
            tip_hash,
            invalidations.clone(),
        );
        let bundle_state = tip.execution_outcome().state().state();
        let tip_timestamp = tip.tip().header().timestamp();

        // Removed transactions are collected here and dropped at the end of the
        // iteration: deallocating them (input data, signatures, allocator work) is
        // expensive and there is a block time of slack after the updates are done.
        let mut removed_txs: Vec<Vec<_>> = Vec::with_capacity(1);

        // 1. Update 2D nonce pool before scan-based maintenance.
        // This removes mined 2D nonce transactions and promotes newly
        // unblocked transactions before later pool scans.
        let nonce_pool_start = Instant::now();
        removed_txs.push(pool.notify_aa_pool_on_state_updates(bundle_state));
        metrics
            .nonce_pool_update_duration_seconds
            .record(nonce_pool_start.elapsed());

        // 2. Update AMM liquidity cache before revalidation/invalidation scans.
        let amm_start = Instant::now();
        amm_cache.on_new_state(tip.execution_outcome());
        if let Err(err) = amm_cache.on_new_blocks(
            tip.blocks_iter().map(|block| block.sealed_header()),
            pool.client(),
        ) {
            error!(target: "txpool", ?err, "AMM liquidity cache update failed");
        }
        metrics
            .amm_cache_update_duration_seconds
            .record(amm_start.elapsed());

        let mut all_txs: Option<AllPoolTransactions<TempoPooledTransaction>> = None;
        // Reth's canonical-update handling may not have pruned mined transactions yet.
        // Exclude them from every snapshot-based maintenance phase so they follow the
        // normal mined path rather than being discarded from the pool.
        let removed_this_iteration: B256Set = tip.transaction_hashes().copied().collect();

        let mut revalidate_txs = Vec::new();

        // 3. Evict expired and invalidated transactions, and take out those the block may have
        // invalidated for revalidation, in one pool traversal.
        let invalidation_start = Instant::now();
        let invalidated = {
            let all_txs = all_txs.get_or_insert_with(|| pool.all_transactions());
            pool.evict_invalidated_transactions_from(
                &invalidations,
                all_txs
                    .iter()
                    .filter(|tx| !removed_this_iteration.contains(tx.hash())),
                Some(tip_timestamp.saturating_add(EVICTION_BUFFER_SECS)),
            )
        };
        metrics
            .transactions_invalidated
            .increment(invalidated.evicted.len() as u64);
        pool.recent_blocks().mark_maintained(tip_hash);
        revalidate_txs.extend(invalidated.revalidate.into_iter().map(|(tx, _)| tx));
        removed_txs.push(invalidated.evicted);
        metrics
            .invalidation_eviction_duration_seconds
            .record(invalidation_start.elapsed());
        metrics
            .expired_eviction_duration_seconds
            .record(invalidation_start.elapsed());

        // 4. Revalidate the transactions whose validity the block may have changed.
        if !revalidate_txs.is_empty() {
            let pool = pool.clone();
            tokio::spawn(async move {
                let txs = revalidate_txs
                    .into_iter()
                    .map(|tx| (tx.origin, tx.transaction.with_discarded_caches()))
                    .collect();
                let results = pool.add_transactions_with_origins(txs).await;
                debug!(target: "txpool", total = results.len(),
                    success = results.iter().filter(|result| result.is_ok()).count(),
                    "Revalidated transactions");
            });
        }

        // 5. Evict stale pending transactions (must happen after AA pool promotions in step 1)
        // Only runs once per interval (~30 min) to avoid overhead on every block.
        // Transactions pending across two consecutive snapshots are considered stale.
        if pending_staleness.should_check(tip_timestamp) {
            let current_pending: B256Set = pool
                .pending_transactions()
                .iter()
                .map(|tx| *tx.hash())
                .collect();
            let stale_to_evict = pending_staleness.check_and_update(current_pending, tip_timestamp);

            if !stale_to_evict.is_empty() {
                debug!(
                    target: "txpool",
                    count = stale_to_evict.len(),
                    tip_timestamp,
                    "Evicting stale pending transactions"
                );
                removed_txs.push(pool.remove_transactions(stale_to_evict));
            }
        }

        // Record total block update duration
        metrics
            .block_update_duration_seconds
            .record(block_update_start.elapsed());

        // Deallocating removed transactions is expensive, so do it after all updates are done.
        drop(removed_txs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_primitives::TxHash;

    mod pending_staleness_tracker_tests {
        use super::*;

        #[test]
        fn no_eviction_on_first_snapshot() {
            let mut tracker = PendingStalenessTracker::new(100);
            let tx1 = TxHash::random();

            // First snapshot should not evict anything (no previous snapshot to compare)
            let stale = tracker.check_and_update([tx1].into_iter().collect(), 100);
            assert!(stale.is_empty());
            assert!(tracker.previous_pending.contains(&tx1));
        }

        #[test]
        fn evicts_transactions_present_in_both_snapshots() {
            let mut tracker = PendingStalenessTracker::new(100);
            let tx_stale = TxHash::random();
            let tx_new = TxHash::random();

            // First snapshot at t=0
            tracker.check_and_update([tx_stale].into_iter().collect(), 0);

            // Second snapshot at t=100: tx_stale still pending, tx_new is new
            let stale = tracker.check_and_update([tx_stale, tx_new].into_iter().collect(), 100);

            // tx_stale was in both snapshots -> evicted
            assert_eq!(stale.len(), 1);
            assert!(stale.contains(&tx_stale));

            // tx_new should be tracked for the next snapshot
            assert!(tracker.previous_pending.contains(&tx_new));
            // tx_stale should NOT be in the snapshot (it was evicted)
            assert!(!tracker.previous_pending.contains(&tx_stale));
        }

        #[test]
        fn should_check_returns_false_before_interval_elapsed() {
            let mut tracker = PendingStalenessTracker::new(100);
            let tx = TxHash::random();

            // First snapshot at t=0
            assert!(tracker.should_check(0));
            tracker.check_and_update([tx].into_iter().collect(), 0);

            // At t=50 (before interval elapsed) - should_check returns false
            assert!(!tracker.should_check(50));
            assert_eq!(tracker.last_snapshot_time, Some(0));

            // At t=100 (interval elapsed) - should_check returns true
            assert!(tracker.should_check(100));
        }

        #[test]
        fn removes_transactions_no_longer_pending_from_snapshot() {
            let mut tracker = PendingStalenessTracker::new(100);
            let tx1 = TxHash::random();
            let tx2 = TxHash::random();

            // First snapshot with both txs at t=0
            tracker.check_and_update([tx1, tx2].into_iter().collect(), 0);
            assert_eq!(tracker.previous_pending.len(), 2);

            // Second snapshot at t=100: only tx1 still pending
            // tx1 was in both -> stale, tx2 not in current -> removed from tracking
            let stale = tracker.check_and_update([tx1].into_iter().collect(), 100);
            assert_eq!(stale.len(), 1);
            assert!(stale.contains(&tx1));

            // Neither should be in the snapshot now
            assert!(tracker.previous_pending.is_empty());
        }
    }
}
