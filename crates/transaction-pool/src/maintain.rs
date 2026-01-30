//! Transaction pool maintenance tasks.

use crate::{
    RevokedKeys, SpendingLimitUpdates, TempoTransactionPool,
    metrics::TempoPoolMaintenanceMetrics,
    paused::{PausedEntry, PausedFeeTokenPool},
    transaction::TempoPooledTransaction,
    tt_2d_pool::AASequenceId,
};
use alloy_consensus::transaction::TxHashRef;
use alloy_primitives::{Address, TxHash};
use alloy_sol_types::SolEvent;
use futures::StreamExt;
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions, Chain};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::Instant,
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks, spec::TEMPO_T1_BASE_FEE};
use tempo_contracts::precompiles::{IAccountKeychain, IFeeManager, ITIP20, ITIP403Registry};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS,
    tip20::is_tip20_prefix,
};
use tempo_primitives::{AASigned, TempoPrimitives};
use tracing::{debug, error};

/// Aggregated block-level invalidation events for the transaction pool.
///
/// Collects all invalidation events from a block into a single structure,
/// allowing efficient batch processing of pool updates.
#[derive(Debug, Default)]
pub struct TempoPoolUpdates {
    /// Transaction hashes that have expired (valid_before <= tip_timestamp).
    pub expired_txs: Vec<TxHash>,
    /// Revoked keychain keys.
    /// Indexed by account for efficient lookup.
    pub revoked_keys: RevokedKeys,
    /// Spending limit changes.
    /// When a spending limit changes, transactions from that key paying with that token
    /// may become unexecutable if the new limit is below their value.
    /// Indexed by account for efficient lookup.
    pub spending_limit_changes: SpendingLimitUpdates,
    /// Validator token preference changes: (validator, new_token).
    pub validator_token_changes: Vec<(Address, Address)>,
    /// TIP403 blacklist additions: (policy_id, account).
    pub blacklist_additions: Vec<(u64, Address)>,
    /// TIP403 whitelist removals: (policy_id, account).
    pub whitelist_removals: Vec<(u64, Address)>,
    /// Fee token pause state changes: (token, is_paused).
    pub pause_events: Vec<(Address, bool)>,
}

impl TempoPoolUpdates {
    /// Creates a new empty `TempoPoolUpdates`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if there are no updates to process.
    pub fn is_empty(&self) -> bool {
        self.expired_txs.is_empty()
            && self.revoked_keys.is_empty()
            && self.spending_limit_changes.is_empty()
            && self.validator_token_changes.is_empty()
            && self.blacklist_additions.is_empty()
            && self.whitelist_removals.is_empty()
            && self.pause_events.is_empty()
    }

    /// Extracts pool updates from a committed chain segment.
    ///
    /// Parses receipts for relevant events (key revocations, validator token changes,
    /// blacklist additions, pause events).
    pub fn from_chain(chain: &Chain<TempoPrimitives>) -> Self {
        let mut updates = Self::new();

        // Parse events from receipts
        for log in chain
            .execution_outcome()
            .receipts()
            .iter()
            .flatten()
            .flat_map(|receipt| &receipt.logs)
        {
            // Key revocations and spending limit changes
            if log.address == ACCOUNT_KEYCHAIN_ADDRESS {
                if let Ok(event) = IAccountKeychain::KeyRevoked::decode_log(log) {
                    updates.revoked_keys.insert(event.account, event.publicKey);
                } else if let Ok(event) = IAccountKeychain::SpendingLimitUpdated::decode_log(log) {
                    updates.spending_limit_changes.insert(
                        event.account,
                        event.publicKey,
                        event.token,
                    );
                }
            }
            // Validator token changes
            else if log.address == TIP_FEE_MANAGER_ADDRESS {
                if let Ok(event) = IFeeManager::ValidatorTokenSet::decode_log(log) {
                    updates
                        .validator_token_changes
                        .push((event.validator, event.token));
                }
            }
            // TIP403 blacklist additions and whitelist removals
            else if log.address == TIP403_REGISTRY_ADDRESS {
                if let Ok(event) = ITIP403Registry::BlacklistUpdated::decode_log(log)
                    && event.restricted
                {
                    updates
                        .blacklist_additions
                        .push((event.policyId, event.account));
                } else if let Ok(event) = ITIP403Registry::WhitelistUpdated::decode_log(log)
                    && !event.allowed
                {
                    updates
                        .whitelist_removals
                        .push((event.policyId, event.account));
                }
            }
            // Fee token pause events
            else if is_tip20_prefix(log.address)
                && let Ok(event) = ITIP20::PauseStateUpdate::decode_log(log)
            {
                updates.pause_events.push((log.address, event.isPaused));
            }
        }

        updates
    }

    /// Returns true if there are any invalidation events that require scanning the pool.
    pub fn has_invalidation_events(&self) -> bool {
        !self.revoked_keys.is_empty()
            || !self.spending_limit_changes.is_empty()
            || !self.validator_token_changes.is_empty()
            || !self.blacklist_additions.is_empty()
            || !self.whitelist_removals.is_empty()
    }
}

/// Tracking state for pool maintenance operations.
///
/// Tracks AA transaction expiry (`valid_before` timestamps) for eviction.
///
/// Note: Stale entries (transactions no longer in the pool) are cleaned up lazily
/// when we check `pool.contains()` before eviction. This avoids the overhead of
/// subscribing to all transaction lifecycle events.
#[derive(Default)]
struct TempoPoolState {
    /// Maps `valid_before` timestamp to transaction hashes that expire at that time.
    expiry_map: BTreeMap<u64, Vec<TxHash>>,
    /// Reverse mapping: tx_hash -> valid_before timestamp (for cleanup during drain).
    tx_to_expiry: HashMap<TxHash, u64>,
    /// Pool for transactions whose fee token is temporarily paused.
    paused_pool: PausedFeeTokenPool,
    /// Tracks pending transaction staleness for DoS mitigation.
    pending_staleness: PendingStalenessTracker,
    /// Tracks whether the T1 transition cleanup has been performed.
    /// This is a one-time operation that removes transactions with max_fee_per_gas < T1 base fee.
    /// Will be removed after T1 is activated on mainnet.
    t1_transition_cleanup_done: bool,
    /// Tracks keychain key expiry timestamps for eviction.
    key_expiry: KeyExpiryTracker,
}

impl TempoPoolState {
    /// Tracks an AA transaction with a `valid_before` timestamp.
    fn track_expiry(&mut self, maybe_aa_tx: Option<&AASigned>) {
        if let Some(aa_tx) = maybe_aa_tx
            && let Some(valid_before) = aa_tx.tx().valid_before
        {
            let hash = *aa_tx.hash();
            self.expiry_map.entry(valid_before).or_default().push(hash);
            self.tx_to_expiry.insert(hash, valid_before);
        }
    }

    /// Collects and removes all expired transactions up to the given timestamp.
    /// Returns the list of expired transaction hashes.
    fn drain_expired(&mut self, tip_timestamp: u64) -> Vec<TxHash> {
        let mut expired = Vec::new();
        while let Some(entry) = self.expiry_map.first_entry()
            && *entry.key() <= tip_timestamp
        {
            let expired_hashes = entry.remove();
            for tx_hash in &expired_hashes {
                self.tx_to_expiry.remove(tx_hash);
            }
            expired.extend(expired_hashes);
        }
        expired
    }

    /// Track a keychain transaction's key expiry for eviction.
    ///
    /// Uses the key expiry cached on the transaction during validation.
    /// Skips if expiry wasn't set (non-keychain tx, key never expires, etc.).
    fn track_key_expiry(&mut self, tx: &TempoPooledTransaction) {
        let Some(expiry) = tx.key_expiry() else {
            return;
        };

        let Some(subject) = tx.keychain_subject() else {
            return;
        };

        self.key_expiry
            .track(subject.account, subject.key_id, expiry, *tx.hash());
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
    previous_pending: HashSet<TxHash>,
    /// Timestamp of the last snapshot.
    last_snapshot_time: Option<u64>,
    /// Interval in seconds between staleness checks.
    interval_secs: u64,
}

impl PendingStalenessTracker {
    /// Creates a new tracker with the given check interval.
    fn new(interval_secs: u64) -> Self {
        Self {
            previous_pending: HashSet::default(),
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
    fn check_and_update(&mut self, current_pending: HashSet<TxHash>, now: u64) -> Vec<TxHash> {
        // Find transactions present in both snapshots (stale)
        let stale: Vec<TxHash> = self
            .previous_pending
            .intersection(&current_pending)
            .copied()
            .collect();

        // Update snapshot: store current pending (excluding stale ones we're about to evict)
        self.previous_pending = current_pending
            .into_iter()
            .filter(|hash| !stale.contains(hash))
            .collect();
        self.last_snapshot_time = Some(now);

        stale
    }
}

impl Default for PendingStalenessTracker {
    fn default() -> Self {
        Self::new(DEFAULT_PENDING_STALENESS_INTERVAL)
    }
}

/// Composite key identifying a keychain key: (account, key_id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct KeyId {
    account: Address,
    key_id: Address,
}

/// Tracks keychain key expiry timestamps for eviction.
///
/// When a keychain-signed transaction enters the pool, we track its (account, key_id)
/// along with the key's expiry timestamp. When a block's timestamp passes the expiry,
/// we evict all transactions using that expired key.
///
/// Note: We don't query state here - the expiry is read once when the transaction
/// enters the pool (during validation) and passed to the tracker.
#[derive(Debug, Default)]
struct KeyExpiryTracker {
    /// Maps expiry timestamp -> set of keys that expire at that time.
    expiry_map: BTreeMap<u64, HashSet<KeyId>>,
    /// Maps KeyId -> (expiry timestamp, set of transaction hashes using this key).
    key_to_txs: HashMap<KeyId, (u64, HashSet<TxHash>)>,
}

impl KeyExpiryTracker {
    /// Track a keychain transaction with its key expiry timestamp.
    ///
    /// Call this when a keychain-signed transaction enters the pool.
    /// The expiry should be read from the AccountKeychain storage during validation.
    fn track(&mut self, account: Address, key_id: Address, expiry: u64, tx_hash: TxHash) {
        let key = KeyId { account, key_id };

        match self.key_to_txs.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let (existing_expiry, txs) = entry.get_mut();
                debug_assert_eq!(
                    *existing_expiry, expiry,
                    "Key expiry changed unexpectedly - this shouldn't happen"
                );
                txs.insert(tx_hash);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert((expiry, [tx_hash].into_iter().collect()));
                self.expiry_map.entry(expiry).or_default().insert(key);
            }
        }
    }

    /// Drain all expired keys and return the transaction hashes that should be evicted.
    ///
    /// Keys with expiry <= tip_timestamp are considered expired.
    fn drain_expired(&mut self, tip_timestamp: u64) -> Vec<TxHash> {
        let mut expired_txs = Vec::new();

        while let Some(entry) = self.expiry_map.first_entry()
            && *entry.key() <= tip_timestamp
        {
            let expired_keys = entry.remove();
            for key in expired_keys {
                if let Some((_, txs)) = self.key_to_txs.remove(&key) {
                    expired_txs.extend(txs);
                }
            }
        }

        expired_txs
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
/// - Moving transactions to/from the paused pool when fee tokens are paused/unpaused
///
/// Consolidates these operations into a single event loop to avoid multiple tasks
/// competing for canonical state updates and to minimize contention on pool locks.
pub async fn maintain_tempo_pool<Client>(pool: TempoTransactionPool<Client>)
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    let mut state = TempoPoolState::default();
    let metrics = TempoPoolMaintenanceMetrics::default();

    // Subscribe to new transactions and chain events
    let mut new_txs = pool.new_transactions_listener();
    let mut chain_events = pool.client().canonical_state_stream();

    // Populate expiry tracking with existing transactions to prevent race conditions at start-up
    let all_txs = pool.all_transactions();
    for tx in all_txs.pending.iter().chain(all_txs.queued.iter()) {
        state.track_expiry(tx.transaction.inner().as_aa());
        state.track_key_expiry(&tx.transaction);
    }

    let amm_cache = pool.amm_liquidity_cache();

    loop {
        tokio::select! {
            // Track new transactions for expiry (valid_before and key expiry)
            tx_event = new_txs.recv() => {
                let Some(tx_event) = tx_event else {
                    break;
                };

                let tx = &tx_event.transaction.transaction;
                state.track_expiry(tx.inner().as_aa());
                state.track_key_expiry(tx);
            }

            // Process all maintenance operations on new block commit or reorg
            Some(event) = chain_events.next() => {
                let new = match event {
                    CanonStateNotification::Reorg { old, new } => {
                        // Handle reorg: identify orphaned AA 2D txs and affected nonce slots
                        let (orphaned_txs, affected_seq_ids) =
                            handle_reorg(old, new.clone(), |hash| pool.contains(hash));

                        // Reset nonce state for affected 2D nonce slots from the new tip's state.
                        // Necessary because state diffs only contain slots that changed in the new chain.
                        if !affected_seq_ids.is_empty() {
                            let new_tip_hash = new.tip().hash();
                            if let Err(err) = pool.reset_2d_nonces_from_state(
                                affected_seq_ids.into_iter().collect(),
                                new_tip_hash,
                            ) {
                                error!(
                                    target: "txpool",
                                    ?err,
                                    "Failed to reset 2D nonce state after reorg"
                                );
                            }
                        }

                        if !orphaned_txs.is_empty() {
                            let count = orphaned_txs.len();
                            debug!(
                                target: "txpool",
                                count,
                                "Re-injecting orphaned AA 2D transactions after reorg"
                            );

                            let pool_clone = pool.clone();
                            tokio::spawn(async move {
                                let results = pool_clone
                                    .add_transactions(TransactionOrigin::Local, orphaned_txs)
                                    .await;
                                let failed = results.iter().filter(|r| r.is_err()).count();
                                if failed > 0 {
                                    debug!(
                                        target: "txpool",
                                        failed,
                                        "Some orphaned AA 2D transactions failed to re-inject"
                                    );
                                }
                            });
                        }

                        // Update nonce state based on the new canonical chain
                        pool.notify_aa_pool_on_state_updates(new.execution_outcome().state().state());
                        continue;
                    }
                    CanonStateNotification::Commit { new } => new,
                };

                let block_update_start = Instant::now();

                let tip = &new;
                let bundle_state = tip.execution_outcome().state().state();
                let tip_timestamp = tip.tip().header().timestamp();

                // T1 transition: one-time cleanup of underpriced transactions.
                // When T1 activates, transactions with max_fee_per_gas < 20 gwei become
                // never-includable and should be evicted. This check runs once per node lifetime.
                // TODO: Remove this after T1 is activated on mainnet.
                if !state.t1_transition_cleanup_done {
                    let chain_spec = pool.client().chain_spec();
                    if chain_spec.is_t1_active_at_timestamp(tip_timestamp) {
                        let evicted = evict_underpriced_transactions_for_t1(&pool);
                        if evicted > 0 {
                            debug!(
                                target: "txpool",
                                count = evicted,
                                tip_timestamp,
                                "T1 transition: evicted underpriced transactions (max_fee_per_gas < 20 gwei)"
                            );
                        }
                        state.t1_transition_cleanup_done = true;
                    }
                }

                // 1. Collect all block-level invalidation events
                let mut updates = TempoPoolUpdates::from_chain(tip);

                // Collect mined transaction hashes separately (not an invalidation event)
                let mined_tx_hashes: Vec<TxHash> = tip
                    .blocks_iter()
                    .flat_map(|block| block.body().transactions())
                    .map(|tx| *tx.tx_hash())
                    .collect();

                // Add expired transactions (from local tracking state)
                let expired = state.drain_expired(tip_timestamp);
                updates.expired_txs = expired.into_iter().filter(|h| pool.contains(h)).collect();

                // Add transactions using expired keychain keys
                let key_expired = state.key_expiry.drain_expired(tip_timestamp);
                let key_expired: Vec<TxHash> =
                    key_expired.into_iter().filter(|h| pool.contains(h)).collect();

                // 2. Evict expired AA transactions (valid_before expiry)
                let expired_start = Instant::now();
                let expired_count = updates.expired_txs.len();
                if expired_count > 0 {
                    debug!(
                        target: "txpool",
                        count = expired_count,
                        tip_timestamp,
                        "Evicting expired AA transactions (valid_before)"
                    );
                    pool.remove_transactions(updates.expired_txs.clone());
                    metrics.expired_transactions_evicted.increment(expired_count as u64);
                }

                // 2b. Evict transactions using expired keychain keys
                let key_expired_count = key_expired.len();
                if key_expired_count > 0 {
                    debug!(
                        target: "txpool",
                        count = key_expired_count,
                        tip_timestamp,
                        "Evicting transactions with expired keychain keys"
                    );
                    pool.remove_transactions(key_expired);
                    metrics.expired_transactions_evicted.increment(key_expired_count as u64);
                }
                metrics.expired_eviction_duration_seconds.record(expired_start.elapsed());

                // 3. Handle fee token pause/unpause events
                let pause_start = Instant::now();

                // Collect pause tokens that need pool scanning.
                // For pause events, we need to scan the pool. For unpause events, we
                // only need to check the paused_pool (O(1) lookup by token).
                let pause_tokens: Vec<Address> = updates
                    .pause_events
                    .iter()
                    .filter_map(|(token, is_paused)| is_paused.then_some(*token))
                    .collect();

                // Process pause events: fetch pool transactions once for all pause tokens.
                // This avoids the O(pause_events * pool_size) cost of fetching per event.
                if !pause_tokens.is_empty() {
                    let all_txs = pool.all_transactions();

                    // Group transactions by fee token for efficient batch processing.
                    // This single pass over all transactions handles all pause events.
                    let mut by_token: HashMap<Address, Vec<TxHash>> = HashMap::new();
                    for tx in all_txs.pending.iter().chain(all_txs.queued.iter()) {
                        if let Some(fee_token) = tx.transaction.inner().fee_token() {
                            by_token.entry(fee_token).or_default().push(*tx.hash());
                        }
                    }

                    // Process each pause token
                    for token in pause_tokens {
                        let Some(hashes_to_pause) = by_token.remove(&token) else {
                            // No transactions use this fee token - skip
                            continue;
                        };

                        let removed_txs = pool.remove_transactions(hashes_to_pause);
                        let count = removed_txs.len();

                        if count > 0 {
                            let entries: Vec<_> = removed_txs
                                .into_iter()
                                .map(|tx| {
                                    let valid_before = tx
                                        .transaction
                                        .inner()
                                        .as_aa()
                                        .and_then(|aa| aa.tx().valid_before);
                                    PausedEntry { tx, valid_before }
                                })
                                .collect();

                            state.paused_pool.insert_batch(token, entries);
                            metrics.transactions_paused.increment(count as u64);
                            debug!(
                                target: "txpool",
                                %token,
                                count,
                                "Moved transactions to paused pool (fee token paused)"
                            );
                        }
                    }
                }

                // Process unpause events: O(1) lookup per token in paused_pool
                for (token, is_paused) in &updates.pause_events {
                    if *is_paused {
                        continue; // Already handled above
                    }

                    // Unpause: drain from paused pool and re-add to main pool
                    let paused_entries = state.paused_pool.drain_token(token);
                    if !paused_entries.is_empty() {
                        let count = paused_entries.len();
                        metrics.transactions_unpaused.increment(count as u64);
                        let pool_clone = pool.clone();
                        let token = *token;
                        tokio::spawn(async move {
                            let txs: Vec<_> = paused_entries
                                .into_iter()
                                .map(|e| e.tx.transaction.clone())
                                .collect();

                            let results = pool_clone
                                .add_external_transactions(txs)
                                .await;

                            let success = results.iter().filter(|r| r.is_ok()).count();
                            debug!(
                                target: "txpool",
                                %token,
                                total = count,
                                success,
                                "Restored transactions from paused pool (fee token unpaused)"
                            );
                        });
                    }
                }

                // 4. Evict expired transactions from the paused pool
                let paused_expired = state.paused_pool.evict_expired(tip_timestamp);
                let paused_timed_out = state.paused_pool.evict_timed_out();
                let total_paused_evicted = paused_expired + paused_timed_out;
                if total_paused_evicted > 0 {
                    debug!(
                        target: "txpool",
                        count = total_paused_evicted,
                        tip_timestamp,
                        "Evicted expired transactions from paused pool"
                    );
                }

                // 5. Evict revoked keys and spending limit updates from paused pool
                if !updates.revoked_keys.is_empty() || !updates.spending_limit_changes.is_empty() {
                    state.paused_pool.evict_invalidated(
                        &updates.revoked_keys,
                        &updates.spending_limit_changes,
                    );
                }
                metrics.pause_events_duration_seconds.record(pause_start.elapsed());

                // 6. Update 2D nonce pool
                let nonce_pool_start = Instant::now();
                pool.notify_aa_pool_on_state_updates(bundle_state);

                // 7. Remove included expiring nonce transactions
                // Expiring nonce txs use tx hash for replay protection rather than sequential nonces,
                // so we need to remove them on inclusion rather than relying on nonce changes.
                pool.remove_included_expiring_nonce_txs(mined_tx_hashes.iter());
                metrics.nonce_pool_update_duration_seconds.record(nonce_pool_start.elapsed());

                // 8. Update AMM liquidity cache (must happen before validator token eviction)
                let amm_start = Instant::now();
                amm_cache.on_new_state(tip.execution_outcome());
                for block in tip.blocks_iter() {
                    if let Err(err) = amm_cache.on_new_block(block.sealed_header(), pool.client()) {
                        error!(target: "txpool", ?err, "AMM liquidity cache update failed");
                    }
                }
                metrics.amm_cache_update_duration_seconds.record(amm_start.elapsed());

                // 9. Evict invalidated transactions in a single pool scan
                // This checks revoked keys, spending limit changes, validator token changes,
                // blacklist additions, and whitelist removals together to avoid scanning
                // all transactions multiple times per block.
                if updates.has_invalidation_events() {
                    let invalidation_start = Instant::now();
                    debug!(
                        target: "txpool",
                        revoked_keys = updates.revoked_keys.len(),
                        spending_limit_changes = updates.spending_limit_changes.len(),
                        validator_token_changes = updates.validator_token_changes.len(),
                        blacklist_additions = updates.blacklist_additions.len(),
                        whitelist_removals = updates.whitelist_removals.len(),
                        "Processing transaction invalidation events"
                    );
                    let evicted = pool.evict_invalidated_transactions(&updates);
                    metrics.transactions_invalidated.increment(evicted as u64);
                    metrics
                        .invalidation_eviction_duration_seconds
                        .record(invalidation_start.elapsed());
                }

                // 10. Evict stale pending transactions (must happen after AA pool promotions in step 6)
                // Only runs once per interval (~30 min) to avoid overhead on every block.
                // Transactions pending across two consecutive snapshots are considered stale.
                if state.pending_staleness.should_check(tip_timestamp) {
                    let current_pending: HashSet<TxHash> =
                        pool.pending_transactions().iter().map(|tx| *tx.hash()).collect();
                    let stale_to_evict =
                        state.pending_staleness.check_and_update(current_pending, tip_timestamp);

                    if !stale_to_evict.is_empty() {
                        debug!(
                            target: "txpool",
                            count = stale_to_evict.len(),
                            tip_timestamp,
                            "Evicting stale pending transactions"
                        );
                        pool.remove_transactions(stale_to_evict);
                    }
                }

                // Record total block update duration
                metrics.block_update_duration_seconds.record(block_update_start.elapsed());
            }
        }
    }
}

/// Removes transactions with max_fee_per_gas below the T1 base fee from the pool.
///
/// This is a one-time cleanup performed when the T0 → T1 hardfork transition is detected.
/// After T1 activation, transactions with max_fee_per_gas < 20 gwei are never includable
/// and should be evicted from the pool.
///
/// # Note
/// This function is temporary and will be removed after T1 is activated on mainnet.
fn evict_underpriced_transactions_for_t1<Pool>(pool: &Pool) -> usize
where
    Pool: TransactionPool,
{
    let all_txs = pool.all_transactions();
    let t1_base_fee = TEMPO_T1_BASE_FEE as u128;

    let underpriced_hashes: Vec<TxHash> = all_txs
        .pending
        .iter()
        .chain(all_txs.queued.iter())
        .filter(|tx| tx.max_fee_per_gas() < t1_base_fee)
        .map(|tx| *tx.hash())
        .collect();

    let count = underpriced_hashes.len();
    if count > 0 {
        pool.remove_transactions(underpriced_hashes);
    }

    count
}

/// Handles a reorg event by identifying orphaned AA 2D transactions from the old chain
/// that are not in the new chain.
///
/// Returns:
/// - Orphaned transactions to re-inject
/// - Affected sequence IDs whose nonce state needs to be reset from the new tip's state
pub fn handle_reorg<F>(
    old_chain: Arc<Chain<TempoPrimitives>>,
    new_chain: Arc<Chain<TempoPrimitives>>,
    is_in_pool: F,
) -> (Vec<TempoPooledTransaction>, HashSet<AASequenceId>)
where
    F: Fn(&TxHash) -> bool,
{
    // Get inner chain blocks for iteration
    let (new_blocks, _) = new_chain.inner();
    let (old_blocks, _) = old_chain.inner();

    // Collect transaction hashes from the new chain to identify what's still mined
    let new_mined_hashes: HashSet<TxHash> = new_blocks.transaction_hashes().collect();

    let mut orphaned_txs = Vec::new();
    let mut affected_seq_ids = HashSet::new();

    // Find AA 2D transactions from the old chain that are NOT in the new chain
    for tx in old_blocks.transactions_ecrecovered() {
        // Skip if transaction is in the new chain
        if new_mined_hashes.contains(tx.tx_hash()) {
            continue;
        }

        let Some(aa_tx) = tx.as_aa() else {
            continue;
        };

        // Only process 2D nonce transactions (nonce_key > 0)
        if aa_tx.tx().nonce_key.is_zero() {
            continue;
        }

        let seq_id = AASequenceId::new(tx.signer(), aa_tx.tx().nonce_key);

        // Track all affected sequence IDs for nonce reset. We reset all orphaned seq_ids
        // because tx presence in the new chain doesn't guarantee the nonce slot was modified.
        affected_seq_ids.insert(seq_id);

        let pooled_tx = TempoPooledTransaction::new(tx);
        if is_in_pool(pooled_tx.hash()) {
            continue;
        }

        orphaned_txs.push(pooled_tx);
    }

    (orphaned_txs, affected_seq_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TxBuilder;
    use alloy_primitives::{Address, TxHash, U256};
    use reth_primitives_traits::RecoveredBlock;
    use reth_transaction_pool::PoolTransaction;
    use std::collections::HashSet;
    use tempo_primitives::{Block, BlockBody, TempoHeader, TempoTxEnvelope};

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

    mod key_expiry_tracker_tests {
        use super::*;

        #[test]
        fn tracks_single_key_single_tx() {
            let mut tracker = KeyExpiryTracker::default();
            let account = Address::random();
            let key_id = Address::random();
            let tx_hash = TxHash::random();
            let expiry = 1000;

            tracker.track(account, key_id, expiry, tx_hash);

            // Key should be tracked
            let key = KeyId { account, key_id };
            assert!(tracker.key_to_txs.contains_key(&key));
            assert!(tracker.expiry_map.contains_key(&expiry));
        }

        #[test]
        fn tracks_multiple_txs_for_same_key() {
            let mut tracker = KeyExpiryTracker::default();
            let account = Address::random();
            let key_id = Address::random();
            let expiry = 1000;
            let tx1 = TxHash::random();
            let tx2 = TxHash::random();

            tracker.track(account, key_id, expiry, tx1);
            tracker.track(account, key_id, expiry, tx2);

            let key = KeyId { account, key_id };
            let (_, txs) = tracker.key_to_txs.get(&key).unwrap();
            assert_eq!(txs.len(), 2);
            assert!(txs.contains(&tx1));
            assert!(txs.contains(&tx2));
        }

        #[test]
        fn drain_expired_returns_txs_for_expired_keys() {
            let mut tracker = KeyExpiryTracker::default();
            let account = Address::random();
            let key_id = Address::random();
            let tx1 = TxHash::random();
            let tx2 = TxHash::random();

            // Key expires at t=1000
            tracker.track(account, key_id, 1000, tx1);
            tracker.track(account, key_id, 1000, tx2);

            // At t=999, nothing should be expired
            let expired = tracker.drain_expired(999);
            assert!(expired.is_empty());

            // At t=1000, the key and both txs should be expired
            let expired = tracker.drain_expired(1000);
            assert_eq!(expired.len(), 2);
            assert!(expired.contains(&tx1));
            assert!(expired.contains(&tx2));

            // Tracker should be empty now
            assert!(tracker.key_to_txs.is_empty());
            assert!(tracker.expiry_map.is_empty());
        }

        #[test]
        fn drain_expired_handles_multiple_keys_with_different_expiries() {
            let mut tracker = KeyExpiryTracker::default();
            let account = Address::random();
            let key1 = Address::random();
            let key2 = Address::random();
            let tx1 = TxHash::random();
            let tx2 = TxHash::random();

            // Key1 expires at t=1000, key2 expires at t=2000
            tracker.track(account, key1, 1000, tx1);
            tracker.track(account, key2, 2000, tx2);

            // At t=1500, only key1's tx should be expired
            let expired = tracker.drain_expired(1500);
            assert_eq!(expired.len(), 1);
            assert!(expired.contains(&tx1));

            // At t=2000, key2's tx should be expired
            let expired = tracker.drain_expired(2000);
            assert_eq!(expired.len(), 1);
            assert!(expired.contains(&tx2));
        }
    }

    fn create_test_chain(
        blocks: Vec<reth_primitives_traits::RecoveredBlock<Block>>,
    ) -> Arc<Chain<TempoPrimitives>> {
        use reth_provider::{Chain, ExecutionOutcome};

        Arc::new(Chain::new(
            blocks,
            ExecutionOutcome::default(),
            Default::default(),
            Default::default(),
        ))
    }

    /// Helper to create a recovered block containing the given transactions.
    fn create_block_with_txs(
        block_number: u64,
        transactions: Vec<TempoTxEnvelope>,
        senders: Vec<Address>,
    ) -> RecoveredBlock<Block> {
        let header = TempoHeader {
            inner: alloy_consensus::Header {
                number: block_number,
                ..Default::default()
            },
            ..Default::default()
        };
        let body = BlockBody {
            transactions,
            ..Default::default()
        };
        let block = Block::new(header, body);
        RecoveredBlock::new_unhashed(block, senders)
    }

    /// Helper to extract a TempoTxEnvelope from a TempoPooledTransaction.
    fn extract_envelope(tx: &crate::transaction::TempoPooledTransaction) -> TempoTxEnvelope {
        tx.inner().clone().into_inner()
    }

    /// Tests all reorg handling scenarios:
    /// 1. AA 2D tx orphaned in reorg -> should be re-injected
    /// 2. AA tx with nonce_key=0 -> should NOT be re-injected (handled by vanilla pool)
    /// 3. EIP-1559 tx -> should NOT be re-injected (not AA)
    /// 4. AA 2D tx in both old and new chain -> should NOT be re-injected
    /// 5. AA 2D tx already in pool -> should NOT be re-injected
    /// 6. All orphaned 2D seq_ids should be in affected_seq_ids (for nonce reset)
    #[test]
    fn handle_reorg_correctly_identifies_orphaned_aa_2d_transactions() {
        let sender_2d = Address::random();

        // AA 2D tx that will be orphaned (should be re-injected)
        let tx_2d_orphaned = TxBuilder::aa(sender_2d).nonce_key(U256::from(1)).build();
        let hash_2d_orphaned = *tx_2d_orphaned.hash();
        let envelope_2d_orphaned = extract_envelope(&tx_2d_orphaned);

        // AA 2D tx that will be re-included in new chain (should NOT be re-injected)
        let tx_2d_reincluded = TxBuilder::aa(sender_2d).nonce_key(U256::from(2)).build();
        let envelope_2d_reincluded = extract_envelope(&tx_2d_reincluded);

        // AA 2D tx that's already in the pool (should NOT be re-injected)
        let tx_2d_in_pool = TxBuilder::aa(sender_2d).nonce_key(U256::from(3)).build();
        let hash_2d_in_pool = *tx_2d_in_pool.hash();
        let envelope_2d_in_pool = extract_envelope(&tx_2d_in_pool);

        // AA tx with nonce_key=0 (should NOT be re-injected - vanilla pool handles it)
        let tx_non_2d = TxBuilder::aa(sender_2d).nonce_key(U256::ZERO).build();
        let envelope_non_2d = extract_envelope(&tx_non_2d);

        // EIP-1559 tx (should NOT be re-injected - not AA)
        let tx_eip1559 = TxBuilder::eip1559(Address::random()).build();
        let envelope_eip1559 = extract_envelope(&tx_eip1559);

        // Create old chain with all 5 transactions
        let old_block = create_block_with_txs(
            1,
            vec![
                envelope_2d_orphaned,
                envelope_2d_reincluded.clone(),
                envelope_2d_in_pool,
                envelope_non_2d,
                envelope_eip1559,
            ],
            vec![sender_2d; 5],
        );
        let old_chain = create_test_chain(vec![old_block]);

        // Create new chain with only the re-included tx
        let new_block = create_block_with_txs(1, vec![envelope_2d_reincluded], vec![sender_2d]);
        let new_chain = create_test_chain(vec![new_block]);

        // Simulate pool containing the "already in pool" tx
        let pool_hashes: HashSet<TxHash> = [hash_2d_in_pool].into_iter().collect();

        // Execute handle_reorg
        let (orphaned, affected_seq_ids) =
            handle_reorg(old_chain, new_chain, |hash| pool_hashes.contains(hash));

        // Verify: Only the orphaned AA 2D tx should be returned (not in-pool, not re-included)
        assert_eq!(
            orphaned.len(),
            1,
            "Expected exactly 1 orphaned tx, got {}",
            orphaned.len()
        );
        assert_eq!(
            *orphaned[0].hash(),
            hash_2d_orphaned,
            "Wrong transaction was identified as orphaned"
        );

        // Verify: affected_seq_ids should contain ALL orphaned 2D seq_ids (nonce_key=1 and nonce_key=3).
        // Note: nonce_key=2 is NOT orphaned (it's in the new chain), so it's not in affected_seq_ids.
        assert_eq!(
            affected_seq_ids.len(),
            2,
            "Expected 2 affected seq_ids, got {}",
            affected_seq_ids.len()
        );
        assert!(
            affected_seq_ids.contains(&AASequenceId::new(sender_2d, U256::from(1))),
            "Should contain orphaned tx's seq_id (nonce_key=1)"
        );
        assert!(
            affected_seq_ids.contains(&AASequenceId::new(sender_2d, U256::from(3))),
            "Should contain in-pool tx's seq_id (nonce_key=3)"
        );
        // nonce_key=2 is NOT orphaned (tx is in new chain), so it won't be in affected_seq_ids
        assert!(
            !affected_seq_ids.contains(&AASequenceId::new(sender_2d, U256::from(2))),
            "Should NOT contain re-included tx's seq_id (nonce_key=2) - tx is in new chain"
        );
    }
}
