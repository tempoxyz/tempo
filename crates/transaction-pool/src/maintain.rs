//! Transaction pool maintenance tasks.

use crate::{
    RevokedKeys, SpendingLimitUpdates, TempoTransactionPool,
    metrics::TempoPoolMaintenanceMetrics,
    paused::{PausedEntry, PausedFeeTokenPool},
    transaction::TempoPooledTransaction,
};
use alloy_consensus::transaction::TxHashRef;
use alloy_primitives::{
    Address, TxHash,
    map::{AddressMap, HashMap, HashSet},
};
use alloy_sol_types::SolEvent;
use futures::StreamExt;
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions, Chain, HeaderProvider};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    time::Instant,
};
use tempo_chainspec::TempoChainSpec;
use tempo_contracts::precompiles::{IAccountKeychain, IFeeManager, ITIP20, ITIP403Registry};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS,
    tip20::is_tip20_prefix,
};
use tempo_primitives::{TempoHeader, TempoPrimitives};
use tracing::{debug, error};

/// Evict transactions this many seconds before they expire to reduce propagation
/// of near-expiry transactions that are likely to fail validation on peers.
const EVICTION_BUFFER_SECS: u64 = 3;

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
    /// Validator token preference changes: validator to new_token (last-write-wins).
    /// Uses `AddressMap` to deduplicate by validator, preventing resource amplification
    /// when a validator emits multiple `ValidatorTokenSet` events in the same block.
    pub validator_token_changes: AddressMap<Address>,
    /// User token preference changes.
    /// When a user changes their fee token preference via `setUserToken()`, pending
    /// transactions from that user that don't have an explicit fee_token set may now
    /// resolve to a different token at execution time, causing fee payment failures.
    /// Uses a set since a user can emit multiple events in the same block; we only need to
    /// process each user once. No cleanup needed as this is ephemeral per-block data.
    pub user_token_changes: HashSet<Address>,
    /// TIP403 blacklist additions: (policy_id, account).
    pub blacklist_additions: Vec<(u64, Address)>,
    /// TIP403 whitelist removals: (policy_id, account).
    pub whitelist_removals: Vec<(u64, Address)>,
    /// Fee token pause state changes: (token, is_paused).
    pub pause_events: Vec<(Address, bool)>,
    /// Tokens whose transfer policy was changed via `changeTransferPolicyId()`.
    /// Pending transactions using these tokens as fee tokens need to be re-validated
    /// because the new policy may forbid the fee payer or fee manager.
    pub transfer_policy_updates: HashSet<Address>,
    /// Fee token balance changes keyed by token.
    ///
    /// We only track the debited `from` account from TIP20 `Transfer` logs because credits to the
    /// `to` account cannot make an already-admitted transaction newly invalid.
    pub fee_balance_changes: AddressMap<HashSet<Address>>,
    /// Keychain transactions that were included in the block, decrementing spending limits.
    ///
    /// We record which (account, key_id, fee_token) combos had their limits decremented by
    /// included txs. During eviction, we re-read the remaining limit from state for these
    /// combos and compare against pending tx costs. This is needed because the pool only
    /// monitors `SpendingLimitUpdated` events (from `update_spending_limit()`), but doesn't
    /// account for actual spends (from `verify_and_update_spending()` during execution).
    pub spending_limit_spends: SpendingLimitUpdates,
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
            && self.user_token_changes.is_empty()
            && self.blacklist_additions.is_empty()
            && self.whitelist_removals.is_empty()
            && self.pause_events.is_empty()
            && self.transfer_policy_updates.is_empty()
            && self.fee_balance_changes.is_empty()
            && self.spending_limit_spends.is_empty()
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
                        Some(event.token),
                    );
                }
            }
            // Validator and user token changes
            else if log.address == TIP_FEE_MANAGER_ADDRESS {
                if let Ok(event) = IFeeManager::ValidatorTokenSet::decode_log(log) {
                    updates
                        .validator_token_changes
                        .insert(event.validator, event.token);
                } else if let Ok(event) = IFeeManager::UserTokenSet::decode_log(log) {
                    updates.user_token_changes.insert(event.user);
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
            // Fee token pause events and balance changes
            else if is_tip20_prefix(log.address) {
                if let Ok(event) = ITIP20::PauseStateUpdate::decode_log(log) {
                    updates.pause_events.push((log.address, event.isPaused));
                } else if ITIP20::TransferPolicyUpdate::decode_log(log).is_ok() {
                    updates.transfer_policy_updates.insert(log.address);
                } else if let Ok(event) = ITIP20::Transfer::decode_log(log) {
                    updates
                        .fee_balance_changes
                        .entry(log.address)
                        .or_default()
                        .insert(event.from);
                }
            }
        }

        // Extract (account, key_id, fee_token) from included keychain transactions.
        // When these txs execute, verify_and_update_spending() decrements spending limits,
        // but no SpendingLimitUpdated event is emitted. We record which combos were affected
        // so the pool can re-read the remaining limit from state and evict over-limit txs.
        for tx in chain
            .blocks_iter()
            .flat_map(|block| block.body().transactions())
        {
            let Some(aa_tx) = tx.as_aa() else {
                continue;
            };
            let Some(keychain_sig) = aa_tx.signature().as_keychain() else {
                continue;
            };
            let Ok(key_id) = keychain_sig.key_id(&aa_tx.signature_hash()) else {
                continue;
            };
            // Skip main keys (key_id == Address::ZERO) - they don't have spending limits
            if key_id.is_zero() {
                continue;
            }
            // Always wildcard the token: a mined tx paying fees in token Y can also
            // decrement token X's spending limit via transfer/approve.
            // `None` wildcards the token in `SpendingLimitUpdates::contains`, so every
            // pending tx for this (account, key_id) is re-checked regardless of fee token.
            // Safe because eviction is still gated on `exceeds_spending_limit()` which
            // reads the actual remaining limit from state.
            updates
                .spending_limit_spends
                .insert(keychain_sig.user_address, key_id, None);
        }

        updates
    }

    /// Returns true if there are any invalidation events that require scanning the pool.
    pub fn has_invalidation_events(&self) -> bool {
        !self.revoked_keys.is_empty()
            || !self.spending_limit_changes.is_empty()
            || !self.spending_limit_spends.is_empty()
            || !self.validator_token_changes.is_empty()
            || !self.user_token_changes.is_empty()
            || !self.blacklist_additions.is_empty()
            || !self.whitelist_removals.is_empty()
            || !self.fee_balance_changes.is_empty()
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
    /// Maps timestamp to transactions that are going to be invalidated at that time (due to `valid_after` or keychain-related expiry).
    expiry_map: BTreeMap<u64, Vec<TxHash>>,
    /// Reverse mapping: tx_hash -> valid_before timestamp (for cleanup during drain).
    tx_to_expiry: HashMap<TxHash, u64>,
    /// Pool for transactions whose fee token is temporarily paused.
    paused_pool: PausedFeeTokenPool,
    /// Tracks pending transaction staleness for DoS mitigation.
    pending_staleness: PendingStalenessTracker,
}

impl TempoPoolState {
    /// Tracks an AA transaction with a `valid_before` timestamp.
    fn track(&mut self, tx: &TempoPooledTransaction) {
        let valid_before = tx.inner().as_aa().and_then(|tx| tx.tx().valid_before);
        let key_expiry = tx.key_expiry();

        let expiry = [valid_before, key_expiry].into_iter().flatten().min();

        if let Some(expiry) = expiry {
            self.expiry_map.entry(expiry).or_default().push(*tx.hash());
            self.tx_to_expiry.insert(*tx.hash(), expiry);
        }
    }

    /// Removes expiry and key-expiry tracking for a single transaction.
    fn untrack(&mut self, hash: &TxHash) {
        if let Some(expiry) = self.tx_to_expiry.remove(hash)
            && let Entry::Occupied(mut entry) = self.expiry_map.entry(expiry)
        {
            entry.get_mut().retain(|h| *h != *hash);
            if entry.get().is_empty() {
                entry.remove();
            }
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
        + HeaderProvider<Header = TempoHeader>
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
        state.track(&tx.transaction);
    }

    let amm_cache = pool.amm_liquidity_cache();

    loop {
        tokio::select! {
            // Track new transactions for expiry (valid_before and key expiry)
            tx_event = new_txs.recv() => {
                let Some(tx_event) = tx_event else {
                    break;
                };

                state.track(&tx_event.transaction.transaction);
            }

            // Process all maintenance operations on new block commit or reorg
            Some(event) = chain_events.next() => {
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
                let bundle_state = tip.execution_outcome().state().state();
                let tip_timestamp = tip.tip().header().timestamp();

                // 1. Collect all block-level invalidation events
                let mut updates = TempoPoolUpdates::from_chain(tip);

                // Remove expiry tracking for mined transactions.
                tip.blocks_iter()
                    .flat_map(|block| block.body().transactions())
                    .for_each(|tx| {
                    state.untrack(tx.tx_hash())
                });

                // Evict transactions slightly before they expire to prevent
                // broadcasting near-expiry txs that peers would reject.
                let max_expiry = tip_timestamp.saturating_add(EVICTION_BUFFER_SECS);

                // Add expired transactions (from local tracking state)
                let expired = state.drain_expired(max_expiry);
                updates.expired_txs = expired.into_iter().filter(|h| pool.contains(h)).collect();

                // 2. Evict expired AA transactions
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
                    let mut by_token: AddressMap<Vec<TxHash>> = AddressMap::default();
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
                            // Clean up expiry tracking for paused txs
                            for tx in &removed_txs {
                                state.untrack(tx.hash());
                            }

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

                            let cap_evicted = state.paused_pool.insert_batch(token, entries);
                            metrics.transactions_paused.increment(count as u64);
                            if cap_evicted > 0 {
                                metrics.paused_pool_cap_evicted.increment(cap_evicted as u64);
                                debug!(
                                    target: "txpool",
                                    cap_evicted,
                                    "Evicted oldest paused transactions due to global cap"
                                );
                            }
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
                if !updates.revoked_keys.is_empty()
                    || !updates.spending_limit_changes.is_empty()
                    || !updates.spending_limit_spends.is_empty()
                {
                    state.paused_pool.evict_invalidated(
                        &updates.revoked_keys,
                        &updates.spending_limit_changes,
                        &updates.spending_limit_spends,
                    );
                }
                metrics.pause_events_duration_seconds.record(pause_start.elapsed());

                // 5b. Handle transfer policy updates
                // When a token's transfer policy changes, pending transactions using that
                // token may become invalid under the new policy. We remove them and re-add
                // so they go through full validation against the updated policy.
                if !updates.transfer_policy_updates.is_empty() {
                    let all_txs = pool.all_transactions();
                    let hashes: Vec<TxHash> = all_txs
                        .pending
                        .iter()
                        .chain(all_txs.queued.iter())
                        .filter(|tx| {
                            tx.transaction
                                .resolved_fee_token()
                                .is_some_and(|t| updates.transfer_policy_updates.contains(&t))
                        })
                        .map(|tx| *tx.hash())
                        .collect();

                    if !hashes.is_empty() {
                        let removed_txs = pool.remove_transactions(hashes);
                        let count = removed_txs.len();

                        for tx in &removed_txs {
                            state.untrack(tx.hash());
                        }

                        metrics
                            .transfer_policy_revalidated
                            .increment(count as u64);

                        let pool_clone = pool.clone();
                        tokio::spawn(async move {
                            let txs: Vec<_> = removed_txs
                                .into_iter()
                                .map(|tx| (tx.origin, tx.transaction.clone()))
                                .collect();

                            let results =
                                pool_clone.add_transactions_with_origins(txs).await;

                            let success =
                                results.iter().filter(|r| r.is_ok()).count();
                            debug!(
                                target: "txpool",
                                total = count,
                                success,
                                "Re-validated transactions after transfer policy update"
                            );
                        });
                    }
                }

                // 6. Update 2D nonce pool (also removes included expiring nonce txs
                // via slot changes on the nonce precompile)
                let nonce_pool_start = Instant::now();
                pool.notify_aa_pool_on_state_updates(bundle_state);
                metrics.nonce_pool_update_duration_seconds.record(nonce_pool_start.elapsed());

                // 7. Update AMM liquidity cache (must happen before validator token eviction)
                let amm_start = Instant::now();
                amm_cache.on_new_state(tip.execution_outcome());
                if let Err(err) = amm_cache.on_new_blocks(tip.blocks_iter().map(|block| block.sealed_header()), pool.client()) {
                    error!(target: "txpool", ?err, "AMM liquidity cache update failed");
                }
                metrics.amm_cache_update_duration_seconds.record(amm_start.elapsed());

                // 8. Evict invalidated transactions in a single pool scan
                // This checks revoked keys, spending limit changes, validator token changes,
                // blacklist additions, and whitelist removals together to avoid scanning
                // all transactions multiple times per block.
                if updates.has_invalidation_events() {
                    let invalidation_start = Instant::now();
                    debug!(
                        target: "txpool",
                        revoked_keys = updates.revoked_keys.len(),
                        spending_limit_changes = updates.spending_limit_changes.len(),
                        spending_limit_spends = updates.spending_limit_spends.len(),
                        validator_token_changes = updates.validator_token_changes.len(),
                        user_token_changes = updates.user_token_changes.len(),
                        blacklist_additions = updates.blacklist_additions.len(),
                        whitelist_removals = updates.whitelist_removals.len(),
                        "Processing transaction invalidation events"
                    );
                    let evicted = pool.evict_invalidated_transactions(&updates);
                    for hash in &evicted {
                        state.untrack(hash);
                    }
                    metrics.transactions_invalidated.increment(evicted.len() as u64);
                    metrics
                        .invalidation_eviction_duration_seconds
                        .record(invalidation_start.elapsed());
                }

                // 9. Evict stale pending transactions (must happen after AA pool promotions in step 6)
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
                        // Clean up expiry tracking for stale txs to prevent orphaned entries
                        for hash in &stale_to_evict {
                            state.untrack(hash);
                        }
                        pool.remove_transactions(stale_to_evict);
                    }
                }

                // Record total block update duration
                metrics.block_update_duration_seconds.record(block_update_start.elapsed());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TxBuilder;
    use alloy_primitives::{Address, TxHash};
    use reth_primitives_traits::RecoveredBlock;
    use std::sync::Arc;
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

    #[test]
    fn test_remove_mined() {
        let mut state = TempoPoolState::default();
        let hash_a = TxHash::random();
        let hash_b = TxHash::random();
        let hash_unknown = TxHash::random();

        // Track two txs at the same valid_before
        state.expiry_map.entry(1000).or_default().push(hash_a);
        state.tx_to_expiry.insert(hash_a, 1000);
        state.expiry_map.entry(1000).or_default().push(hash_b);
        state.tx_to_expiry.insert(hash_b, 1000);

        // Mine hash_a and an unknown hash
        state.untrack(&hash_a);
        state.untrack(&hash_unknown);

        // hash_a removed from both maps
        assert!(!state.tx_to_expiry.contains_key(&hash_a));
        assert_eq!(state.expiry_map[&1000], vec![hash_b]);

        // Mine hash_b should remove the expiry_map entry entirely
        state.untrack(&hash_b);
        assert!(!state.tx_to_expiry.contains_key(&hash_b));
        assert!(!state.expiry_map.contains_key(&1000));
    }

    fn create_test_chain(
        blocks: Vec<reth_primitives_traits::RecoveredBlock<Block>>,
    ) -> Arc<Chain<TempoPrimitives>> {
        use reth_provider::{Chain, ExecutionOutcome};

        Arc::new(Chain::new(
            blocks,
            ExecutionOutcome::default(),
            Default::default(),
        ))
    }

    fn create_test_chain_with_receipts(
        blocks: Vec<reth_primitives_traits::RecoveredBlock<Block>>,
        receipts: Vec<Vec<tempo_primitives::TempoReceipt>>,
    ) -> Arc<Chain<TempoPrimitives>> {
        use reth_provider::{Chain, ExecutionOutcome};

        Arc::new(Chain::new(
            blocks,
            ExecutionOutcome {
                receipts,
                ..Default::default()
            },
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

    mod from_chain_spending_limit_spends {
        use super::*;
        use alloy_primitives::{IntoLogData, Log, U256};
        use alloy_signer_local::PrivateKeySigner;
        use tempo_primitives::{TempoReceipt, TempoTxType};

        /// Verify from_chain extracts (account, key_id) with wildcard token from included
        /// keychain txs, so all pending txs for that key are rechecked regardless of fee token.
        #[test]
        fn extracts_keychain_tx_spending_limit_spends() {
            let user_address = Address::random();
            let access_key_signer = PrivateKeySigner::random();
            let key_id = access_key_signer.address();
            let fee_token = Address::random();

            let keychain_tx = TxBuilder::aa(user_address)
                .fee_token(fee_token)
                .build_keychain(user_address, &access_key_signer);
            let envelope = extract_envelope(&keychain_tx);

            let block = create_block_with_txs(1, vec![envelope], vec![user_address]);
            let chain = create_test_chain(vec![block]);

            let updates = TempoPoolUpdates::from_chain(&chain);

            // Wildcard: matches both the original fee token and any other token
            assert!(
                updates
                    .spending_limit_spends
                    .contains(user_address, key_id, fee_token),
                "Should match the keychain tx's fee token"
            );
            assert!(
                updates
                    .spending_limit_spends
                    .contains(user_address, key_id, Address::random()),
                "Should match any other token (wildcard)"
            );
            assert_eq!(updates.spending_limit_spends.len(), 1);
        }

        /// Non-keychain AA txs should NOT produce spending limit spends.
        #[test]
        fn ignores_non_keychain_aa_transactions() {
            let sender = Address::random();
            let tx = TxBuilder::aa(sender).fee_token(Address::random()).build();
            let envelope = extract_envelope(&tx);

            let block = create_block_with_txs(1, vec![envelope], vec![sender]);
            let chain = create_test_chain(vec![block]);

            let updates = TempoPoolUpdates::from_chain(&chain);
            assert!(updates.spending_limit_spends.is_empty());
        }

        /// EIP-1559 txs should NOT produce spending limit spends.
        #[test]
        fn ignores_eip1559_transactions() {
            let sender = Address::random();
            let tx = TxBuilder::eip1559(Address::random()).build_eip1559();
            let envelope = extract_envelope(&tx);

            let block = create_block_with_txs(1, vec![envelope], vec![sender]);
            let chain = create_test_chain(vec![block]);

            let updates = TempoPoolUpdates::from_chain(&chain);
            assert!(updates.spending_limit_spends.is_empty());
        }

        /// When a keychain tx has no explicit fee_token, it is stored as a wildcard.
        #[test]
        fn uses_wildcard_fee_token_when_none_set() {
            let user_address = Address::random();
            let access_key_signer = PrivateKeySigner::random();
            let key_id = access_key_signer.address();

            // Build keychain tx without explicit fee_token
            let keychain_tx =
                TxBuilder::aa(user_address).build_keychain(user_address, &access_key_signer);
            let envelope = extract_envelope(&keychain_tx);

            let block = create_block_with_txs(1, vec![envelope], vec![user_address]);
            let chain = create_test_chain(vec![block]);

            let updates = TempoPoolUpdates::from_chain(&chain);

            // Wildcard should match any token
            assert!(updates.spending_limit_spends.contains(
                user_address,
                key_id,
                Address::random(),
            ));
        }

        /// When a keychain tx has an explicit fee_token, spending_limit_spends should
        /// still use a wildcard so pending txs with ANY fee token are rechecked.
        /// This prevents the case where a mined tx pays fees in token Y but also
        /// spends token X's limit via transfer/approve, leaving pending txs paying
        /// in token X unrechecked.
        #[test]
        fn always_wildcards_fee_token_for_cross_token_recheck() {
            let user_address = Address::random();
            let access_key_signer = PrivateKeySigner::random();
            let key_id = access_key_signer.address();
            let fee_token_y = Address::random();
            let fee_token_x = Address::random();

            let keychain_tx = TxBuilder::aa(user_address)
                .fee_token(fee_token_y)
                .build_keychain(user_address, &access_key_signer);
            let envelope = extract_envelope(&keychain_tx);

            let block = create_block_with_txs(1, vec![envelope], vec![user_address]);
            let chain = create_test_chain(vec![block]);

            let updates = TempoPoolUpdates::from_chain(&chain);

            // Must match ANY fee token (wildcard), not just the included tx's fee token
            assert!(
                updates
                    .spending_limit_spends
                    .contains(user_address, key_id, fee_token_x),
                "spending_limit_spends should wildcard fee_token to catch cross-token limit spends"
            );
            assert!(
                updates
                    .spending_limit_spends
                    .contains(user_address, key_id, fee_token_y),
                "spending_limit_spends should also match the original fee token"
            );
        }

        /// has_invalidation_events returns true when spending_limit_spends is non-empty.
        #[test]
        fn has_invalidation_events_includes_spending_limit_spends() {
            let mut updates = TempoPoolUpdates::new();
            assert!(!updates.has_invalidation_events());

            updates.spending_limit_spends.insert(
                Address::random(),
                Address::random(),
                Some(Address::random()),
            );
            assert!(updates.has_invalidation_events());
        }

        #[test]
        fn extracts_fee_balance_changes_from_tip20_transfer_logs() {
            let fee_token = tempo_precompiles::PATH_USD_ADDRESS;
            let from = Address::random();
            let to = Address::random();
            let amount = U256::from(42_u64);
            let log_data = ITIP20::Transfer { from, to, amount }.into_log_data();
            let log =
                Log::new_unchecked(fee_token, log_data.topics().to_vec(), log_data.data.clone());
            let receipt = TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 21_000,
                logs: vec![log],
            };

            let block = create_block_with_txs(1, vec![], vec![]);
            let chain = create_test_chain_with_receipts(vec![block], vec![vec![receipt]]);
            let updates = TempoPoolUpdates::from_chain(&chain);

            assert!(
                updates
                    .fee_balance_changes
                    .get(&fee_token)
                    .is_some_and(|accounts| accounts.len() == 1 && accounts.contains(&from)),
                "TIP20 transfer logs should only mark the debited sender as balance-changed"
            );
            assert!(updates.has_invalidation_events());
        }

        /// TransferPolicyUpdate events are parsed from TIP20 token logs.
        #[test]
        fn extracts_transfer_policy_updates() {
            let fee_token = tempo_precompiles::PATH_USD_ADDRESS;
            let updater = Address::random();
            let new_policy_id = 42u64;
            let log_data = ITIP20::TransferPolicyUpdate {
                updater,
                newPolicyId: new_policy_id,
            }
            .into_log_data();
            let log =
                Log::new_unchecked(fee_token, log_data.topics().to_vec(), log_data.data.clone());
            let receipt = TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 21_000,
                logs: vec![log],
            };

            let block = create_block_with_txs(1, vec![], vec![]);
            let chain = create_test_chain_with_receipts(vec![block], vec![vec![receipt]]);
            let updates = TempoPoolUpdates::from_chain(&chain);

            assert!(
                updates.transfer_policy_updates.contains(&fee_token),
                "TransferPolicyUpdate should be tracked by token address"
            );
        }

        /// Duplicate TransferPolicyUpdate events for the same token are deduplicated.
        #[test]
        fn transfer_policy_updates_deduplicates_by_token() {
            let fee_token = tempo_precompiles::PATH_USD_ADDRESS;

            let log_data_1 = ITIP20::TransferPolicyUpdate {
                updater: Address::random(),
                newPolicyId: 1,
            }
            .into_log_data();
            let log_data_2 = ITIP20::TransferPolicyUpdate {
                updater: Address::random(),
                newPolicyId: 2,
            }
            .into_log_data();
            let log1 = Log::new_unchecked(
                fee_token,
                log_data_1.topics().to_vec(),
                log_data_1.data.clone(),
            );
            let log2 = Log::new_unchecked(
                fee_token,
                log_data_2.topics().to_vec(),
                log_data_2.data.clone(),
            );
            let receipt = TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 21_000,
                logs: vec![log1, log2],
            };

            let block = create_block_with_txs(1, vec![], vec![]);
            let chain = create_test_chain_with_receipts(vec![block], vec![vec![receipt]]);
            let updates = TempoPoolUpdates::from_chain(&chain);

            assert_eq!(
                updates.transfer_policy_updates.len(),
                1,
                "duplicate policy updates for the same token should be deduplicated"
            );
        }

        /// Duplicate validator token changes must be deduplicated (last-write-wins).
        #[test]
        fn validator_token_changes_deduplicates_by_validator() {
            let validator = Address::random();
            let token_a = Address::random();
            let token_b = Address::random();

            let mut updates = TempoPoolUpdates::new();
            updates.validator_token_changes.insert(validator, token_a);
            updates.validator_token_changes.insert(validator, token_b);

            assert_eq!(
                updates.validator_token_changes.len(),
                1,
                "duplicate validator entries must be deduplicated"
            );
            assert_eq!(
                updates.validator_token_changes.get(&validator).copied(),
                Some(token_b),
                "last-write-wins: second token should overwrite the first"
            );
        }
    }
}
