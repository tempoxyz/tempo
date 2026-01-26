//! Transaction pool maintenance tasks.

use crate::{
    TempoTransactionPool,
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
use tempo_chainspec::TempoChainSpec;
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
    /// Revoked keychain keys: (account, public_key).
    pub revoked_keys: Vec<(Address, Address)>,
    /// Spending limit changes: (account, public_key, token).
    /// When a spending limit changes, transactions from that key paying with that token
    /// may become unexecutable if the new limit is below their value.
    pub spending_limit_changes: Vec<(Address, Address, Address)>,
    /// Validator token preference changes: (validator, new_token).
    pub validator_token_changes: Vec<(Address, Address)>,
    /// TIP403 blacklist additions: (policy_id, account).
    pub blacklist_additions: Vec<(u64, Address)>,
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
                    updates.revoked_keys.push((event.account, event.publicKey));
                } else if let Ok(event) = IAccountKeychain::SpendingLimitUpdated::decode_log(log) {
                    updates.spending_limit_changes.push((
                        event.account,
                        event.publicKey,
                        event.token,
                    ));
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
            // TIP403 blacklist additions
            else if log.address == TIP403_REGISTRY_ADDRESS {
                if let Ok(event) = ITIP403Registry::BlacklistUpdated::decode_log(log)
                    && event.restricted
                {
                    updates
                        .blacklist_additions
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
}

/// Unified maintenance task for the Tempo transaction pool.
///
/// Handles:
/// - Evicting expired AA transactions (`valid_before <= tip_timestamp`)
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
    }

    let amm_cache = pool.amm_liquidity_cache();

    loop {
        tokio::select! {
            // Track new transactions for expiry
            tx_event = new_txs.recv() => {
                let Some(tx_event) = tx_event else {
                    break;
                };

                let tx = &tx_event.transaction.transaction;
                state.track_expiry(tx.inner().as_aa());
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

                // 2. Evict expired AA transactions
                let expired_start = Instant::now();
                let expired_count = updates.expired_txs.len();
                if expired_count > 0 {
                    debug!(
                        target: "txpool",
                        count = expired_count,
                        tip_timestamp,
                        "Evicting expired AA transactions"
                    );
                    pool.remove_transactions(updates.expired_txs.clone());
                    metrics.expired_transactions_evicted.increment(expired_count as u64);
                }
                metrics.expired_eviction_duration_seconds.record(expired_start.elapsed());

                // 3. Handle fee token pause/unpause events
                let pause_start = Instant::now();
                for (token, is_paused) in &updates.pause_events {
                    if *is_paused {
                        // Pause: remove from main pool and store in paused pool
                        let all_txs = pool.all_transactions();
                        let hashes_to_pause: Vec<_> = all_txs
                            .pending
                            .iter()
                            .chain(all_txs.queued.iter())
                            .filter_map(|tx| {
                                tx.transaction.inner().fee_token().filter(|t| t == token).map(|_| {
                                    *tx.hash()
                                })
                            })
                            .collect();

                        if !hashes_to_pause.is_empty() {
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

                                state.paused_pool.insert_batch(*token, entries);
                                metrics.transactions_paused.increment(count as u64);
                                debug!(
                                    target: "txpool",
                                    %token,
                                    count,
                                    "Moved transactions to paused pool (fee token paused)"
                                );
                            }
                        }
                    } else {
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
                // and blacklist additions together to avoid scanning all transactions
                // multiple times per block.
                if updates.has_invalidation_events() {
                    let invalidation_start = Instant::now();
                    debug!(
                        target: "txpool",
                        revoked_keys = updates.revoked_keys.len(),
                        spending_limit_changes = updates.spending_limit_changes.len(),
                        validator_token_changes = updates.validator_token_changes.len(),
                        blacklist_additions = updates.blacklist_additions.len(),
                        "Processing transaction invalidation events"
                    );
                    let evicted = pool.evict_invalidated_transactions(&updates);
                    metrics.transactions_invalidated.increment(evicted as u64);
                    metrics
                        .invalidation_eviction_duration_seconds
                        .record(invalidation_start.elapsed());
                }

                // Record total block update duration
                metrics.block_update_duration_seconds.record(block_update_start.elapsed());
            }
        }
    }
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
