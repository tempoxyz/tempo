//! Transaction pool maintenance tasks.

use crate::{
    TempoTransactionPool,
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
use reth_transaction_pool::{
    FullTransactionEvent, PoolTransaction, TransactionListenerKind, TransactionOrigin,
    TransactionPool,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};
use tempo_chainspec::TempoChainSpec;
use tempo_contracts::precompiles::{IAccountKeychain, IFeeManager, ITIP20, ITIP403Registry};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS,
    tip20::is_tip20_prefix,
};
use tempo_primitives::{AASigned, TempoPrimitives, TempoTxEnvelope};
use tracing::{debug, error};

/// A key identifying a keychain-signed transaction: (account, key_id).
type KeychainKey = (Address, Address);

/// Tracking state for pool maintenance operations.
///
/// Groups the data structures needed to track:
/// - AA transaction expiry (`valid_before` timestamps)
/// - Keychain-signed transactions (for revocation eviction)
/// - Fee payer transactions (for blacklist eviction)
/// - Paused fee token transactions
#[derive(Default)]
struct MaintenanceState {
    /// Maps `valid_before` timestamp to transaction hashes that expire at that time.
    expiry_map: BTreeMap<u64, Vec<TxHash>>,
    /// Reverse mapping: tx_hash -> valid_before timestamp (for cleanup).
    tx_to_expiry: HashMap<TxHash, u64>,
    /// Maps (account, key_id) to the set of transaction hashes using that key.
    keychain_txs: HashMap<KeychainKey, HashSet<TxHash>>,
    /// Reverse mapping: tx_hash -> (account, key_id) (for cleanup when tx is removed).
    tx_to_key: HashMap<TxHash, KeychainKey>,
    /// Maps fee payer address to the set of transaction hashes they are paying for.
    fee_payer_txs: HashMap<Address, HashSet<TxHash>>,
    /// Reverse mapping: tx_hash -> fee payer address (for cleanup when tx is removed).
    tx_to_fee_payer: HashMap<TxHash, Address>,
    /// Pool for transactions whose fee token is temporarily paused.
    paused_pool: PausedFeeTokenPool,
}

impl MaintenanceState {
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

    /// Tracks a keychain-signed transaction for revocation eviction.
    fn track_keychain_tx(&mut self, maybe_aa_tx: Option<&AASigned>, tx_hash: TxHash) {
        let Some(aa_tx) = maybe_aa_tx else {
            return;
        };

        let Some(keychain_sig) = aa_tx.signature().as_keychain() else {
            return;
        };

        let Ok(key_id) = keychain_sig.key_id(&aa_tx.signature_hash()) else {
            return;
        };

        let account = keychain_sig.user_address;
        let key = (account, key_id);

        self.keychain_txs.entry(key).or_default().insert(tx_hash);
        self.tx_to_key.insert(tx_hash, key);
    }

    /// Tracks the fee payer for a transaction.
    fn track_fee_payer(&mut self, tx: &TempoTxEnvelope, sender: Address, tx_hash: TxHash) {
        let fee_payer = tx.fee_payer(sender).unwrap_or(sender);
        self.fee_payer_txs
            .entry(fee_payer)
            .or_default()
            .insert(tx_hash);
        self.tx_to_fee_payer.insert(tx_hash, fee_payer);
    }

    /// Removes a transaction from keychain tracking maps.
    fn remove_from_keychain_tracking(&mut self, tx_hash: &TxHash) {
        if let Some(key) = self.tx_to_key.remove(tx_hash)
            && let Some(hashes) = self.keychain_txs.get_mut(&key)
        {
            hashes.remove(tx_hash);
            if hashes.is_empty() {
                self.keychain_txs.remove(&key);
            }
        }
    }

    /// Removes a transaction from expiry tracking maps.
    fn remove_from_expiry_tracking(&mut self, tx_hash: &TxHash) {
        if let Some(valid_before) = self.tx_to_expiry.remove(tx_hash)
            && let Some(hashes) = self.expiry_map.get_mut(&valid_before)
        {
            hashes.retain(|h| h != tx_hash);
            if hashes.is_empty() {
                self.expiry_map.remove(&valid_before);
            }
        }
    }

    /// Removes a transaction from fee payer tracking maps.
    fn remove_from_fee_payer_tracking(&mut self, tx_hash: &TxHash) {
        if let Some(fee_payer) = self.tx_to_fee_payer.remove(tx_hash)
            && let Some(hashes) = self.fee_payer_txs.get_mut(&fee_payer)
        {
            hashes.remove(tx_hash);
            if hashes.is_empty() {
                self.fee_payer_txs.remove(&fee_payer);
            }
        }
    }

    /// Removes a transaction from all tracking maps.
    fn remove_tx(&mut self, tx_hash: &TxHash) {
        self.remove_from_keychain_tracking(tx_hash);
        self.remove_from_expiry_tracking(tx_hash);
        self.remove_from_fee_payer_tracking(tx_hash);
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

    /// Finds all transactions using a specific keychain key.
    fn txs_for_key(&self, account: Address, key_id: Address) -> Option<&HashSet<TxHash>> {
        self.keychain_txs.get(&(account, key_id))
    }

    /// Finds all transactions for a specific fee payer.
    fn txs_for_fee_payer(&self, fee_payer: Address) -> Option<&HashSet<TxHash>> {
        self.fee_payer_txs.get(&fee_payer)
    }
}

/// A unified maintenance task for the Tempo transaction pool.
///
/// This task consolidates multiple pool maintenance operations into a single event loop
/// to avoid multiple tasks competing for the same canonical state updates:
///
/// - **Expired AA transactions**: Evicts transactions when `valid_before <= tip_timestamp`
/// - **2D nonce pool**: Updates the AA 2D nonce pool based on `NonceManager` state changes
/// - **AMM liquidity cache**: Updates the AMM liquidity cache from `FeeManager` state changes
/// - **Revoked keychain keys**: Evicts transactions signed with revoked keychain keys
/// - **Blacklisted fee payers**: Evicts transactions when fee payer is added to a TIP403 blacklist
///
/// By batching these operations, we can process all updates with a single state subscription
/// and minimize contention on pool locks.
pub async fn maintain_tempo_pool<Client>(pool: TempoTransactionPool<Client>)
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    let mut state = MaintenanceState::default();

    // Small delay to allow other tasks to initialize (skip in tests)
    #[cfg(not(feature = "test-utils"))]
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Subscribe to new transactions, transaction events, and chain events
    // Use TransactionListenerKind::All to receive ALL new transactions,
    // including those with valid_after in the future (not yet propagate-able)
    let mut new_txs = pool.new_transactions_listener_for(TransactionListenerKind::All);
    let mut tx_events = pool.all_transactions_event_listener();
    let mut chain_events = pool.client().canonical_state_stream();

    // Populate tracking maps with existing transactions to prevent race conditions at start-up
    // pool.all_transactions().all() returns an iterator of Recovered<TempoTxEnvelope>
    pool.all_transactions().all().for_each(|tx| {
        let maybe_aa = tx.as_aa();
        let tx_hash = *tx.tx_hash();
        let sender = tx.signer();
        state.track_expiry(maybe_aa);
        state.track_keychain_tx(maybe_aa, tx_hash);
        state.track_fee_payer(tx.inner(), sender, tx_hash);
    });

    let amm_cache = pool.amm_liquidity_cache();

    loop {
        tokio::select! {
            // Track new transactions for expiry, keychain revocation, and fee payer blacklisting
            tx_event = new_txs.recv() => {
                let Some(tx_event) = tx_event else {
                    break;
                };

                // tx_event.transaction is Arc<ValidPoolTransaction<TempoPooledTransaction>>
                // .transaction gives TempoPooledTransaction, .inner() gives &Recovered<TempoTxEnvelope>
                let recovered = tx_event.transaction.transaction.inner();
                let tx_hash = *tx_event.transaction.hash();
                let sender = tx_event.transaction.sender();
                let maybe_aa = recovered.as_aa();

                state.track_expiry(maybe_aa);
                state.track_keychain_tx(maybe_aa, tx_hash);
                state.track_fee_payer(recovered.inner(), sender, tx_hash);
            }

            // Clean up tracking maps when transactions are removed from the pool
            Some(event) = tx_events.next() => {
                let tx_hash = match event {
                    FullTransactionEvent::Mined { tx_hash, .. }
                    | FullTransactionEvent::Discarded(tx_hash)
                    | FullTransactionEvent::Invalid(tx_hash) => tx_hash,
                    FullTransactionEvent::Replaced { transaction, .. } => *transaction.hash(),
                    // Pending/Queued/Propagated don't indicate removal
                    _ => continue,
                };
                state.remove_tx(&tx_hash);
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

                let tip = &new;
                #[cfg(feature = "test-utils")]
                let tip_number = tip.tip().header().number();

                debug!(
                    target: "txpool",
                    tip_number,
                    receipts_count = tip.execution_outcome().receipts().iter().flatten().count(),
                    "Processing chain commit event"
                );

                let bundle_state = tip.execution_outcome().state().state();

                // 1. Evict expired AA transactions
                let tip_timestamp = tip.tip().header().timestamp();
                let mut to_remove = state.drain_expired(tip_timestamp);

                if !to_remove.is_empty() {
                    debug!(
                        target: "txpool",
                        count = to_remove.len(),
                        tip_timestamp,
                        "Evicting expired AA transactions"
                    );
                }

                // 2. Evict transactions with revoked keychain keys by scanning for KeyRevoked events
                let mut revoked_txs = Vec::new();

                for receipts in tip.execution_outcome().receipts().iter() {
                    for receipt in receipts {
                        for log in &receipt.logs {
                            if log.address != ACCOUNT_KEYCHAIN_ADDRESS {
                                continue;
                            }

                            if let Ok(event) = IAccountKeychain::KeyRevoked::decode_log(log)
                                && let Some(tx_hashes) = state.txs_for_key(event.account, event.publicKey)
                            {
                                revoked_txs.extend(tx_hashes.iter().copied());
                            }
                        }
                    }
                }

                if !revoked_txs.is_empty() {
                    debug!(
                        target: "txpool",
                        count = revoked_txs.len(),
                        "Evicting AA transactions with revoked keychain keys"
                    );
                    for tx_hash in &revoked_txs {
                        state.remove_from_keychain_tracking(tx_hash);
                    }
                    to_remove.extend(revoked_txs);
                }

                // 3. Evict transactions where fee payer was added to a blacklist
                let mut blacklisted_txs = Vec::new();

                for receipts in tip.execution_outcome().receipts().iter() {
                    for receipt in receipts {
                        for log in &receipt.logs {
                            debug!(
                                target: "txpool",
                                log_address = ?log.address,
                                expected_address = ?TIP403_REGISTRY_ADDRESS,
                                matches = (log.address == TIP403_REGISTRY_ADDRESS),
                                "Checking log address"
                            );
                            if log.address != TIP403_REGISTRY_ADDRESS {
                                continue;
                            }

                            debug!(
                                target: "txpool",
                                address = ?log.address,
                                topics = ?log.topics(),
                                "Found TIP403 Registry log"
                            );

                            if let Ok(event) = ITIP403Registry::BlacklistUpdated::decode_log(log) {
                                debug!(
                                    target: "txpool",
                                    account = ?event.account,
                                    restricted = event.restricted,
                                    policy_id = event.policyId,
                                    "Decoded BlacklistUpdated event"
                                );
                                if event.restricted {
                                    if let Some(tx_hashes) = state.txs_for_fee_payer(event.account) {
                                        debug!(
                                            target: "txpool",
                                            count = tx_hashes.len(),
                                            account = ?event.account,
                                            "Found transactions to evict for blacklisted fee payer"
                                        );
                                        blacklisted_txs.extend(tx_hashes.iter().copied());
                                    } else {
                                        debug!(
                                            target: "txpool",
                                            account = ?event.account,
                                            "No transactions found for blacklisted fee payer"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                if !blacklisted_txs.is_empty() {
                    debug!(
                        target: "txpool",
                        count = blacklisted_txs.len(),
                        "Evicting transactions with blacklisted fee payers"
                    );
                    for tx_hash in &blacklisted_txs {
                        state.remove_from_fee_payer_tracking(tx_hash);
                    }
                    to_remove.extend(blacklisted_txs);
                }

                // 4. Handle fee token pause/unpause events
                let pause_events: Vec<(Address, bool)> = tip
                    .execution_outcome()
                    .receipts()
                    .iter()
                    .flatten()
                    .flat_map(|receipt| &receipt.logs)
                    .filter(|log| is_tip20_prefix(log.address))
                    .filter_map(|log| {
                        ITIP20::PauseStateUpdate::decode_log(log)
                            .ok()
                            .map(|event| (log.address, event.isPaused))
                    })
                    .collect();

                for (token, is_paused) in pause_events {
                    if is_paused {
                        // Pause: remove from main pool and store in paused pool
                        let all_txs = pool.all_transactions();
                        let hashes_to_pause: Vec<_> = all_txs
                            .pending
                            .iter()
                            .chain(all_txs.queued.iter())
                            .filter_map(|tx| {
                                tx.transaction.inner().fee_token().filter(|&t| t == token).map(|_| {
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

                                state.paused_pool.insert_batch(token, entries);
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
                        let paused_entries = state.paused_pool.drain_token(&token);
                        if !paused_entries.is_empty() {
                            let count = paused_entries.len();
                            let pool_clone = pool.clone();
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

                // 5. Evict expired transactions from the paused pool
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

                // 6. Remove all collected transactions in a single batch
                if !to_remove.is_empty() {
                    pool.remove_transactions(to_remove);
                }

                // 7. Update 2D nonce pool
                pool.notify_aa_pool_on_state_updates(bundle_state);

                // 8. Remove included expiring nonce transactions
                let mined_tx_hashes: Vec<_> = tip
                    .blocks_iter()
                    .flat_map(|block| block.body().transactions())
                    .map(|tx| *tx.tx_hash())
                    .collect();
                pool.remove_included_expiring_nonce_txs(mined_tx_hashes.iter());

                // 9. Update AMM liquidity cache (must happen before validator token eviction)
                amm_cache.on_new_state(tip.execution_outcome());
                for block in tip.blocks_iter() {
                    if let Err(err) = amm_cache.on_new_block(block.sealed_header(), pool.client()) {
                        error!(target: "txpool", ?err, "AMM liquidity cache update failed");
                    }
                }

                // 10. Collect and process validator token changes
                let revoked_keys: Vec<_> = tip
                    .execution_outcome()
                    .receipts()
                    .iter()
                    .flatten()
                    .flat_map(|receipt| &receipt.logs)
                    .filter(|log| log.address == ACCOUNT_KEYCHAIN_ADDRESS)
                    .filter_map(|log| IAccountKeychain::KeyRevoked::decode_log(log).ok())
                    .map(|event| (event.account, event.publicKey))
                    .collect();

                let validator_token_changes: Vec<(Address, Address)> = tip
                    .execution_outcome()
                    .receipts()
                    .iter()
                    .flatten()
                    .flat_map(|receipt| &receipt.logs)
                    .filter(|log| log.address == TIP_FEE_MANAGER_ADDRESS)
                    .filter_map(|log| IFeeManager::ValidatorTokenSet::decode_log(log).ok())
                    .map(|event| (event.validator, event.token))
                    .collect();

                // Evict revoked keys from paused pool
                if !revoked_keys.is_empty() {
                    state.paused_pool.evict_by_revoked_keys(&revoked_keys);
                }

                // Evict transactions affected by validator token changes
                if !revoked_keys.is_empty() || !validator_token_changes.is_empty() {
                    debug!(
                        target: "txpool",
                        revoked_keys = revoked_keys.len(),
                        validator_token_changes = validator_token_changes.len(),
                        "Processing transaction invalidation events"
                    );
                    pool.evict_invalidated_transactions(&revoked_keys, &validator_token_changes);
                }

                // Signal that we have processed this tip (for test synchronization)
                #[cfg(feature = "test-utils")]
                pool.mark_maintenance_processed_tip(tip_number);
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
