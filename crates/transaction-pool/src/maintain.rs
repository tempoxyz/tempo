//! Transaction pool maintenance tasks.

use crate::TempoTransactionPool;
use alloy_consensus::transaction::TxHashRef;
use alloy_primitives::{Address, TxHash};
use alloy_sol_types::SolEvent;
use futures::StreamExt;
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::TransactionPool;
use std::collections::{BTreeMap, HashMap};
use tempo_chainspec::TempoChainSpec;
use tempo_contracts::precompiles::{IAccountKeychain, IFeeManager, ITIP20};
use tempo_precompiles::{ACCOUNT_KEYCHAIN_ADDRESS, TIP_FEE_MANAGER_ADDRESS, tip20::is_tip20_prefix};
use tempo_primitives::{AASigned, TempoPrimitives};
use tracing::{debug, error};

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

    // Subscribe to new transactions and chain events
    let mut new_txs = pool.new_transactions_listener();
    let mut chain_events = pool.client().canonical_state_stream();

    // Populate expiry tracking with existing transactions to prevent race conditions at start-up
    pool.all_transactions().all().for_each(|tx| {
        state.track_expiry(tx.inner().as_aa());
    });

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

            // Process all maintenance operations on new block commit
            Some(event) = chain_events.next() => {
                let CanonStateNotification::Commit { new } = event else {
                    continue;
                };

                let tip = &new;
                let bundle_state = tip.execution_outcome().state().state();

                // 1. Evict expired AA transactions (filter to only those still in pool)
                let tip_timestamp = tip.tip().header().timestamp();
                let expired = state.drain_expired(tip_timestamp);
                let to_remove: Vec<_> =
                    expired.into_iter().filter(|h| pool.contains(h)).collect();

                if !to_remove.is_empty() {
                    debug!(
                        target: "txpool",
                        count = to_remove.len(),
                        tip_timestamp,
                        "Evicting expired AA transactions"
                    );
                    pool.remove_transactions(to_remove);
                }

                // 2. Collect invalidation events from this block
                // Key revocations are rare, so we scan the pool on-demand rather than
                // tracking all keychain-signed transactions.
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

                // Validator token changes - transactions may fail if there's insufficient
                // liquidity in the new (user_token, validator_token) AMM pool.
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

                if !revoked_keys.is_empty() {
                    debug!(
                        target: "txpool",
                        count = revoked_keys.len(),
                        "Processing keychain key revocations"
                    );
                    pool.evict_transactions_by_revoked_keys(&revoked_keys);
                    pool.evict_paused_by_revoked_keys(&revoked_keys);
                }

                // 3. Handle fee token pause/unpause events
                // Collect PauseStateUpdate events from TIP20 tokens
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
                        let count = pool.pause_fee_token(token);
                        if count > 0 {
                            debug!(
                                target: "txpool",
                                %token,
                                count,
                                "Moved transactions to paused pool (fee token paused)"
                            );
                        }
                    } else {
                        let count = pool.unpause_fee_token(token).await;
                        if count > 0 {
                            debug!(
                                target: "txpool",
                                %token,
                                count,
                                "Restored transactions from paused pool (fee token unpaused)"
                            );
                        }
                    }
                }

                // 4. Evict expired transactions from the paused pool
                let paused_expired = pool.evict_expired_paused(tip_timestamp);
                if paused_expired > 0 {
                    debug!(
                        target: "txpool",
                        count = paused_expired,
                        tip_timestamp,
                        "Evicted expired transactions from paused pool"
                    );
                }

                // 5. Update 2D nonce pool
                pool.notify_aa_pool_on_state_updates(bundle_state);

                // 6. Remove included expiring nonce transactions
                // Expiring nonce txs use tx hash for replay protection rather than sequential nonces,
                // so we need to remove them on inclusion rather than relying on nonce changes.
                let mined_tx_hashes: Vec<_> = tip
                    .blocks_iter()
                    .flat_map(|block| block.body().transactions())
                    .map(|tx| *tx.tx_hash())
                    .collect();
                pool.remove_included_expiring_nonce_txs(mined_tx_hashes.iter());

                // 7. Update AMM liquidity cache (must happen before validator token eviction)
                amm_cache.on_new_state(tip.execution_outcome());
                for block in tip.blocks_iter() {
                    if let Err(err) = amm_cache.on_new_block(block.sealed_header(), pool.client()) {
                        error!(target: "txpool", ?err, "AMM liquidity cache update failed");
                    }
                }

                // 8. Evict invalidated transactions for validator token changes
                if !validator_token_changes.is_empty() {
                    debug!(
                        target: "txpool",
                        validator_token_changes = validator_token_changes.len(),
                        "Processing validator token change events"
                    );
                    pool.evict_invalidated_transactions(&[], &validator_token_changes);
                }
            }
        }
    }
}
