//! Transaction pool maintenance tasks.

use crate::TempoTransactionPool;
use alloy_primitives::TxHash;
use alloy_sol_types::SolEvent;
use futures::StreamExt;
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::TransactionPool;
use std::collections::{BTreeMap, HashMap};
use tempo_chainspec::TempoChainSpec;
use tempo_contracts::precompiles::IAccountKeychain;
use tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS;
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

                // 2. Evict transactions with revoked keychain keys
                // Key revocations are rare, so we scan the pool on-demand rather than
                // tracking all keychain-signed transactions.
                for receipts in tip.execution_outcome().receipts().iter() {
                    for receipt in receipts {
                        for log in &receipt.logs {
                            if log.address != ACCOUNT_KEYCHAIN_ADDRESS {
                                continue;
                            }

                            if let Ok(event) = IAccountKeychain::KeyRevoked::decode_log(log) {
                                debug!(
                                    target: "txpool",
                                    account = %event.account,
                                    key_id = %event.publicKey,
                                    "Processing keychain key revocation"
                                );
                                pool.evict_transactions_by_revoked_key(event.account, event.publicKey);
                            }
                        }
                    }
                }

                // 3. Update 2D nonce pool
                pool.notify_aa_pool_on_state_updates(bundle_state);

                // 4. Update AMM liquidity cache
                amm_cache.on_new_state(tip.execution_outcome());
                for block in tip.blocks_iter() {
                    if let Err(err) = amm_cache.on_new_block(block.sealed_header(), pool.client()) {
                        error!(target: "txpool", ?err, "AMM liquidity cache update failed");
                    }
                }
            }
        }
    }
}
