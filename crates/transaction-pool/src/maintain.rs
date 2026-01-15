//! Transaction pool maintenance tasks.

use crate::TempoTransactionPool;
use alloy_primitives::{Address, TxHash};
use alloy_sol_types::SolEvent;
use futures::StreamExt;
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{FullTransactionEvent, TransactionPool};
use std::collections::{BTreeMap, HashMap, HashSet};
use tempo_chainspec::TempoChainSpec;
use tempo_contracts::precompiles::IAccountKeychain;
use tempo_precompiles::ACCOUNT_KEYCHAIN_ADDRESS;
use tempo_primitives::{AASigned, TempoPrimitives};
use tracing::{debug, error};

/// A key identifying a keychain-signed transaction: (account, key_id).
type KeychainKey = (Address, Address);

/// Tracking state for pool maintenance operations.
///
/// Groups the data structures needed to track:
/// - AA transaction expiry (`valid_before` timestamps)
/// - Keychain-signed transactions (for revocation eviction)
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

    /// Removes a transaction from all tracking maps.
    fn remove_tx(&mut self, tx_hash: &TxHash) {
        self.remove_from_keychain_tracking(tx_hash);
        self.remove_from_expiry_tracking(tx_hash);
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
    let mut new_txs = pool.new_transactions_listener();
    let mut tx_events = pool.all_transactions_event_listener();
    let mut chain_events = pool.client().canonical_state_stream();

    // Populate tracking maps with existing transactions to prevent race conditions at start-up
    pool.all_transactions().all().for_each(|tx| {
        let maybe_aa = tx.inner().as_aa();
        state.track_expiry(maybe_aa);
        if let Some(aa_tx) = maybe_aa {
            let tx_hash = *aa_tx.hash();
            state.track_keychain_tx(Some(aa_tx), tx_hash);
        }
    });

    let amm_cache = pool.amm_liquidity_cache();

    loop {
        tokio::select! {
            // Track new transactions for expiry and keychain revocation
            tx_event = new_txs.recv() => {
                let Some(tx_event) = tx_event else {
                    break;
                };

                let tx = &tx_event.transaction.transaction;
                let tx_hash = *tx_event.transaction.hash();
                let maybe_aa = tx.inner().as_aa();

                state.track_expiry(maybe_aa);
                state.track_keychain_tx(maybe_aa, tx_hash);
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

            // Process all maintenance operations on new block commit
            Some(event) = chain_events.next() => {
                let CanonStateNotification::Commit { new } = event else {
                    continue;
                };

                let tip = &new;
                #[cfg(feature = "test-utils")]
                let tip_number = tip.tip().header().number();

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

                // 3. Remove all collected transactions in a single batch
                if !to_remove.is_empty() {
                    pool.remove_transactions(to_remove);
                }

                // 4. Update 2D nonce pool
                pool.notify_aa_pool_on_state_updates(bundle_state);

                // 5. Update AMM liquidity cache
                amm_cache.on_new_state(tip.execution_outcome());
                for block in tip.blocks_iter() {
                    if let Err(err) = amm_cache.on_new_block(block.sealed_header(), pool.client()) {
                        error!(target: "txpool", ?err, "AMM liquidity cache update failed");
                    }
                }

                // Signal that we have processed this tip (for test synchronization)
                #[cfg(feature = "test-utils")]
                pool.mark_maintenance_processed_tip(tip_number);
            }
        }
    }
}
