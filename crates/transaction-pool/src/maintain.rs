//! Transaction pool maintenance tasks.

use crate::{TempoTransactionPool, transaction::TempoPooledTransaction};
use alloy_primitives::{Address, TxHash, U256};
use futures::StreamExt;
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::TransactionPool;
use std::collections::{BTreeMap, HashMap, HashSet};
use tempo_chainspec::TempoChainSpec;
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    account_keychain::{AccountKeychain, AuthorizedKey},
};
use tempo_primitives::{AASigned, TempoPrimitives};
use tracing::{debug, error};

/// Spawns a background task that evicts expired AA transactions.
///
/// - Listens for new blocks to get chain timestamp
/// - Listens for new transactions to track `valid_before` timestamps
/// - Evicts transactions when `valid_before <= tip_timestamp`
pub async fn evict_expired_aa_txs<P, C>(pool: P, client: C)
where
    P: TransactionPool<Transaction = TempoPooledTransaction> + 'static,
    C: CanonStateSubscriptions + 'static,
{
    // Helper to track AA transactions with `valid_before` timestamps
    let track_expiry = |map: &mut BTreeMap<u64, Vec<TxHash>>, maybe_aa_tx: Option<&AASigned>| {
        if let Some(aa_tx) = maybe_aa_tx
            && let Some(valid_before) = aa_tx.tx().valid_before
        {
            let hash = *aa_tx.hash();
            map.entry(valid_before).or_default().push(hash);
        }
    };

    // Track valid_before timestamp -> Vec<TxHash>
    let mut expiry_map: BTreeMap<u64, Vec<TxHash>> = BTreeMap::new();

    // Small delay to allow backup tasks to initialize
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Subscribe to new transactions and blocks
    let mut new_txs = pool.new_transactions_listener();
    let mut chain_events = client.canonical_state_stream();

    // Populate expiry map to prevent race condition at start-up
    pool.all_transactions()
        .all()
        .for_each(|tx| track_expiry(&mut expiry_map, tx.inner().as_aa()));

    loop {
        tokio::select! {
            // Update cache when a txs are added to the mempool
            tx_event = new_txs.recv() => {
                let Some(tx_event) = tx_event else {
                    break;
                };

                // Check if it's an AA tx with `valid_before`
                let tx = &tx_event.transaction.transaction;
                track_expiry(&mut expiry_map, tx.inner().as_aa());
            }

            // Check for expired txs when a new block is committed
            Some(event) = chain_events.next() => {
                let CanonStateNotification::Commit { new } = event else {
                    continue;
                };

                let tip_timestamp = new.tip().header().timestamp();

                // Gather expired tx hashes and evict them
                let mut to_remove = Vec::new();
                while let Some(entry) = expiry_map.first_entry() && *entry.key() <= tip_timestamp {
                    to_remove.extend(entry.remove());
                }

                if !to_remove.is_empty() {
                    debug!(
                        target: "txpool",
                        count = to_remove.len(),
                        tip_timestamp,
                        "Evicting expired AA transactions"
                    );
                    // Note: txs already mined or evicted by other means are ignored
                    pool.remove_transactions(to_remove);
                }
            }
        }
    }
}

/// An endless future that maintains the [`TempoTransactionPool`] 2d nonce pool based on the storage changes of the `NonceManager` precompile.
///
/// The `NonceManager` contains
///
/// ```solidity
///  mapping(address => mapping(uint256 => uint64)) public nonces
/// ```
///
/// where each slot tracks the current nonce for a nonce key assigned to the transaction.
/// The next executable nonce is the current value of in the contract's state.
pub async fn maintain_2d_nonce_pool<Client>(pool: TempoTransactionPool<Client>)
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    let mut events = pool.client().canonical_state_stream();
    while let Some(notification) = events.next().await {
        pool.notify_aa_pool_on_state_updates(
            notification.committed().execution_outcome().state().state(),
        );
    }
}

/// An endless future that updates the [`crate::amm::AmmLiquidityCache`] based
/// on the storage changes of the `FeeManager` precompile.
pub async fn maintain_amm_cache<Client>(pool: TempoTransactionPool<Client>)
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    let amm_cache = pool.amm_liquidity_cache();
    let mut events = pool.client().canonical_state_stream();

    while let Some(notification) = events.next().await {
        let tip = notification.committed();

        amm_cache.on_new_state(tip.execution_outcome());
        for block in tip.blocks_iter() {
            if let Err(err) = amm_cache.on_new_block(block.sealed_header(), pool.client()) {
                error!(target: "txpool", ?err, "AMM liquidity cache update failed");
            }
        }
    }
}

/// An endless future that evicts AA transactions signed with revoked keychain keys.
///
/// This task monitors storage changes to the `AccountKeychain` precompile and evicts
/// transactions when their authorizing access key is revoked. This prevents DoS attacks
/// where transactions signed with later-revoked keys could clog the mempool.
///
/// The task:
/// - Tracks keychain-signed transactions by their key slot (user_address, key_id)
/// - Monitors `ACCOUNT_KEYCHAIN_ADDRESS` storage changes for revocations
/// - Evicts affected transactions when `is_revoked` becomes true
/// - Periodically checks all tracked keys' current revocation status (handles missed events)
pub async fn evict_revoked_keychain_txs<P, C>(pool: P, client: C)
where
    P: TransactionPool<Transaction = TempoPooledTransaction> + 'static,
    C: CanonStateSubscriptions<Primitives = TempoPrimitives> + StateProviderFactory + 'static,
{
    // Track keychain-signed transactions by their key slot
    // key_slot (U256) -> Set of tx hashes using that key
    let mut keychain_txs: HashMap<U256, HashSet<TxHash>> = HashMap::new();
    // Reverse mapping: tx_hash -> key_slot (for cleanup when tx is removed)
    let mut tx_to_slot: HashMap<TxHash, U256> = HashMap::new();

    // Helper to compute the storage slot for a key in the AccountKeychain
    let compute_key_slot = |user_address: Address, key_id: Address| -> U256 {
        AccountKeychain::new().keys[user_address][key_id].base_slot()
    };

    // Helper to track a keychain-signed transaction
    let track_keychain_tx = |keychain_txs: &mut HashMap<U256, HashSet<TxHash>>,
                             tx_to_slot: &mut HashMap<TxHash, U256>,
                             maybe_aa_tx: Option<&AASigned>,
                             tx_hash: TxHash| {
        let Some(aa_tx) = maybe_aa_tx else {
            return;
        };

        // Check if this is a keychain signature
        let Some(keychain_sig) = aa_tx.signature().as_keychain() else {
            return;
        };

        // Get the key_id from the signature
        let Ok(key_id) = keychain_sig.key_id(&aa_tx.signature_hash()) else {
            return;
        };

        let user_address = keychain_sig.user_address;
        let key_slot = compute_key_slot(user_address, key_id);

        keychain_txs.entry(key_slot).or_default().insert(tx_hash);
        tx_to_slot.insert(tx_hash, key_slot);
    };

    // Helper to remove transactions and clean up tracking maps
    let remove_txs = |keychain_txs: &mut HashMap<U256, HashSet<TxHash>>,
                      tx_to_slot: &mut HashMap<TxHash, U256>,
                      to_remove: &[TxHash]| {
        for tx_hash in to_remove {
            if let Some(slot) = tx_to_slot.remove(tx_hash)
                && let Some(hashes) = keychain_txs.get_mut(&slot)
            {
                hashes.remove(tx_hash);
                if hashes.is_empty() {
                    keychain_txs.remove(&slot);
                }
            }
        }
    };

    // Small delay to allow other tasks to initialize
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Subscribe to new transactions and chain events
    let mut new_txs = pool.new_transactions_listener();
    let mut chain_events = client.canonical_state_stream();

    // Populate keychain map with existing transactions to prevent race conditions at start-up
    pool.all_transactions().all().for_each(|tx| {
        if let Some(aa_tx) = tx.inner().as_aa() {
            let tx_hash = *aa_tx.hash();
            track_keychain_tx(&mut keychain_txs, &mut tx_to_slot, Some(aa_tx), tx_hash);
        }
    });

    loop {
        tokio::select! {
            // Track new keychain-signed transactions
            tx_event = new_txs.recv() => {
                let Some(tx_event) = tx_event else {
                    break;
                };

                let tx = &tx_event.transaction.transaction;
                let tx_hash = *tx_event.transaction.hash();
                track_keychain_tx(&mut keychain_txs, &mut tx_to_slot, tx.inner().as_aa(), tx_hash);
            }

            // Check for revoked keys when a new block is committed
            Some(event) = chain_events.next() => {
                let CanonStateNotification::Commit { new } = event else {
                    continue;
                };

                // Collect tx hashes to remove
                let mut to_remove = Vec::new();

                // First, check state changes from the committed blocks for revocations
                let state = new.execution_outcome().state().state();
                if let Some(keychain_account) = state.get(&ACCOUNT_KEYCHAIN_ADDRESS) {
                    for (slot, value) in &keychain_account.storage {
                        if let Some(tx_hashes) = keychain_txs.get(slot) {
                            let authorized_key = AuthorizedKey::decode_from_slot(value.present_value);
                            if authorized_key.is_revoked {
                                to_remove.extend(tx_hashes.iter().copied());
                            }
                        }
                    }
                }

                // Second, for any remaining tracked slots, check current state to catch
                // revocations that happened before we subscribed to events
                if to_remove.is_empty() && !keychain_txs.is_empty() {
                    let Ok(state_provider) = client.latest() else {
                        continue;
                    };

                    for (slot, tx_hashes) in &keychain_txs {
                        let slot_value = state_provider
                            .storage(ACCOUNT_KEYCHAIN_ADDRESS, (*slot).into())
                            .ok()
                            .flatten()
                            .unwrap_or(U256::ZERO);

                        let authorized_key = AuthorizedKey::decode_from_slot(slot_value);
                        if authorized_key.is_revoked {
                            to_remove.extend(tx_hashes.iter().copied());
                        }
                    }
                }

                // Evict transactions
                if !to_remove.is_empty() {
                    debug!(
                        target: "txpool",
                        count = to_remove.len(),
                        "Evicting AA transactions with revoked keychain keys"
                    );

                    remove_txs(&mut keychain_txs, &mut tx_to_slot, &to_remove);
                    pool.remove_transactions(to_remove);
                }
            }
        }
    }
}
