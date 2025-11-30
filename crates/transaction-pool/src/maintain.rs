//! Transaction pool maintenance tasks.

use crate::{TempoTransactionPool, transaction::TempoPooledTransaction};
use alloy_primitives::TxHash;
use futures::{Stream, StreamExt};
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions};
use reth_storage_api::StateProviderFactory;
use reth_tracing::tracing::trace;
use reth_transaction_pool::TransactionPool;
use std::collections::BTreeMap;
use tempo_chainspec::TempoChainSpec;
use tempo_precompiles::NONCE_PRECOMPILE_ADDRESS;
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
pub async fn maintain_2d_nonce_pool<Client, St>(pool: TempoTransactionPool<Client>, mut events: St)
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = TempoChainSpec> + 'static,
    St: Stream<Item = CanonStateNotification<TempoPrimitives>> + Send + Unpin + 'static,
{
    let nonce_keys = pool.aa_2d_nonce_keys();
    while let Some(notification) = events.next().await {
        let tip = notification.committed();
        let Some(nonce_manager_changes) = tip
            .execution_outcome()
            .bundle
            .account(&NONCE_PRECOMPILE_ADDRESS)
        else {
            continue;
        };
        // this contains all the nonce manager precompile changes. if any
        let changed_slots = nonce_manager_changes
            .storage
            .iter()
            .map(|(slot, change)| (*slot, change.present_value))
            .collect::<Vec<_>>();
        if changed_slots.is_empty() {
            continue;
        }

        // we can now map the slots back to addresses and nonce keys and then update the pool
        let updates = nonce_keys.update_tracked(changed_slots);
        trace!(target: "txpool::2d",  ?updates, "update tracked 2d nonce changes");

        pool.on_aa_2d_nonce_changes(updates);
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
