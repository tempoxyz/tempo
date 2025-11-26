//! Transaction pool maintenance tasks.

use crate::transaction::TempoPooledTransaction;
use alloy_primitives::TxHash;
use futures::StreamExt;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions};
use reth_transaction_pool::{PoolTransaction, TransactionPool};
use std::collections::BTreeMap;
use tracing::debug;

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
    // Track valid_before timestamp -> Vec<TxHash>
    let mut expiry_map: BTreeMap<u64, Vec<TxHash>> = BTreeMap::new();

    // Subscribe to new transactions and blocks
    let mut new_txs = pool.new_transactions_listener();
    let mut chain_events = client.canonical_state_stream();

    loop {
        tokio::select! {
            // Update cache when a txs are added to the mempool
            tx_event = new_txs.recv() => {
                let Some(tx_event) = tx_event else {
                    break;
                };

                // Check if it's an AA tx with `valid_before`
                let tx = &tx_event.transaction.transaction;
                if let Some(aa_tx) = tx.inner().as_aa()
                    && let Some(valid_before) = aa_tx.tx().valid_before
                {
                    let hash = *tx.hash();
                    expiry_map.entry(valid_before).or_default().push(hash);
                }
            }

            // Check for expired txs when a new block is commited
            Some(event) = chain_events.next() => {
                let CanonStateNotification::Commit { new } = event else {
                    continue;
                };

                let tip_timestamp = new.tip().header().timestamp();

                // Gather expired tx hashes and evict them
                let expired: Vec<u64> = expiry_map
                    .range(..=tip_timestamp)
                    .map(|(ts, _)| *ts)
                    .collect();

                let mut to_remove = Vec::new();
                for ts in expired {
                    if let Some(hashes) = expiry_map.remove(&ts) {
                        to_remove.extend(hashes);
                    }
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
