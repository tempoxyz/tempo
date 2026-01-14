//! Transaction pool maintenance tasks.

use crate::{TempoTransactionPool, transaction::TempoPooledTransaction};
use alloy_consensus::transaction::TxHashRef;
use alloy_primitives::TxHash;
use futures::StreamExt;
use reth_chainspec::ChainSpecProvider;
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{PoolTransaction, TransactionOrigin, TransactionPool};
use std::{collections::BTreeMap, sync::Arc};
use tempo_chainspec::TempoChainSpec;
use tempo_primitives::{AASigned, TempoPrimitives};
use tracing::{debug, error};

pub use reorg::handle_reorg;

mod reorg {
    use super::*;
    use reth_provider::Chain;
    use std::collections::HashSet;

    /// Handles a reorg event by identifying orphaned AA 2D transactions from the old chain
    /// that are not in the new chain.
    pub fn handle_reorg<F>(
        old_chain: Arc<Chain<TempoPrimitives>>,
        new_chain: Arc<Chain<TempoPrimitives>>,
        is_in_pool: F,
    ) -> Vec<TempoPooledTransaction>
    where
        F: Fn(&TxHash) -> bool,
    {
        // Get inner chain blocks for iteration
        let (new_blocks, _) = new_chain.inner();
        let (old_blocks, _) = old_chain.inner();

        // Collect transaction hashes from the new chain to identify what's still mined
        let new_mined_hashes: HashSet<TxHash> = new_blocks.transaction_hashes().collect();

        // Find AA 2D transactions from the old chain that are NOT in the new chain
        old_blocks
            .transactions_ecrecovered()
            .filter(|tx| !new_mined_hashes.contains(tx.tx_hash()))
            .filter_map(|tx| {
                let aa_tx = tx.as_aa()?;
                // Only process 2D nonce transactions (nonce_key > 0)
                if aa_tx.tx().nonce_key.is_zero() {
                    return None;
                }
                let pooled_tx = TempoPooledTransaction::new(tx);
                // Skip if already in pool
                if is_in_pool(pooled_tx.hash()) {
                    return None;
                }
                Some(pooled_tx)
            })
            .collect()
    }
}

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
///
/// # Reorg Handling
///
/// During a reorg, this function:
/// 1. Identifies AA 2D transactions that were mined in the old chain but NOT in the new chain
/// 2. Re-injects those orphaned transactions back into the pool
/// 3. Updates the nonce state based on the new canonical chain
pub async fn maintain_2d_nonce_pool<Client>(pool: TempoTransactionPool<Client>)
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    let mut events = pool.client().canonical_state_stream();
    while let Some(notification) = events.next().await {
        match notification {
            CanonStateNotification::Commit { new } => {
                // Simple commit: just update nonce state from the new chain
                pool.notify_aa_pool_on_state_updates(new.execution_outcome().state().state());
            }
            CanonStateNotification::Reorg { old, new } => {
                // Use the extracted reorg handler to identify orphaned transactions
                let orphaned_txs = handle_reorg(old, new.clone(), |hash| pool.contains(hash));

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
            }
        }
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

#[cfg(test)]
mod tests {
    use super::handle_reorg;
    use crate::test_utils::TxBuilder;
    use alloy_primitives::{Address, TxHash, U256};
    use reth_primitives_traits::RecoveredBlock;
    use reth_provider::{Chain, ExecutionOutcome};
    use reth_transaction_pool::PoolTransaction;
    use std::{collections::HashSet, sync::Arc};
    use tempo_primitives::{Block, BlockBody, TempoHeader, TempoPrimitives, TempoTxEnvelope};

    /// Creates a test chain from a list of blocks.
    fn create_test_chain(blocks: Vec<RecoveredBlock<Block>>) -> Arc<Chain<TempoPrimitives>> {
        Arc::new(Chain::new(blocks, ExecutionOutcome::default(), None))
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

    #[test]
    fn handle_reorg_correctly_identifies_orphaned_aa_2d_transactions() {
        let sender = Address::random();

        // AA 2D tx that will be orphaned (should be re-injected)
        let tx_2d_orphaned = TxBuilder::aa(sender).nonce_key(U256::from(1)).build();
        let hash_2d_orphaned = *tx_2d_orphaned.hash();
        let envelope_2d_orphaned = extract_envelope(&tx_2d_orphaned);

        // AA 2D tx that will be re-included in new chain (should NOT be re-injected)
        let tx_2d_reincluded = TxBuilder::aa(sender).nonce_key(U256::from(2)).build();
        let envelope_2d_reincluded = extract_envelope(&tx_2d_reincluded);

        // AA 2D tx that's already in the pool (should NOT be re-injected)
        let tx_2d_in_pool = TxBuilder::aa(sender).nonce_key(U256::from(3)).build();
        let hash_2d_in_pool = *tx_2d_in_pool.hash();
        let envelope_2d_in_pool = extract_envelope(&tx_2d_in_pool);

        // AA tx with nonce_key=0 (should NOT be re-injected - vanilla pool handles it)
        let tx_non_2d = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let envelope_non_2d = extract_envelope(&tx_non_2d);

        // EIP-1559 tx (should NOT be re-injected - not AA)
        let tx_eip1559 = TxBuilder::eip1559(Address::random()).build();
        let envelope_eip1559 = extract_envelope(&tx_eip1559);

        // Create old chain with all 5 transactions (all from same sender for simplicity)
        let old_block = create_block_with_txs(
            1,
            vec![
                envelope_2d_orphaned,
                envelope_2d_reincluded.clone(),
                envelope_2d_in_pool,
                envelope_non_2d,
                envelope_eip1559,
            ],
            vec![sender; 5],
        );
        let old_chain = create_test_chain(vec![old_block]);

        // Create new chain with only the re-included tx
        let new_block = create_block_with_txs(1, vec![envelope_2d_reincluded], vec![sender]);
        let new_chain = create_test_chain(vec![new_block]);

        // Simulate pool containing the "already in pool" tx
        let pool_hashes: HashSet<TxHash> = [hash_2d_in_pool].into_iter().collect();

        // Execute handle_reorg
        let orphaned = handle_reorg(old_chain, new_chain, |hash| pool_hashes.contains(hash));

        // Verify: Only the orphaned AA 2D tx should be returned
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
    }
}
