//! Pool for transactions whose fee token is temporarily paused.
//!
//! When a TIP20 fee token emits `PauseStateUpdate(isPaused=true)`, transactions
//! using that fee token are moved here instead of being evicted entirely.
//! When the token is unpaused, transactions are moved back to the main pool
//! and re-validated.

use alloy_primitives::{Address, TxHash, map::HashMap};
use reth_primitives_traits::{Recovered, transaction::TxHashRef};
use reth_transaction_pool::TransactionOrigin;
use std::time::Instant;
use tempo_primitives::TempoTxEnvelope;

/// Entry in the paused pool.
#[derive(Debug, Clone)]
pub struct PausedEntry {
    /// The recovered transaction that was paused.
    pub tx: Recovered<TempoTxEnvelope>,
    /// The origin of the transaction (local, external, etc.).
    pub origin: TransactionOrigin,
    /// When the transaction was moved to the paused pool.
    pub paused_at: Instant,
    /// The `valid_before` timestamp, if any (for expiry tracking).
    pub valid_before: Option<u64>,
}

/// Pool for transactions whose fee token is temporarily paused.
///
/// Transactions are indexed by both fee token address and transaction hash
/// for efficient lookup in both directions.
#[derive(Debug, Default)]
pub struct PausedFeeTokenPool {
    /// Fee token -> (tx_hash -> entry)
    by_token: HashMap<Address, HashMap<TxHash, PausedEntry>>,
    /// tx_hash -> fee token (for O(1) removal by hash)
    by_hash: HashMap<TxHash, Address>,
}

impl PausedFeeTokenPool {
    /// Creates a new empty paused pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of paused transactions.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Returns true if there are no paused transactions.
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Inserts a transaction into the paused pool.
    ///
    /// If the transaction is already paused (by hash), this is a no-op.
    pub fn insert(&mut self, fee_token: Address, entry: PausedEntry) {
        let tx_hash = *entry.tx.tx_hash();

        if self.by_hash.contains_key(&tx_hash) {
            return;
        }

        self.by_hash.insert(tx_hash, fee_token);
        self.by_token
            .entry(fee_token)
            .or_default()
            .insert(tx_hash, entry);
    }

    /// Removes a transaction by hash from the paused pool.
    ///
    /// Returns the entry if it was present.
    pub fn remove(&mut self, tx_hash: &TxHash) -> Option<PausedEntry> {
        let fee_token = self.by_hash.remove(tx_hash)?;
        let entry = self
            .by_token
            .get_mut(&fee_token)
            .and_then(|txs| txs.remove(tx_hash));

        if let Some(txs) = self.by_token.get(&fee_token)
            && txs.is_empty()
        {
            self.by_token.remove(&fee_token);
        }

        entry
    }

    /// Drains all transactions for a given fee token.
    ///
    /// Returns an iterator over the paused entries for that token.
    pub fn drain_token(&mut self, fee_token: &Address) -> Vec<PausedEntry> {
        let Some(txs) = self.by_token.remove(fee_token) else {
            return Vec::new();
        };

        for tx_hash in txs.keys() {
            self.by_hash.remove(tx_hash);
        }

        txs.into_values().collect()
    }

    /// Returns true if a transaction with the given hash is in the paused pool.
    pub fn contains(&self, tx_hash: &TxHash) -> bool {
        self.by_hash.contains_key(tx_hash)
    }

    /// Returns the number of transactions paused for a given fee token.
    pub fn count_for_token(&self, fee_token: &Address) -> usize {
        self.by_token.get(fee_token).map_or(0, HashMap::len)
    }

    /// Returns an iterator over all transaction hashes that have expired
    /// (valid_before <= tip_timestamp).
    ///
    /// This does not remove the transactions; caller should use `remove()`.
    pub fn expired_hashes(&self, tip_timestamp: u64) -> Vec<TxHash> {
        self.by_token
            .values()
            .flat_map(|txs| txs.iter())
            .filter_map(|(hash, entry)| {
                entry
                    .valid_before
                    .filter(|&vb| vb <= tip_timestamp)
                    .map(|_| *hash)
            })
            .collect()
    }

    /// Returns an iterator over all paused entries for scanning (e.g., key revocations).
    pub fn all_entries(&self) -> impl Iterator<Item = (&TxHash, &PausedEntry)> {
        self.by_token.values().flat_map(|txs| txs.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TxBuilder;
    use reth_primitives_traits::transaction::TxHashRef;
    use reth_transaction_pool::PoolTransaction;

    fn create_recovered_tx(sender: Address) -> Recovered<TempoTxEnvelope> {
        let tx = TxBuilder::aa(sender).build();
        tx.clone_into_consensus()
    }

    #[test]
    fn test_insert_and_remove() {
        let mut pool = PausedFeeTokenPool::new();
        let fee_token = Address::random();
        let sender = Address::random();

        let tx = create_recovered_tx(sender);
        let tx_hash = *tx.tx_hash();

        let entry = PausedEntry {
            tx,
            origin: TransactionOrigin::External,
            paused_at: Instant::now(),
            valid_before: None,
        };

        assert!(pool.is_empty());
        pool.insert(fee_token, entry);

        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tx_hash));
        assert_eq!(pool.count_for_token(&fee_token), 1);

        let removed = pool.remove(&tx_hash);
        assert!(removed.is_some());
        assert!(pool.is_empty());
        assert!(!pool.contains(&tx_hash));
    }

    #[test]
    fn test_drain_token() {
        let mut pool = PausedFeeTokenPool::new();
        let fee_token = Address::random();

        for _ in 0..3 {
            let tx = create_recovered_tx(Address::random());
            let entry = PausedEntry {
                tx,
                origin: TransactionOrigin::External,
                paused_at: Instant::now(),
                valid_before: None,
            };
            pool.insert(fee_token, entry);
        }

        assert_eq!(pool.len(), 3);
        assert_eq!(pool.count_for_token(&fee_token), 3);

        let drained = pool.drain_token(&fee_token);
        assert_eq!(drained.len(), 3);
        assert!(pool.is_empty());
        assert_eq!(pool.count_for_token(&fee_token), 0);
    }

    #[test]
    fn test_expired_hashes() {
        let mut pool = PausedFeeTokenPool::new();
        let fee_token = Address::random();

        let tx1 = create_recovered_tx(Address::random());
        let tx1_hash = *tx1.tx_hash();
        pool.insert(
            fee_token,
            PausedEntry {
                tx: tx1,
                origin: TransactionOrigin::External,
                paused_at: Instant::now(),
                valid_before: Some(100),
            },
        );

        let tx2 = create_recovered_tx(Address::random());
        pool.insert(
            fee_token,
            PausedEntry {
                tx: tx2,
                origin: TransactionOrigin::External,
                paused_at: Instant::now(),
                valid_before: Some(200),
            },
        );

        let tx3 = create_recovered_tx(Address::random());
        pool.insert(
            fee_token,
            PausedEntry {
                tx: tx3,
                origin: TransactionOrigin::External,
                paused_at: Instant::now(),
                valid_before: None,
            },
        );

        let expired = pool.expired_hashes(100);
        assert_eq!(expired.len(), 1);
        assert!(expired.contains(&tx1_hash));

        let expired = pool.expired_hashes(200);
        assert_eq!(expired.len(), 2);
    }

    #[test]
    fn test_idempotent_insert() {
        let mut pool = PausedFeeTokenPool::new();
        let fee_token = Address::random();

        let tx = create_recovered_tx(Address::random());
        let entry = PausedEntry {
            tx,
            origin: TransactionOrigin::External,
            paused_at: Instant::now(),
            valid_before: None,
        };

        pool.insert(fee_token, entry.clone());
        pool.insert(fee_token, entry);

        assert_eq!(pool.len(), 1);
    }
}
