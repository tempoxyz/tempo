//! Pool for transactions whose fee token is temporarily paused.
//!
//! When a TIP20 fee token emits `PauseStateUpdate(isPaused=true)`, transactions
//! using that fee token are moved here instead of being evicted entirely.
//! When the token is unpaused, transactions are moved back to the main pool
//! and re-validated.

use crate::transaction::TempoPooledTransaction;
use alloy_primitives::{Address, TxHash, map::HashMap};
use reth_transaction_pool::ValidPoolTransaction;
use std::{sync::Arc, time::Instant};

/// Duration after which paused transactions are expired and removed.
/// If a token isn't unpaused within this time, we clear all pending transactions.
pub const PAUSED_TX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60); // 30 minutes

/// Entry in the paused pool.
#[derive(Debug, Clone)]
pub struct PausedEntry {
    /// The valid pool transaction that was paused (Arc to avoid expensive clones).
    pub tx: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    /// When the transaction was moved to the paused pool.
    pub paused_at: Instant,
    /// The `valid_before` timestamp, if any (for expiry tracking).
    pub valid_before: Option<u64>,
}

/// Pool for transactions whose fee token is temporarily paused.
///
/// Transactions are indexed by fee token address for efficient batch operations.
/// Since all transactions for a token are paused/unpaused together, we only need
/// the token-level grouping.
#[derive(Debug, Default)]
pub struct PausedFeeTokenPool {
    /// Fee token -> list of paused entries
    by_token: HashMap<Address, Vec<PausedEntry>>,
}

impl PausedFeeTokenPool {
    /// Creates a new empty paused pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the total number of paused transactions across all tokens.
    pub fn len(&self) -> usize {
        self.by_token.values().map(|v| v.len()).sum()
    }

    /// Returns true if there are no paused transactions.
    pub fn is_empty(&self) -> bool {
        self.by_token.is_empty()
    }

    /// Inserts transactions for a fee token into the paused pool.
    ///
    /// Takes the full batch at once since all transactions for a token
    /// are paused together.
    pub fn insert_batch(&mut self, fee_token: Address, entries: Vec<PausedEntry>) {
        if entries.is_empty() {
            return;
        }
        self.by_token.entry(fee_token).or_default().extend(entries);
    }

    /// Drains all transactions for a given fee token.
    ///
    /// Returns the list of paused entries for that token.
    pub fn drain_token(&mut self, fee_token: &Address) -> Vec<PausedEntry> {
        self.by_token.remove(fee_token).unwrap_or_default()
    }

    /// Returns the number of transactions paused for a given fee token.
    pub fn count_for_token(&self, fee_token: &Address) -> usize {
        self.by_token.get(fee_token).map_or(0, Vec::len)
    }

    /// Returns true if a transaction with the given hash is in the paused pool.
    pub fn contains(&self, tx_hash: &TxHash) -> bool {
        self.by_token
            .values()
            .any(|entries| entries.iter().any(|e| e.tx.hash() == tx_hash))
    }

    /// Evicts expired transactions based on `valid_before` timestamp.
    ///
    /// Returns the number of transactions removed.
    pub fn evict_expired(&mut self, tip_timestamp: u64) -> usize {
        let mut count = 0;
        for entries in self.by_token.values_mut() {
            let before = entries.len();
            entries.retain(|e| e.valid_before.map_or(true, |vb| vb > tip_timestamp));
            count += before - entries.len();
        }
        // Clean up empty token entries
        self.by_token.retain(|_, v| !v.is_empty());
        count
    }

    /// Evicts transactions that have been paused for too long (timeout).
    ///
    /// Returns the number of transactions removed.
    pub fn evict_timed_out(&mut self) -> usize {
        let now = Instant::now();
        let mut count = 0;
        for entries in self.by_token.values_mut() {
            let before = entries.len();
            entries.retain(|e| now.duration_since(e.paused_at) < PAUSED_TX_TIMEOUT);
            count += before - entries.len();
        }
        // Clean up empty token entries
        self.by_token.retain(|_, v| !v.is_empty());
        count
    }

    /// Removes transactions with revoked keychain keys from the paused pool.
    ///
    /// Returns the number of transactions removed.
    pub fn evict_by_revoked_keys(&mut self, revoked_keys: &[(Address, Address)]) -> usize {
        if revoked_keys.is_empty() {
            return 0;
        }

        let mut count = 0;
        for entries in self.by_token.values_mut() {
            let before = entries.len();
            entries.retain(|entry| {
                let Some(aa_tx) = entry.tx.transaction.inner().as_aa() else {
                    return true;
                };
                let Some(keychain_sig) = aa_tx.signature().as_keychain() else {
                    return true;
                };
                let Ok(key_id) = keychain_sig.key_id(&aa_tx.signature_hash()) else {
                    return true;
                };
                let account = keychain_sig.user_address;
                !revoked_keys.contains(&(account, key_id))
            });
            count += before - entries.len();
        }
        // Clean up empty token entries
        self.by_token.retain(|_, v| !v.is_empty());
        count
    }

    /// Returns an iterator over all paused entries across all tokens.
    pub fn all_entries(&self) -> impl Iterator<Item = &PausedEntry> {
        self.by_token.values().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TxBuilder, wrap_valid_tx};

    fn create_valid_tx(sender: Address) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        use reth_transaction_pool::TransactionOrigin;
        let pooled = TxBuilder::aa(sender).build();
        Arc::new(wrap_valid_tx(pooled, TransactionOrigin::External))
    }

    #[test]
    fn test_insert_and_drain() {
        let mut pool = PausedFeeTokenPool::new();
        let fee_token = Address::random();

        let entries: Vec<_> = (0..3)
            .map(|_| PausedEntry {
                tx: create_valid_tx(Address::random()),
                paused_at: Instant::now(),
                valid_before: None,
            })
            .collect();

        assert!(pool.is_empty());
        pool.insert_batch(fee_token, entries);

        assert_eq!(pool.len(), 3);
        assert_eq!(pool.count_for_token(&fee_token), 3);

        let drained = pool.drain_token(&fee_token);
        assert_eq!(drained.len(), 3);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_evict_expired() {
        let mut pool = PausedFeeTokenPool::new();
        let fee_token = Address::random();

        let entries = vec![
            PausedEntry {
                tx: create_valid_tx(Address::random()),
                paused_at: Instant::now(),
                valid_before: Some(100), // Will expire
            },
            PausedEntry {
                tx: create_valid_tx(Address::random()),
                paused_at: Instant::now(),
                valid_before: Some(200), // Won't expire
            },
            PausedEntry {
                tx: create_valid_tx(Address::random()),
                paused_at: Instant::now(),
                valid_before: None, // No expiry
            },
        ];

        pool.insert_batch(fee_token, entries);
        assert_eq!(pool.len(), 3);

        let evicted = pool.evict_expired(150);
        assert_eq!(evicted, 1);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_contains() {
        let mut pool = PausedFeeTokenPool::new();
        let fee_token = Address::random();

        let tx = create_valid_tx(Address::random());
        let tx_hash = *tx.hash();

        let entry = PausedEntry {
            tx,
            paused_at: Instant::now(),
            valid_before: None,
        };

        assert!(!pool.contains(&tx_hash));
        pool.insert_batch(fee_token, vec![entry]);
        assert!(pool.contains(&tx_hash));
    }
}
