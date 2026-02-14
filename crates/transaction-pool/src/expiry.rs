//! Shared expiry tracking for transaction eviction.
//!
//! This module provides a thread-safe tracker for transaction expiry events:
//! - `valid_before` timestamps on AA transactions
//! - Keychain key expiry timestamps
//!
//! The tracker is shared between the pool (which calls `track`/`untrack` on add/remove)
//! and the maintain task (which calls `drain_expired` on each block).
//!
//! This design eliminates the need for a separate cleanup queue - when the pool
//! removes a transaction, it directly updates the tracking structures.

use alloy_primitives::{Address, TxHash, map::HashMap};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashSet};

/// Composite key identifying a keychain key: (account, key_id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct KeyId {
    account: Address,
    key_id: Address,
}

/// Thread-safe tracker for transaction expiry.
///
/// Tracks both `valid_before` timestamps and keychain key expiry.
/// Call `track` when adding transactions, `untrack` when removing,
/// and `drain_expired` to get transactions that have expired.
#[derive(Debug, Default)]
pub struct ExpiryTracker {
    inner: Mutex<ExpiryTrackerInner>,
}

#[derive(Debug, Default)]
struct ExpiryTrackerInner {
    // === valid_before tracking ===
    /// Maps `valid_before` timestamp to transaction hashes that expire at that time.
    valid_before_map: BTreeMap<u64, HashSet<TxHash>>,
    /// Reverse mapping: tx_hash -> valid_before timestamp.
    tx_to_valid_before: HashMap<TxHash, u64>,

    // === keychain key expiry tracking ===
    /// Maps expiry timestamp -> set of keys that expire at that time.
    key_expiry_map: BTreeMap<u64, HashSet<KeyId>>,
    /// Maps KeyId -> (expiry timestamp, set of transaction hashes using this key).
    key_to_txs: HashMap<KeyId, (u64, HashSet<TxHash>)>,
    /// Reverse mapping: tx_hash -> KeyId (for efficient untracking by hash).
    tx_to_key: HashMap<TxHash, KeyId>,
}

/// Information needed to track a transaction's expiry.
#[derive(Debug, Clone)]
pub struct ExpiryInfo {
    /// The transaction hash.
    pub tx_hash: TxHash,
    /// The `valid_before` timestamp, if any.
    pub valid_before: Option<u64>,
    /// Keychain key info: (account, key_id, expiry), if this is a keychain-signed tx.
    pub key_expiry: Option<(Address, Address, u64)>,
}

impl ExpiryTracker {
    /// Creates a new expiry tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a transaction's expiry information.
    ///
    /// Call this when a transaction is added to the pool.
    pub fn track(&self, info: ExpiryInfo) {
        let mut inner = self.inner.lock();

        // Track valid_before
        if let Some(valid_before) = info.valid_before {
            inner
                .valid_before_map
                .entry(valid_before)
                .or_default()
                .insert(info.tx_hash);
            inner.tx_to_valid_before.insert(info.tx_hash, valid_before);
        }

        // Track key expiry
        if let Some((account, key_id, expiry)) = info.key_expiry {
            let key = KeyId { account, key_id };

            match inner.key_to_txs.entry(key) {
                alloy_primitives::map::Entry::Occupied(mut entry) => {
                    let (existing_expiry, txs) = entry.get_mut();
                    debug_assert_eq!(
                        *existing_expiry, expiry,
                        "Key expiry changed unexpectedly - this shouldn't happen"
                    );
                    txs.insert(info.tx_hash);
                }
                alloy_primitives::map::Entry::Vacant(entry) => {
                    entry.insert((expiry, [info.tx_hash].into_iter().collect()));
                    inner.key_expiry_map.entry(expiry).or_default().insert(key);
                }
            }

            inner.tx_to_key.insert(info.tx_hash, key);
        }
    }

    /// Untrack a transaction by hash.
    ///
    /// Call this when a transaction is removed from the pool for any reason
    /// (mined, replaced, evicted, etc.). This is a no-op if the hash wasn't tracked.
    pub fn untrack(&self, tx_hash: TxHash) {
        let mut inner = self.inner.lock();

        // Untrack from valid_before
        if let Some(expiry) = inner.tx_to_valid_before.remove(&tx_hash)
            && let std::collections::btree_map::Entry::Occupied(mut entry) =
                inner.valid_before_map.entry(expiry)
        {
            entry.get_mut().remove(&tx_hash);
            if entry.get().is_empty() {
                entry.remove();
            }
        }

        // Untrack from key expiry
        if let Some(key) = inner.tx_to_key.remove(&tx_hash)
            && let Some((expiry, txs)) = inner.key_to_txs.get_mut(&key)
        {
            txs.remove(&tx_hash);

            // If no more transactions use this key, remove it entirely
            if txs.is_empty() {
                let expiry = *expiry;
                inner.key_to_txs.remove(&key);

                if let std::collections::btree_map::Entry::Occupied(mut entry) =
                    inner.key_expiry_map.entry(expiry)
                {
                    entry.get_mut().remove(&key);
                    if entry.get().is_empty() {
                        entry.remove();
                    }
                }
            }
        }
    }

    /// Drain all expired transactions up to the given timestamp.
    ///
    /// Returns transaction hashes that have expired due to either:
    /// - `valid_before <= tip_timestamp`
    /// - keychain key expiry <= tip_timestamp
    ///
    /// The returned hashes are removed from tracking (no separate cleanup needed).
    pub fn drain_expired(&self, tip_timestamp: u64) -> ExpiredTransactions {
        let mut inner = self.inner.lock();

        let mut valid_before_expired = Vec::new();
        let mut key_expired = Vec::new();

        // Drain valid_before expired
        while let Some(entry) = inner.valid_before_map.first_entry()
            && *entry.key() <= tip_timestamp
        {
            let expired_hashes = entry.remove();
            for tx_hash in &expired_hashes {
                inner.tx_to_valid_before.remove(tx_hash);
            }
            valid_before_expired.extend(expired_hashes);
        }

        // Drain key expired
        while let Some(entry) = inner.key_expiry_map.first_entry()
            && *entry.key() <= tip_timestamp
        {
            let expired_keys = entry.remove();
            for key in expired_keys {
                if let Some((_, txs)) = inner.key_to_txs.remove(&key) {
                    for tx_hash in &txs {
                        inner.tx_to_key.remove(tx_hash);
                    }
                    key_expired.extend(txs);
                }
            }
        }

        ExpiredTransactions {
            valid_before_expired,
            key_expired,
        }
    }
}

/// Result of draining expired transactions.
#[derive(Debug, Default)]
pub struct ExpiredTransactions {
    /// Transactions expired due to `valid_before` timestamp.
    pub valid_before_expired: Vec<TxHash>,
    /// Transactions expired due to keychain key expiry.
    pub key_expired: Vec<TxHash>,
}

impl ExpiredTransactions {
    /// Returns true if there are no expired transactions.
    pub fn is_empty(&self) -> bool {
        self.valid_before_expired.is_empty() && self.key_expired.is_empty()
    }

    /// Returns the total count of expired transactions.
    pub fn len(&self) -> usize {
        self.valid_before_expired.len() + self.key_expired.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    fn tx_hash(n: u8) -> TxHash {
        B256::repeat_byte(n)
    }

    fn address(n: u8) -> Address {
        Address::repeat_byte(n)
    }

    #[test]
    fn test_track_and_drain_valid_before() {
        let tracker = ExpiryTracker::new();

        // Track tx with valid_before = 100
        tracker.track(ExpiryInfo {
            tx_hash: tx_hash(1),
            valid_before: Some(100),
            key_expiry: None,
        });

        // Not expired yet at timestamp 99
        let expired = tracker.drain_expired(99);
        assert!(expired.is_empty());

        // Expired at timestamp 100
        let expired = tracker.drain_expired(100);
        assert_eq!(expired.valid_before_expired.len(), 1);
        assert_eq!(expired.valid_before_expired[0], tx_hash(1));

        // Should be drained now
        let expired = tracker.drain_expired(100);
        assert!(expired.is_empty());
    }

    #[test]
    fn test_untrack_before_expiry() {
        let tracker = ExpiryTracker::new();

        tracker.track(ExpiryInfo {
            tx_hash: tx_hash(1),
            valid_before: Some(100),
            key_expiry: None,
        });

        // Untrack before it expires
        tracker.untrack(tx_hash(1));

        // Should not show up in expired
        let expired = tracker.drain_expired(200);
        assert!(expired.is_empty());
    }

    #[test]
    fn test_key_expiry_tracking() {
        let tracker = ExpiryTracker::new();

        // Track tx with key expiry
        tracker.track(ExpiryInfo {
            tx_hash: tx_hash(1),
            valid_before: None,
            key_expiry: Some((address(1), address(2), 100)),
        });

        // Not expired at 99
        let expired = tracker.drain_expired(99);
        assert!(expired.is_empty());

        // Expired at 100
        let expired = tracker.drain_expired(100);
        assert_eq!(expired.key_expired.len(), 1);
        assert_eq!(expired.key_expired[0], tx_hash(1));
    }

    #[test]
    fn test_multiple_txs_same_key() {
        let tracker = ExpiryTracker::new();

        // Track two txs using the same key
        tracker.track(ExpiryInfo {
            tx_hash: tx_hash(1),
            valid_before: None,
            key_expiry: Some((address(1), address(2), 100)),
        });
        tracker.track(ExpiryInfo {
            tx_hash: tx_hash(2),
            valid_before: None,
            key_expiry: Some((address(1), address(2), 100)),
        });

        // Untrack one - the other should still be tracked
        tracker.untrack(tx_hash(1));

        let expired = tracker.drain_expired(100);
        assert_eq!(expired.key_expired.len(), 1);
        assert_eq!(expired.key_expired[0], tx_hash(2));
    }

    #[test]
    fn test_untrack_idempotent() {
        let tracker = ExpiryTracker::new();

        tracker.track(ExpiryInfo {
            tx_hash: tx_hash(1),
            valid_before: Some(100),
            key_expiry: Some((address(1), address(2), 100)),
        });

        // Untrack multiple times - should be fine
        tracker.untrack(tx_hash(1));
        tracker.untrack(tx_hash(1));
        tracker.untrack(tx_hash(1));

        // Should still be empty
        let expired = tracker.drain_expired(200);
        assert!(expired.is_empty());
    }
}
