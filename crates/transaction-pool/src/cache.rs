//! Sender recovery cache for avoiding redundant signature recovery.

use alloy_primitives::{Address, B256};
use dashmap::DashMap;
use std::sync::Arc;

/// A cache for storing recovered transaction senders.
///
/// This cache is shared between the transaction pool and the EVM executor.
/// Senders are inserted when transactions are validated in the pool, and
/// removed when transactions are executed during `newPayload` processing.
#[derive(Debug, Clone, Default)]
pub struct SenderRecoveryCache {
    cache: Arc<DashMap<B256, Address>>,
}

impl SenderRecoveryCache {
    /// Inserts a sender for the given transaction hash.
    pub fn insert(&self, tx_hash: B256, sender: Address) {
        self.cache.insert(tx_hash, sender);
    }

    /// Removes and returns the sender for the given transaction hash, if present.
    pub fn remove(&self, tx_hash: &B256) -> Option<Address> {
        self.cache.remove(tx_hash).map(|(_, sender)| sender)
    }

    /// Removes multiple entries from the cache.
    pub fn remove_many<'a>(&self, tx_hashes: impl IntoIterator<Item = &'a B256>) {
        for tx_hash in tx_hashes {
            self.cache.remove(tx_hash);
        }
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_remove() {
        let cache = SenderRecoveryCache::default();
        let tx_hash = B256::repeat_byte(1);
        let sender = Address::repeat_byte(2);

        cache.insert(tx_hash, sender);
        assert_eq!(cache.len(), 1);

        let recovered = cache.remove(&tx_hash);
        assert_eq!(recovered, Some(sender));
        assert!(cache.is_empty());
    }

    #[test]
    fn test_remove_many() {
        let cache = SenderRecoveryCache::default();

        let hashes: Vec<_> = (0..5)
            .map(|i| {
                let tx_hash = B256::repeat_byte(i);
                let sender = Address::repeat_byte(i);
                cache.insert(tx_hash, sender);
                tx_hash
            })
            .collect();

        assert_eq!(cache.len(), 5);

        cache.remove_many(hashes[0..3].iter());
        assert_eq!(cache.len(), 2);
    }
}
