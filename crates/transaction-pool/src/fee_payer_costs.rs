//! Aggregate fee cost of pooled transactions per fee payer.

use alloy_primitives::{
    Address, TxHash, U256,
    map::{B256Map, HashMap},
};

/// The `(fee_token, fee_payer)` pair that pays for a transaction.
pub(crate) type FeePayerKey = (Address, Address);

/// Tracks the summed max fee cost of pooled transactions per `(fee_token, fee_payer)`.
///
/// The protocol pool can drop transactions without notifying us (replacement, size-limit
/// discards, mined transactions), so entries may outlive their transaction. Stale entries only
/// make the admission check stricter, and a rejection is only final after
/// [`Self::retain_payer`] has dropped entries that are no longer pooled. A missed removal can
/// therefore never permanently block a fee payer.
#[derive(Debug, Default)]
pub(crate) struct PooledFeeCosts {
    by_payer: HashMap<FeePayerKey, PayerFeeCosts>,
    by_hash: B256Map<FeePayerKey>,
}

#[derive(Debug, Default)]
struct PayerFeeCosts {
    total: U256,
    txs: B256Map<U256>,
}

impl PooledFeeCosts {
    /// Returns the number of tracked transactions.
    pub(crate) fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Returns the tracked fee cost of all transactions paid by `key`.
    pub(crate) fn total(&self, key: &FeePayerKey) -> U256 {
        self.by_payer
            .get(key)
            .map_or(U256::ZERO, |payer| payer.total)
    }

    /// Returns the tracked fee cost of `key`, excluding the given transactions.
    pub(crate) fn total_excluding(&self, key: &FeePayerKey, excluded: &[TxHash]) -> U256 {
        let Some(payer) = self.by_payer.get(key) else {
            return U256::ZERO;
        };
        excluded
            .iter()
            .filter_map(|hash| payer.txs.get(hash))
            .fold(payer.total, |total, cost| total - cost)
    }

    /// Returns the hashes tracked for `key`.
    pub(crate) fn hashes(&self, key: &FeePayerKey) -> impl Iterator<Item = &TxHash> {
        self.by_payer
            .get(key)
            .into_iter()
            .flat_map(|payer| payer.txs.keys())
    }

    /// Tracks a transaction. Returns `false` if the hash was already tracked.
    pub(crate) fn insert(&mut self, hash: TxHash, key: FeePayerKey, cost: U256) -> bool {
        if self.by_hash.contains_key(&hash) {
            return false;
        }
        self.by_hash.insert(hash, key);
        let payer = self.by_payer.entry(key).or_default();
        payer.total = payer.total.saturating_add(cost);
        payer.txs.insert(hash, cost);
        true
    }

    /// Stops tracking a transaction.
    pub(crate) fn remove(&mut self, hash: &TxHash) {
        let Some(key) = self.by_hash.remove(hash) else {
            return;
        };
        let Some(payer) = self.by_payer.get_mut(&key) else {
            return;
        };
        if let Some(cost) = payer.txs.remove(hash) {
            payer.total -= cost;
        }
        if payer.txs.is_empty() {
            self.by_payer.remove(&key);
        }
    }

    /// Stops tracking all given transactions.
    pub(crate) fn remove_all<'a>(&mut self, hashes: impl IntoIterator<Item = &'a TxHash>) {
        for hash in hashes {
            self.remove(hash);
        }
    }

    /// Keeps only the transactions for which `is_pooled` returns true.
    pub(crate) fn retain(&mut self, mut is_pooled: impl FnMut(&TxHash) -> bool) {
        self.by_payer.retain(|_, payer| {
            payer.txs.retain(|hash, cost| {
                let keep = is_pooled(hash);
                if !keep {
                    payer.total -= *cost;
                }
                keep
            });
            !payer.txs.is_empty()
        });
        self.by_hash.retain(|hash, _| is_pooled(hash));
    }
}

#[cfg(test)]
impl PooledFeeCosts {
    /// Returns every tracked fee payer with its total.
    pub(crate) fn totals(&self) -> HashMap<FeePayerKey, U256> {
        self.by_payer
            .iter()
            .map(|(key, payer)| (*key, payer.total))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;

    #[test]
    fn insert_remove_and_retain_keep_totals_consistent() {
        let key = (Address::random(), Address::random());
        let other = (Address::random(), Address::random());
        let [a, b, c] = [B256::random(), B256::random(), B256::random()];
        let mut costs = PooledFeeCosts::default();

        assert!(costs.insert(a, key, U256::from(10)));
        assert!(!costs.insert(a, key, U256::from(10)));
        assert!(costs.insert(b, key, U256::from(5)));
        assert!(costs.insert(c, other, U256::from(7)));
        assert_eq!(costs.total(&key), U256::from(15));
        assert_eq!(costs.total_excluding(&key, &[a, c]), U256::from(5));

        costs.remove_all(&[a]);
        assert_eq!(costs.total(&key), U256::from(5));
        assert_eq!(costs.len(), 2);

        costs.retain(|hash| *hash != c);
        assert_eq!(costs.total(&other), U256::ZERO);
        assert_eq!(costs.len(), 1);

        costs.remove(&b);
        assert_eq!(costs.total(&key), U256::ZERO);
        assert_eq!(costs.len(), 0);
        assert!(costs.totals().is_empty());
    }
}
