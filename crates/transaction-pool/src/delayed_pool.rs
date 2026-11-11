//! Sub-pool for expiring nonce transactions whose `valid_after` is too far ahead of the tip to be
//! included soon.
//!
//! Delayed transactions are visible to lookups and gossip but stay out of the live sub-pools and
//! their limits until pool maintenance releases them shortly before `valid_after`.
//!
//! Only expiring nonce transactions are delayed. They are unique by their expiring nonce hash and
//! belong to no sequential nonce lane, so delaying them never splits a sender's nonce sequence
//! across sub-pools. Future-dated transactions with sequential nonces enter the live sub-pools.

use crate::{
    authority_counts::AuthorityCounts, metrics::DelayedPoolMetrics,
    transaction::TempoPooledTransaction, tt_2d_pool::DEFAULT_MAX_TXS_PER_AUTHORITY,
};
use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, TxHash, map::B256Map};
use reth_primitives_traits::InMemorySize;
use reth_transaction_pool::{
    GetPooledTransactionLimit, PoolResult, PoolTransaction, ValidPoolTransaction,
    error::{PoolError, PoolErrorKind},
};
use std::{collections::BTreeSet, num::NonZeroUsize, sync::Arc};

/// Number of seconds before `valid_after` at which a delayed transaction is released.
const DEFAULT_DELAYED_LEAD_SECS: u64 = 2;

/// Default maximum number of delayed transactions.
pub const DEFAULT_DELAYED_MAX_COUNT: NonZeroUsize = NonZeroUsize::new(4096).unwrap();

/// Maximum total size of delayed transactions in bytes.
const DEFAULT_DELAYED_MAX_SIZE: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).unwrap();

/// Delays expiring nonce transactions that pass validation but whose `valid_after` is later than
/// the tip timestamp plus [`DelayedPoolConfig::lead_secs`].
#[derive(Debug, Default)]
pub struct DelayedPool {
    /// Lead time and limits.
    config: DelayedPoolConfig,
    /// Delayed transactions by hash.
    by_hash: B256Map<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    /// Delayed transactions ordered by `valid_after`, for release.
    by_valid_after: BTreeSet<(u64, TxHash)>,
    /// Delayed transactions ordered by priority fee, lowest first, for eviction when full.
    by_priority: BTreeSet<(u128, TxHash)>,
    /// Total size of delayed transactions in bytes.
    size: usize,
    /// Number of delayed transactions per authority, limited by
    /// [`DelayedPoolConfig::max_txs_per_authority`].
    txs_by_authority: AuthorityCounts,
    /// Metrics for delayed transactions.
    metrics: DelayedPoolMetrics,
}

impl DelayedPool {
    /// Creates an empty pool with the given config.
    pub fn new(config: DelayedPoolConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    /// Returns the lead time and limits.
    pub(crate) const fn config(&self) -> DelayedPoolConfig {
        self.config
    }

    /// Delays a validated transaction until its `valid_after` and returns the delayed transactions it
    /// evicted. The caller ensures the transaction uses an expiring nonce.
    ///
    /// Rejected as already imported if it is delayed already, and with the authority if one of
    /// its authorities has [`DelayedPoolConfig::max_txs_per_authority`] delayed transactions.
    /// When the pool is full, the lowest-priority delayed transactions are evicted to make room,
    /// but only for a transaction whose priority fee is higher than each of theirs; otherwise it
    /// is rejected as discarded on insert.
    pub(crate) fn insert(
        &mut self,
        transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    ) -> PoolResult<Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>> {
        debug_assert!(transaction.transaction.is_expiring_nonce());
        let hash = *transaction.hash();
        if self.by_hash.contains_key(&hash) {
            return Err(PoolError::new(hash, PoolErrorKind::AlreadyImported));
        }
        if let Some(authority) = self
            .txs_by_authority
            .at_capacity(self.config.max_txs_per_authority, &transaction.transaction)
        {
            return Err(PoolError::new(
                hash,
                PoolErrorKind::SpammerExceededCapacity(authority),
            ));
        }
        let full = || PoolError::new(hash, PoolErrorKind::DiscardedOnInsert);
        let tx_size = transaction.transaction.size();
        let max_size = self.config.max_size.get();
        if tx_size > max_size {
            return Err(full());
        }
        let priority = transaction.transaction.priority_fee_or_price();
        let (mut count, mut size) = (self.by_hash.len(), self.size);
        let mut to_evict = Vec::new();
        for (evict_priority, evict_hash) in &self.by_priority {
            if count < self.config.max_count.get() && size + tx_size <= max_size {
                break;
            }
            if *evict_priority >= priority {
                return Err(full());
            }
            count -= 1;
            size -= self.by_hash[evict_hash].transaction.size();
            to_evict.push(*evict_hash);
        }
        let evicted = to_evict
            .iter()
            .filter_map(|evict_hash| self.remove(evict_hash))
            .collect();

        self.by_valid_after
            .insert((valid_after(&transaction), hash));
        self.by_priority.insert((priority, hash));
        self.size += tx_size;
        self.txs_by_authority.add(&transaction.transaction);

        self.by_hash.insert(hash, transaction);
        self.update_metrics();
        Ok(evicted)
    }

    /// Removes and returns the delayed transactions whose `valid_after` is within the lead time
    /// of `tip_timestamp`, earliest first.
    pub(crate) fn take_due(
        &mut self,
        tip_timestamp: u64,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let release_until = tip_timestamp.saturating_add(self.config.lead_secs);
        let due: Vec<_> = self
            .by_valid_after
            .range(..=(release_until, B256::repeat_byte(0xff)))
            .map(|(_, hash)| *hash)
            .collect();
        self.metrics
            .released_transactions
            .increment(due.len() as u64);
        due.iter().filter_map(|hash| self.remove(hash)).collect()
    }

    /// Removes the delayed transaction with the given hash, if any.
    pub(crate) fn remove(
        &mut self,
        hash: &TxHash,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let transaction = self.by_hash.remove(hash)?;
        self.by_valid_after
            .remove(&(valid_after(&transaction), *hash));
        self.by_priority
            .remove(&(transaction.transaction.priority_fee_or_price(), *hash));
        self.size -= transaction.transaction.size();
        self.txs_by_authority.remove(&transaction.transaction);
        self.update_metrics();
        Some(transaction)
    }

    /// Removes the delayed transactions with the given hashes and returns them.
    pub(crate) fn remove_transactions<'a>(
        &mut self,
        hashes: impl IntoIterator<Item = &'a TxHash>,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        if self.by_hash.is_empty() {
            return Vec::new();
        }
        hashes
            .into_iter()
            .filter_map(|hash| self.remove(hash))
            .collect()
    }

    /// Removes the delayed transactions sent by `sender` and returns them.
    pub(crate) fn remove_transactions_by_sender(
        &mut self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let hashes: Vec<_> = self
            .transactions_by_sender(sender)
            .map(|tx| *tx.hash())
            .collect();
        self.remove_transactions(&hashes)
    }

    /// Returns whether a transaction with the given hash is delayed.
    pub(crate) fn contains(&self, hash: &TxHash) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Returns the delayed transaction with the given hash.
    pub(crate) fn get(
        &self,
        hash: &TxHash,
    ) -> Option<&Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_hash.get(hash)
    }

    /// Returns all delayed transactions.
    pub(crate) fn transactions(
        &self,
    ) -> impl Iterator<Item = &Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_hash.values()
    }

    /// Returns the delayed transactions that may be propagated to peers.
    pub(crate) fn pooled_transactions(
        &self,
    ) -> impl Iterator<Item = &Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.transactions().filter(|tx| tx.propagate)
    }

    /// Appends the pooled form of the delayed, propagatable transactions among `tx_hashes` to
    /// `out`, adding their encoded length to `accumulated_size` and stopping once `limit` is
    /// exceeded.
    pub(crate) fn append_pooled_transaction_elements(
        &self,
        tx_hashes: &[TxHash],
        limit: GetPooledTransactionLimit,
        accumulated_size: &mut usize,
        out: &mut Vec<<TempoPooledTransaction as PoolTransaction>::Pooled>,
    ) {
        for hash in tx_hashes {
            let Some(tx) = self.by_hash.get(hash).filter(|tx| tx.propagate) else {
                continue;
            };
            let Some(pooled) = tx.transaction.clone_into_pooled().ok() else {
                continue;
            };
            *accumulated_size += tx.transaction.encoded_length();
            out.push(pooled.into_inner());
            if limit.exceeds(*accumulated_size) {
                break;
            }
        }
    }

    /// Returns the delayed transactions sent by `sender`.
    pub(crate) fn transactions_by_sender(
        &self,
        sender: Address,
    ) -> impl Iterator<Item = &Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.transactions().filter(move |tx| tx.sender() == sender)
    }

    /// Returns the number of delayed transactions.
    pub(crate) fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Returns the total size of delayed transactions in bytes.
    pub(crate) const fn size(&self) -> usize {
        self.size
    }

    fn update_metrics(&self) {
        self.metrics.transactions.set(self.by_hash.len() as f64);
        self.metrics.size_bytes.set(self.size as f64);
    }
}

/// Lead time and limits of the [`DelayedPool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelayedPoolConfig {
    /// A transaction is delayed while its `valid_after` is later than the tip timestamp plus this
    /// many seconds, and released by the first block that brings it within that window.
    pub lead_secs: u64,
    /// Maximum number of delayed transactions.
    pub max_count: NonZeroUsize,
    /// Maximum total size of delayed transactions in bytes.
    pub max_size: NonZeroUsize,
    /// Maximum number of delayed transactions naming the same authority, counted separately
    /// from the live sub-pools' limits; see [`TempoPooledTransaction::authorities`].
    pub max_txs_per_authority: usize,
}

impl DelayedPoolConfig {
    /// Returns whether a transaction must be delayed: it uses an expiring nonce and its
    /// `valid_after` is later than `tip_timestamp` plus the lead time. Otherwise it can enter the
    /// live sub-pools.
    pub(crate) fn should_delay(
        &self,
        transaction: &TempoPooledTransaction,
        tip_timestamp: u64,
    ) -> bool {
        transaction.is_expiring_nonce()
            && transaction
                .inner()
                .valid_after()
                .is_some_and(|valid_after| {
                    valid_after > tip_timestamp.saturating_add(self.lead_secs)
                })
    }
}

impl Default for DelayedPoolConfig {
    fn default() -> Self {
        Self {
            lead_secs: DEFAULT_DELAYED_LEAD_SECS,
            max_count: DEFAULT_DELAYED_MAX_COUNT,
            max_size: DEFAULT_DELAYED_MAX_SIZE,
            max_txs_per_authority: DEFAULT_MAX_TXS_PER_AUTHORITY,
        }
    }
}

/// Returns the timestamp a delayed transaction is indexed by in [`DelayedPool::by_valid_after`].
///
/// Delayed transactions have a `valid_after` ([`DelayedPoolConfig::should_delay`]); the zero fallback
/// only keeps the index total, making such a transaction due at once.
fn valid_after(transaction: &ValidPoolTransaction<TempoPooledTransaction>) -> u64 {
    transaction
        .transaction
        .inner()
        .valid_after()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TxBuilder, wrap_valid_tx};
    use alloy_primitives::U256;
    use reth_transaction_pool::TransactionOrigin;

    fn valid(tx: TempoPooledTransaction) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        Arc::new(wrap_valid_tx(tx, TransactionOrigin::External))
    }

    /// Returns a builder for an expiring nonce transaction from `sender`.
    fn expiring(sender: Address) -> TxBuilder {
        TxBuilder::aa(sender)
            .nonce_key(U256::MAX)
            .valid_after(105)
            .valid_before(200)
    }

    /// Inserts into `pool` and returns the hashes of the evicted transactions.
    fn insert(
        pool: &mut DelayedPool,
        tx: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    ) -> Option<Vec<TxHash>> {
        pool.insert(tx).ok().map(|evicted| hashes(&evicted))
    }

    fn hashes(txs: &[Arc<ValidPoolTransaction<TempoPooledTransaction>>]) -> Vec<TxHash> {
        txs.iter().map(|tx| *tx.hash()).collect()
    }

    #[test]
    fn should_hold_respects_lead_time() {
        let config = DelayedPoolConfig {
            lead_secs: 2,
            ..Default::default()
        };
        let sender = Address::random();
        let without_valid_after = TxBuilder::aa(sender).nonce_key(U256::MAX).valid_before(200);

        assert!(!config.should_delay(&without_valid_after.build(), 100));
        assert!(!config.should_delay(&expiring(sender).valid_after(102).build(), 100));
        assert!(config.should_delay(&expiring(sender).valid_after(103).build(), 100));
    }

    #[test_case::test_case(U256::ZERO; "protocol")]
    #[test_case::test_case(U256::ONE; "2d")]
    fn delays_only_expiring_nonce_transactions(nonce_key: U256) {
        let tx = TxBuilder::aa(Address::random())
            .nonce_key(nonce_key)
            .valid_after(1_000)
            .build();
        assert!(!DelayedPoolConfig::default().should_delay(&tx, 100));
    }

    #[test]
    fn delays_independent_expiring_nonce_transactions() {
        let mut pool = DelayedPool::default();
        let sender = Address::random();
        for valid_before in [200, 201] {
            let tx = expiring(sender).valid_before(valid_before).build();
            assert!(tx.is_expiring_nonce());
            assert_eq!(insert(&mut pool, valid(tx)), Some(Vec::new()));
        }
    }

    #[test]
    fn rejects_transaction_that_is_delayed_already() {
        let mut pool = DelayedPool::default();
        let tx = valid(expiring(Address::random()).build());
        pool.insert(Arc::clone(&tx)).unwrap();

        let err = pool.insert(tx).unwrap_err();
        assert!(matches!(err.kind, PoolErrorKind::AlreadyImported));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn limits_transactions_per_authority() {
        let mut pool = DelayedPool::new(DelayedPoolConfig {
            max_txs_per_authority: 1,
            ..Default::default()
        });
        let sender = Address::random();
        let first = valid(expiring(sender).build());
        pool.insert(Arc::clone(&first)).unwrap();

        let err = pool
            .insert(valid(expiring(sender).valid_before(201).build()))
            .unwrap_err();
        assert!(matches!(err.kind, PoolErrorKind::SpammerExceededCapacity(a) if a == sender));

        // Removing the transaction frees its authorities' slots.
        pool.remove(first.hash()).unwrap();
        pool.insert(valid(expiring(sender).valid_before(201).build()))
            .unwrap();
    }

    #[test]
    fn rejects_when_count_or_size_is_full() {
        let mut pool = DelayedPool::new(DelayedPoolConfig {
            max_count: NonZeroUsize::MIN,
            ..Default::default()
        });
        assert_eq!(
            insert(&mut pool, valid(expiring(Address::random()).build())),
            Some(Vec::new())
        );
        assert_eq!(
            insert(&mut pool, valid(expiring(Address::random()).build())),
            None
        );

        let tx = expiring(Address::random()).build();
        let mut pool = DelayedPool::new(DelayedPoolConfig {
            max_size: NonZeroUsize::new(tx.size()).unwrap(),
            ..Default::default()
        });
        assert_eq!(insert(&mut pool, valid(tx)), Some(Vec::new()));
        assert_eq!(
            insert(&mut pool, valid(expiring(Address::random()).build())),
            None
        );
    }

    #[test]
    fn take_due_removes_transactions_within_lead_time() {
        let mut pool = DelayedPool::new(DelayedPoolConfig {
            lead_secs: 2,
            ..Default::default()
        });
        let early = valid(expiring(Address::random()).build());
        let late = valid(expiring(Address::random()).valid_after(110).build());
        insert(&mut pool, Arc::clone(&late)).unwrap();
        insert(&mut pool, Arc::clone(&early)).unwrap();

        assert!(pool.take_due(102).is_empty());
        assert_eq!(hashes(&pool.take_due(103)), vec![*early.hash()]);
        assert!(!pool.contains(early.hash()));
        assert_eq!(hashes(&pool.take_due(108)), vec![*late.hash()]);
        assert_eq!((pool.len(), pool.size()), (0, 0));
    }

    #[test]
    fn remove_frees_every_index() {
        let mut pool = DelayedPool::default();
        let tx = expiring(Address::random()).build();
        let hash = *tx.hash();
        insert(&mut pool, valid(tx)).unwrap();

        assert_eq!(*pool.remove(&hash).unwrap().hash(), hash);
        assert!(!pool.contains(&hash));
        assert_eq!((pool.len(), pool.size()), (0, 0));
        assert!(pool.take_due(u64::MAX).is_empty());
    }

    #[test]
    fn evicts_lower_priority_transactions_when_full() {
        let mut pool = DelayedPool::new(DelayedPoolConfig {
            max_count: NonZeroUsize::MIN,
            ..Default::default()
        });
        let cheap = valid(
            expiring(Address::random())
                .max_priority_fee(1_000_000_000)
                .build(),
        );
        let equal = valid(
            expiring(Address::random())
                .max_priority_fee(1_000_000_000)
                .build(),
        );
        let expensive = valid(
            expiring(Address::random())
                .max_priority_fee(2_000_000_000)
                .build(),
        );
        insert(&mut pool, Arc::clone(&cheap)).unwrap();

        assert_eq!(insert(&mut pool, equal), None);
        let evicted = pool
            .insert(Arc::clone(&expensive))
            .expect("a higher priority fee evicts the cheapest delayed transaction");
        assert_eq!(hashes(&evicted), vec![*cheap.hash()]);
        assert!(!pool.contains(cheap.hash()));
        assert!(pool.contains(expensive.hash()));
        assert_eq!(pool.len(), 1);
    }
}
