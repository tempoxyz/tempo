//! Sub-pool for transactions whose `valid_after` is too far ahead of the tip to be included soon.
//!
//! Held transactions are visible to lookups and gossip but stay out of the pending and queued
//! structures, eviction ordering and limits of the live sub-pools until pool maintenance releases
//! them shortly before `valid_after`.

use crate::{
    metrics::DelayedPoolMetrics,
    transaction::TempoPooledTransaction,
    tt_2d_pool::{AA2dTransactionId, AASequenceId},
};
use alloy_consensus::Transaction;
use alloy_primitives::{
    Address, B256, TxHash, U256,
    map::{AddressMap, B256Map, Entry, HashMap},
};
use reth_primitives_traits::InMemorySize;
use reth_transaction_pool::{GetPooledTransactionLimit, PoolTransaction, ValidPoolTransaction};
use std::{collections::BTreeSet, num::NonZeroUsize, sync::Arc};
use tokio::sync::mpsc;

/// Default number of seconds before `valid_after` at which a held transaction is released.
pub const DEFAULT_DELAYED_LEAD_SECS: u64 = 2;

/// Default maximum number of held transactions.
pub const DEFAULT_DELAYED_MAX_COUNT: NonZeroUsize = NonZeroUsize::new(4096).unwrap();

/// Default maximum total size of held transactions, in megabytes.
pub const DEFAULT_DELAYED_MAX_SIZE_MB: NonZeroUsize = NonZeroUsize::new(8).unwrap();

/// Default maximum number of held transactions per authority.
pub const DEFAULT_DELAYED_MAX_PER_AUTHORITY: NonZeroUsize = NonZeroUsize::new(4).unwrap();

/// Bytes in a megabyte, for converting size limits given in megabytes.
pub const BYTES_PER_MB: NonZeroUsize = NonZeroUsize::new(1024 * 1024).unwrap();

/// Bound on hashes buffered per listener of newly held transactions.
const HELD_LISTENER_BUFFER_SIZE: usize = 2048;

/// Holds transactions that pass validation but whose `valid_after` is later than the tip
/// timestamp plus [`Config::lead_secs`].
#[derive(Debug, Default)]
pub struct DelayedPool {
    /// Lead time and limits.
    config: Config,
    /// Held transactions by hash.
    by_hash: B256Map<HeldTransaction>,
    /// Held transaction hash by the nonce it uses; there is at most one per nonce.
    by_nonce: HashMap<HeldNonce, TxHash>,
    /// Held transactions ordered by `valid_after`, for release.
    by_valid_after: BTreeSet<(u64, TxHash)>,
    /// Held transactions ordered by priority fee, lowest first, for eviction when full.
    by_priority: BTreeSet<(u128, TxHash)>,
    /// Number of held transactions per authority.
    by_authority: AddressMap<usize>,
    /// Total size of held transactions in bytes.
    size: usize,
    /// Receive the hashes of propagatable transactions as they are held.
    held_listeners: Vec<mpsc::Sender<TxHash>>,
    /// Metrics for held transactions.
    metrics: DelayedPoolMetrics,
}

impl DelayedPool {
    /// Creates an empty pool with the given config.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    /// Returns the metrics for held transactions.
    pub(crate) const fn metrics(&self) -> &DelayedPoolMetrics {
        &self.metrics
    }

    /// Returns the transaction's `valid_after` if it is later than `tip_timestamp` plus the lead
    /// time, meaning the transaction must be held; `None` if it can enter the live sub-pools.
    pub(crate) fn hold_until(
        &self,
        transaction: &TempoPooledTransaction,
        tip_timestamp: u64,
    ) -> Option<u64> {
        transaction.inner().valid_after().filter(|valid_after| {
            *valid_after > tip_timestamp.saturating_add(self.config.lead_secs)
        })
    }

    /// Holds a validated transaction until `valid_after` and returns the held transactions it
    /// evicted.
    ///
    /// When the pool is full, the lowest-priority held transactions are evicted to make room,
    /// but only for a transaction whose priority fee is higher than each of theirs; otherwise it
    /// is rejected with [`Error::PoolFull`]. `authorities` are the authorities recovered during
    /// validation; the sender always counts as one. The caller ensures no sub-pool holds the
    /// transaction's hash.
    pub(crate) fn insert(
        &mut self,
        transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        valid_after: u64,
        mut authorities: Vec<Address>,
    ) -> Result<Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>, Error> {
        let hash = *transaction.hash();
        let held_nonce = HeldNonce::of(&transaction.transaction);
        if self.by_nonce.contains_key(&held_nonce) {
            return Err(Error::NonceConflict);
        }

        authorities.push(transaction.sender());
        authorities.sort_unstable();
        authorities.dedup();
        if let Some(authority) = authorities.iter().find(|authority| {
            self.by_authority
                .get(*authority)
                .copied()
                .unwrap_or_default()
                >= self.config.max_per_authority.get()
        }) {
            return Err(Error::AuthorityLimit(*authority));
        }

        let tx_size = transaction.transaction.size();
        let max_size = self.config.max_size.get();
        if tx_size > max_size {
            return Err(Error::PoolFull);
        }
        let priority = transaction.transaction.priority_fee_or_price();
        let (mut count, mut size) = (self.by_hash.len(), self.size);
        let mut to_evict = Vec::new();
        for (evict_priority, evict_hash) in &self.by_priority {
            if count < self.config.max_count.get() && size + tx_size <= max_size {
                break;
            }
            if *evict_priority >= priority {
                return Err(Error::PoolFull);
            }
            count -= 1;
            size -= self.by_hash[evict_hash].transaction.transaction.size();
            to_evict.push(*evict_hash);
        }
        let evicted = to_evict
            .iter()
            .filter_map(|evict_hash| self.remove(evict_hash))
            .collect();

        self.by_nonce.insert(held_nonce, hash);
        for authority in &authorities {
            *self.by_authority.entry(*authority).or_default() += 1;
        }
        self.by_valid_after.insert((valid_after, hash));
        self.by_priority.insert((priority, hash));
        self.size += tx_size;

        if transaction.propagate {
            self.held_listeners
                .retain(|listener| match listener.try_send(hash) {
                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
                    Err(mpsc::error::TrySendError::Closed(_)) => false,
                });
        }

        self.by_hash.insert(
            hash,
            HeldTransaction {
                transaction,
                valid_after,
                authorities,
            },
        );
        self.update_metrics();
        Ok(evicted)
    }

    /// Returns held transactions whose `valid_after` is within the lead time of
    /// `tip_timestamp`, earliest first. They stay held until removed.
    pub(crate) fn due(
        &self,
        tip_timestamp: u64,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let release_until = tip_timestamp.saturating_add(self.config.lead_secs);
        self.by_valid_after
            .range(..=(release_until, B256::repeat_byte(0xff)))
            .map(|(_, hash)| Arc::clone(&self.by_hash[hash].transaction))
            .collect()
    }

    /// Removes the held transaction with the given hash, if any.
    pub(crate) fn remove(
        &mut self,
        hash: &TxHash,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let HeldTransaction {
            transaction,
            valid_after,
            authorities,
        } = self.by_hash.remove(hash)?;
        self.by_nonce
            .remove(&HeldNonce::of(&transaction.transaction));
        self.by_valid_after.remove(&(valid_after, *hash));
        self.by_priority
            .remove(&(transaction.transaction.priority_fee_or_price(), *hash));
        for authority in &authorities {
            if let Entry::Occupied(mut entry) = self.by_authority.entry(*authority) {
                *entry.get_mut() -= 1;
                if *entry.get() == 0 {
                    entry.remove();
                }
            }
        }
        self.size -= transaction.transaction.size();
        self.update_metrics();
        Some(transaction)
    }

    /// Removes the held transactions with the given hashes and returns them.
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

    /// Removes the held transactions sent by `sender` and returns them.
    pub(crate) fn remove_transactions_by_sender(
        &mut self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let hashes: Vec<_> = self
            .by_hash
            .iter()
            .filter(|(_, held)| held.transaction.sender() == sender)
            .map(|(hash, _)| *hash)
            .collect();
        self.remove_transactions(&hashes)
    }

    /// Returns whether a transaction with the given hash is held.
    pub(crate) fn contains(&self, hash: &TxHash) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Returns the held transaction with the given hash.
    pub(crate) fn get(
        &self,
        hash: &TxHash,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_hash
            .get(hash)
            .map(|held| Arc::clone(&held.transaction))
    }

    /// Returns the held transaction from `sender` at `nonce` in the `nonce_key` lane, zero
    /// for protocol nonces.
    pub(crate) fn get_by_nonce(
        &self,
        sender: Address,
        nonce_key: U256,
        nonce: u64,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let id = AA2dTransactionId::new(AASequenceId::new(sender, nonce_key), nonce);
        self.by_nonce
            .get(&HeldNonce::Sequence(id))
            .and_then(|hash| self.get(hash))
    }

    /// Returns all held transactions.
    pub(crate) fn transactions(
        &self,
    ) -> impl Iterator<Item = &Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_hash.values().map(|held| &held.transaction)
    }

    /// Returns the held transactions that may be propagated to peers.
    pub(crate) fn pooled_transactions(
        &self,
    ) -> impl Iterator<Item = &Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.transactions().filter(|tx| tx.propagate)
    }

    /// Appends the pooled form of the held, propagatable transactions among `tx_hashes` to
    /// `out`, adding their encoded length to `accumulated_size` and stopping once `limit` is
    /// exceeded.
    pub(crate) fn append_pooled_transaction_elements<'a>(
        &self,
        tx_hashes: impl IntoIterator<Item = &'a TxHash>,
        limit: GetPooledTransactionLimit,
        accumulated_size: &mut usize,
        out: &mut Vec<<TempoPooledTransaction as PoolTransaction>::Pooled>,
    ) {
        if self.by_hash.is_empty() {
            return;
        }
        for hash in tx_hashes {
            let Some(held) = self
                .by_hash
                .get(hash)
                .filter(|held| held.transaction.propagate)
            else {
                continue;
            };
            let Some(pooled) = held.transaction.transaction.clone_into_pooled().ok() else {
                continue;
            };
            *accumulated_size += held.transaction.transaction.encoded_length();
            out.push(pooled.into_inner());
            if limit.exceeds(*accumulated_size) {
                break;
            }
        }
    }

    /// Returns the number of held transactions.
    pub(crate) fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Returns the total size of held transactions in bytes.
    pub(crate) const fn size(&self) -> usize {
        self.size
    }

    /// Returns a receiver of the hashes of propagatable transactions as they are held.
    ///
    /// Hashes are dropped while the receiver's buffer is full.
    pub(crate) fn held_transactions_listener(&mut self) -> mpsc::Receiver<TxHash> {
        let (sender, receiver) = mpsc::channel(HELD_LISTENER_BUFFER_SIZE);
        self.held_listeners.retain(|listener| !listener.is_closed());
        self.held_listeners.push(sender);
        receiver
    }

    fn update_metrics(&self) {
        self.metrics.transactions.set(self.by_hash.len() as f64);
        self.metrics.size_bytes.set(self.size as f64);
    }
}

/// Lead time and limits of the [`DelayedPool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// A transaction is held while its `valid_after` is later than the tip timestamp plus this
    /// many seconds, and released by the first block that brings it within that window.
    pub lead_secs: u64,
    /// Maximum number of held transactions.
    pub max_count: NonZeroUsize,
    /// Maximum total size of held transactions in bytes.
    pub max_size: NonZeroUsize,
    /// Maximum number of held transactions per authority: the sender and every authority
    /// recovered from the transaction's authorization lists.
    pub max_per_authority: NonZeroUsize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lead_secs: DEFAULT_DELAYED_LEAD_SECS,
            max_count: DEFAULT_DELAYED_MAX_COUNT,
            max_size: DEFAULT_DELAYED_MAX_SIZE_MB.saturating_mul(BYTES_PER_MB),
            max_per_authority: DEFAULT_DELAYED_MAX_PER_AUTHORITY,
        }
    }
}

/// Why the [`DelayedPool`] rejected a transaction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The pool holds the maximum number or total size of transactions, none of them with a
    /// lower priority fee than the rejected one.
    #[error("delayed transaction pool is full")]
    PoolFull,
    /// The authority already has the maximum number of held transactions.
    #[error("authority {0} has the maximum number of delayed transactions")]
    AuthorityLimit(Address),
    /// A held transaction already uses this nonce; held transactions cannot be replaced.
    #[error("a delayed transaction with the same nonce is already held")]
    NonceConflict,
}

#[derive(Debug)]
struct HeldTransaction {
    transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    valid_after: u64,
    /// Sorted, deduplicated authorities counted against [`Config::max_per_authority`].
    authorities: Vec<Address>,
}

/// The nonce a held transaction consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HeldNonce {
    /// Sender, nonce key (zero for protocol nonces) and nonce.
    Sequence(AA2dTransactionId),
    /// Expiring nonce hash.
    Expiring(B256),
}

impl HeldNonce {
    fn of(transaction: &TempoPooledTransaction) -> Self {
        if transaction.is_expiring_nonce()
            && let Some(hash) = transaction.expiring_nonce_hash()
        {
            return Self::Expiring(hash);
        }
        Self::Sequence(AA2dTransactionId::new(
            AASequenceId::new(
                transaction.sender(),
                transaction.nonce_key().unwrap_or_default(),
            ),
            transaction.nonce(),
        ))
    }
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

    /// Inserts into `pool` and returns the hashes of the evicted transactions.
    fn insert(
        pool: &mut DelayedPool,
        tx: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        valid_after: u64,
        authorities: Vec<Address>,
    ) -> Result<Vec<TxHash>, Error> {
        pool.insert(tx, valid_after, authorities)
            .map(|evicted| hashes(&evicted))
    }

    fn hashes(txs: &[Arc<ValidPoolTransaction<TempoPooledTransaction>>]) -> Vec<TxHash> {
        txs.iter().map(|tx| *tx.hash()).collect()
    }

    #[test]
    fn hold_until_respects_lead_time() {
        let pool = DelayedPool::new(Config {
            lead_secs: 2,
            ..Default::default()
        });
        let sender = Address::random();

        assert_eq!(pool.hold_until(&TxBuilder::aa(sender).build(), 100), None);
        assert_eq!(
            pool.hold_until(&TxBuilder::aa(sender).valid_after(102).build(), 100),
            None
        );
        assert_eq!(
            pool.hold_until(&TxBuilder::aa(sender).valid_after(103).build(), 100),
            Some(103)
        );
    }

    #[test_case::test_case(U256::ZERO; "protocol")]
    #[test_case::test_case(U256::ONE; "2d")]
    fn rejects_second_transaction_for_held_nonce(nonce_key: U256) {
        let mut pool = DelayedPool::default();
        let sender = Address::random();
        let first = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let replacement = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .max_priority_fee(10_000_000_000)
            .build();
        let next = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build();

        assert_eq!(
            insert(&mut pool, valid(first), 100, Vec::new()),
            Ok(Vec::new())
        );
        assert_eq!(
            insert(&mut pool, valid(replacement), 100, Vec::new()),
            Err(Error::NonceConflict)
        );
        assert_eq!(
            insert(&mut pool, valid(next), 100, Vec::new()),
            Ok(Vec::new())
        );
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn holds_independent_expiring_nonce_transactions() {
        let mut pool = DelayedPool::default();
        let sender = Address::random();
        for valid_before in [200, 201] {
            let tx = TxBuilder::aa(sender)
                .nonce_key(U256::MAX)
                .valid_before(valid_before)
                .build();
            assert!(tx.is_expiring_nonce());
            assert_eq!(
                insert(&mut pool, valid(tx), 100, Vec::new()),
                Ok(Vec::new())
            );
        }
    }

    #[test]
    fn rejects_when_count_or_size_is_full() {
        let mut pool = DelayedPool::new(Config {
            max_count: NonZeroUsize::MIN,
            ..Default::default()
        });
        assert_eq!(
            insert(
                &mut pool,
                valid(TxBuilder::aa(Address::random()).build()),
                100,
                Vec::new()
            ),
            Ok(Vec::new())
        );
        assert_eq!(
            insert(
                &mut pool,
                valid(TxBuilder::aa(Address::random()).build()),
                100,
                Vec::new()
            ),
            Err(Error::PoolFull)
        );

        let tx = TxBuilder::aa(Address::random()).build();
        let mut pool = DelayedPool::new(Config {
            max_size: NonZeroUsize::new(tx.size()).unwrap(),
            ..Default::default()
        });
        assert_eq!(
            insert(&mut pool, valid(tx), 100, Vec::new()),
            Ok(Vec::new())
        );
        assert_eq!(
            insert(
                &mut pool,
                valid(TxBuilder::aa(Address::random()).build()),
                100,
                Vec::new()
            ),
            Err(Error::PoolFull)
        );
    }

    #[test]
    fn limits_transactions_per_authority() {
        let mut pool = DelayedPool::new(Config {
            max_per_authority: NonZeroUsize::MIN,
            ..Default::default()
        });
        let sender = Address::random();
        let authority = Address::random();
        let first = TxBuilder::aa(sender).build();
        let first_hash = *first.hash();

        assert_eq!(
            insert(&mut pool, valid(first), 100, vec![authority]),
            Ok(Vec::new())
        );
        assert_eq!(
            insert(
                &mut pool,
                valid(TxBuilder::aa(sender).nonce(1).build()),
                100,
                Vec::new()
            ),
            Err(Error::AuthorityLimit(sender))
        );
        let other_sender = TxBuilder::aa(Address::random()).build();
        assert_eq!(
            insert(&mut pool, valid(other_sender.clone()), 100, vec![authority]),
            Err(Error::AuthorityLimit(authority))
        );

        pool.remove(&first_hash).expect("first transaction is held");
        assert_eq!(
            insert(&mut pool, valid(other_sender), 100, vec![authority]),
            Ok(Vec::new())
        );
    }

    #[test]
    fn due_returns_transactions_within_lead_time() {
        let mut pool = DelayedPool::new(Config {
            lead_secs: 2,
            ..Default::default()
        });
        let early = valid(TxBuilder::aa(Address::random()).build());
        let late = valid(TxBuilder::aa(Address::random()).build());
        insert(&mut pool, Arc::clone(&late), 110, Vec::new()).unwrap();
        insert(&mut pool, Arc::clone(&early), 105, Vec::new()).unwrap();

        assert!(pool.due(102).is_empty());
        assert_eq!(hashes(&pool.due(103)), vec![*early.hash()]);
        assert_eq!(hashes(&pool.due(108)), vec![*early.hash(), *late.hash()]);
        assert_eq!(pool.len(), 2, "due must not remove transactions");
    }

    #[test]
    fn remove_frees_every_index() {
        let mut pool = DelayedPool::new(Config {
            max_per_authority: NonZeroUsize::MIN,
            ..Default::default()
        });
        let sender = Address::random();
        let tx = TxBuilder::aa(sender).build();
        let hash = *tx.hash();
        insert(&mut pool, valid(tx.clone()), 105, Vec::new()).unwrap();

        assert_eq!(hashes(&pool.remove_transactions([&hash])), vec![hash]);
        assert!(!pool.contains(&hash));
        assert_eq!((pool.len(), pool.size()), (0, 0));
        assert!(pool.due(u64::MAX).is_empty());
        assert_eq!(
            insert(&mut pool, valid(tx), 105, Vec::new()),
            Ok(Vec::new())
        );
    }

    #[test]
    fn removes_transactions_by_sender() {
        let mut pool = DelayedPool::default();
        let sender = Address::random();
        let ours = [
            valid(TxBuilder::aa(sender).build()),
            valid(TxBuilder::aa(sender).nonce_key(U256::ONE).build()),
        ];
        let other = valid(TxBuilder::aa(Address::random()).build());
        for tx in ours.iter().chain([&other]) {
            insert(&mut pool, Arc::clone(tx), 105, Vec::new()).unwrap();
        }

        let mut removed = hashes(&pool.remove_transactions_by_sender(sender));
        removed.sort();
        let mut expected = hashes(&ours);
        expected.sort();
        assert_eq!(removed, expected);
        assert_eq!(
            hashes(&pool.transactions().cloned().collect::<Vec<_>>()),
            vec![*other.hash()]
        );
    }

    #[test]
    fn notifies_listeners_of_propagatable_transactions() {
        let mut pool = DelayedPool::default();
        let mut listener = pool.held_transactions_listener();
        let propagated = valid(TxBuilder::aa(Address::random()).build());
        let mut local = wrap_valid_tx(
            TxBuilder::aa(Address::random()).build(),
            TransactionOrigin::Local,
        );
        local.propagate = false;

        insert(&mut pool, Arc::clone(&propagated), 105, Vec::new()).unwrap();
        insert(&mut pool, Arc::new(local), 105, Vec::new()).unwrap();

        assert_eq!(listener.try_recv(), Ok(*propagated.hash()));
        assert_eq!(listener.try_recv(), Err(mpsc::error::TryRecvError::Empty));
        assert_eq!(pool.pooled_transactions().count(), 1);
    }

    #[test]
    fn evicts_lower_priority_transactions_when_full() {
        let mut pool = DelayedPool::new(Config {
            max_count: NonZeroUsize::MIN,
            ..Default::default()
        });
        let cheap = valid(
            TxBuilder::aa(Address::random())
                .max_priority_fee(1_000_000_000)
                .build(),
        );
        let equal = valid(
            TxBuilder::aa(Address::random())
                .max_priority_fee(1_000_000_000)
                .build(),
        );
        let expensive = valid(
            TxBuilder::aa(Address::random())
                .max_priority_fee(2_000_000_000)
                .build(),
        );
        insert(&mut pool, Arc::clone(&cheap), 105, Vec::new()).unwrap();

        assert_eq!(
            insert(&mut pool, equal, 105, Vec::new()),
            Err(Error::PoolFull)
        );
        let evicted = pool
            .insert(Arc::clone(&expensive), 105, Vec::new())
            .expect("a higher priority fee evicts the cheapest held transaction");
        assert_eq!(hashes(&evicted), vec![*cheap.hash()]);
        assert!(!pool.contains(cheap.hash()));
        assert!(pool.contains(expensive.hash()));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn looks_up_held_transactions_by_nonce() {
        let mut pool = DelayedPool::default();
        let sender = Address::random();
        let protocol = valid(TxBuilder::aa(sender).nonce(3).build());
        let lane = valid(TxBuilder::aa(sender).nonce_key(U256::ONE).nonce(3).build());
        insert(&mut pool, Arc::clone(&protocol), 105, Vec::new()).unwrap();
        insert(&mut pool, Arc::clone(&lane), 105, Vec::new()).unwrap();

        let hash_at = |nonce_key, nonce| {
            pool.get_by_nonce(sender, nonce_key, nonce)
                .map(|tx| *tx.hash())
        };
        assert_eq!(hash_at(U256::ZERO, 3), Some(*protocol.hash()));
        assert_eq!(hash_at(U256::ONE, 3), Some(*lane.hash()));
        assert_eq!(hash_at(U256::ZERO, 2), None);
    }
}
