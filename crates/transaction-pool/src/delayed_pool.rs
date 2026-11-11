//! Sub-pool for expiring nonce transactions whose `valid_after` is too far ahead of the tip to be
//! included soon.
//!
//! Held transactions are visible to lookups and gossip but stay out of the pending and queued
//! structures, eviction ordering and limits of the live sub-pools until pool maintenance releases
//! them shortly before `valid_after`.
//!
//! Only expiring nonce transactions are held. They are unique by their expiring nonce hash and
//! belong to no sequential nonce lane, so holding them never splits a sender's nonce sequence
//! across sub-pools. Future-dated transactions with sequential nonces enter the live sub-pools.

use crate::{metrics::DelayedPoolMetrics, transaction::TempoPooledTransaction};
use alloy_consensus::Transaction;
use alloy_primitives::{
    Address, B256, TxHash,
    map::{AddressMap, B256Map, B256Set, Entry},
};
use reth_primitives_traits::InMemorySize;
use reth_transaction_pool::{GetPooledTransactionLimit, PoolTransaction, ValidPoolTransaction};
use reth_trie_common::bundle_state::BundleAccount;
use std::{collections::BTreeSet, num::NonZeroUsize, sync::Arc};
use tempo_precompiles::NONCE_PRECOMPILE_ADDRESS;
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

/// Holds expiring nonce transactions that pass validation but whose `valid_after` is later than
/// the tip timestamp plus [`Config::lead_secs`].
#[derive(Debug, Default)]
pub struct DelayedPool {
    /// Lead time and limits.
    config: Config,
    /// Held transactions by hash.
    by_hash: B256Map<HeldTransaction>,
    /// Held transaction hash by its expiring nonce hash; there is at most one per expiring nonce.
    by_expiring_nonce: B256Map<TxHash>,
    /// Held transactions ordered by `valid_after`, for release.
    by_valid_after: BTreeSet<(u64, TxHash)>,
    /// Held transactions ordered by priority fee, lowest first, for eviction when full.
    by_priority: BTreeSet<(u128, TxHash)>,
    /// Number of held transactions per sender.
    by_sender: AddressMap<usize>,
    /// Number of held transactions that name an address as an authority other than their sender.
    ///
    /// Kept apart from [`Self::by_sender`] so that replaying an address's published authorization
    /// cannot use up that address's own sends.
    by_authority: AddressMap<usize>,
    /// Hashes handed out by [`Self::take_due`] and not yet removed.
    releasing: B256Set,
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

    /// Returns the `valid_after` of an expiring nonce transaction if it is later than
    /// `tip_timestamp` plus the lead time, meaning the transaction must be held; `None` if it can
    /// enter the live sub-pools.
    pub(crate) fn hold_until(
        &self,
        transaction: &TempoPooledTransaction,
        tip_timestamp: u64,
    ) -> Option<u64> {
        if !transaction.is_expiring_nonce() {
            return None;
        }
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
    /// validation, counted apart from the sender. The caller ensures the transaction uses an
    /// expiring nonce and that no sub-pool holds its hash.
    pub(crate) fn insert(
        &mut self,
        transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        valid_after: u64,
        mut authorities: Vec<Address>,
    ) -> Result<Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>, Error> {
        debug_assert!(transaction.transaction.is_expiring_nonce());
        let hash = *transaction.hash();
        let expiring_nonce = expiring_nonce_key(&transaction);
        if self.by_expiring_nonce.contains_key(&expiring_nonce) {
            return Err(Error::NonceConflict);
        }

        let sender = transaction.sender();
        let max_per_authority = self.config.max_per_authority.get();
        if self.by_sender.get(&sender).copied().unwrap_or_default() >= max_per_authority {
            return Err(Error::AuthorityLimit(sender));
        }
        authorities.retain(|authority| *authority != sender);
        authorities.sort_unstable();
        authorities.dedup();
        if let Some(authority) = authorities.iter().find(|authority| {
            self.by_authority
                .get(*authority)
                .copied()
                .unwrap_or_default()
                >= max_per_authority
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

        self.by_expiring_nonce.insert(expiring_nonce, hash);
        *self.by_sender.entry(sender).or_default() += 1;
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
    /// `tip_timestamp`, earliest first, skipping those an earlier call returned. They stay held
    /// until removed, so only one release revalidates each transaction.
    pub(crate) fn take_due(
        &mut self,
        tip_timestamp: u64,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let release_until = tip_timestamp.saturating_add(self.config.lead_secs);
        let due: Vec<_> = self
            .by_valid_after
            .range(..=(release_until, B256::repeat_byte(0xff)))
            .filter(|(_, hash)| !self.releasing.contains(hash))
            .map(|(_, hash)| Arc::clone(&self.by_hash[hash].transaction))
            .collect();
        self.releasing.extend(due.iter().map(|tx| *tx.hash()));
        due
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
        self.by_expiring_nonce
            .remove(&expiring_nonce_key(&transaction));
        self.by_valid_after.remove(&(valid_after, *hash));
        self.releasing.remove(hash);
        if let Entry::Occupied(mut entry) = self.by_sender.entry(transaction.sender()) {
            *entry.get_mut() -= 1;
            if *entry.get() == 0 {
                entry.remove();
            }
        }
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

    /// Removes and returns the held transactions whose expiring nonce `state` marks as seen.
    pub(crate) fn remove_consumed(
        &mut self,
        state: &AddressMap<BundleAccount>,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        if self.by_hash.is_empty() {
            return Vec::new();
        }
        let Some(nonce_state) = state.get(&NONCE_PRECOMPILE_ADDRESS) else {
            return Vec::new();
        };
        let consumed: Vec<_> = self
            .by_hash
            .iter()
            .filter(|(_, held)| {
                held.transaction
                    .transaction
                    .expiring_nonce_slot()
                    .and_then(|slot| nonce_state.storage.get(&slot))
                    .is_some_and(|seen| !seen.present_value.is_zero())
            })
            .map(|(hash, _)| *hash)
            .collect();
        self.remove_transactions(&consumed)
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
    /// Maximum number of held transactions per sender, and separately per authority recovered
    /// from held transactions' authorization lists.
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
    /// The sender already sends, or the authority is already named by, the maximum number of
    /// held transactions.
    #[error("authority {0} has the maximum number of delayed transactions")]
    AuthorityLimit(Address),
    /// A held transaction already uses this expiring nonce; held transactions cannot be replaced.
    #[error("a delayed transaction with the same expiring nonce is already held")]
    NonceConflict,
}

#[derive(Debug)]
struct HeldTransaction {
    transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    valid_after: u64,
    /// Sorted, deduplicated authorities other than the sender, counted against
    /// [`Config::max_per_authority`].
    authorities: Vec<Address>,
}

/// Returns the key a held transaction is indexed by in [`DelayedPool::by_expiring_nonce`].
///
/// Held transactions use expiring nonces, which always have an expiring nonce hash; the
/// transaction hash fallback only keeps the index total.
fn expiring_nonce_key(transaction: &ValidPoolTransaction<TempoPooledTransaction>) -> B256 {
    transaction
        .transaction
        .expiring_nonce_hash()
        .unwrap_or(*transaction.hash())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TxBuilder, wrap_valid_tx};
    use alloy_primitives::{Signature, U256, map::HashMap};
    use reth_primitives_traits::Recovered;
    use reth_transaction_pool::TransactionOrigin;
    use reth_trie_common::bundle_state::{AccountStatus, StorageSlot};
    use tempo_primitives::TempoTxEnvelope;

    fn valid(tx: TempoPooledTransaction) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        Arc::new(wrap_valid_tx(tx, TransactionOrigin::External))
    }

    /// Returns a builder for an expiring nonce transaction from `sender`.
    fn expiring(sender: Address) -> TxBuilder {
        TxBuilder::aa(sender).nonce_key(U256::MAX).valid_before(200)
    }

    /// Returns `tx` signed with another signature: a different transaction hash, but the same
    /// expiring nonce hash.
    fn resigned(tx: &TempoPooledTransaction) -> TempoPooledTransaction {
        let signed = tx
            .inner()
            .as_aa()
            .expect("AA transaction")
            .tx()
            .clone()
            .into_signed(Signature::new(U256::from(1), U256::from(2), false).into());
        TempoPooledTransaction::new(Recovered::new_unchecked(
            TempoTxEnvelope::from(signed),
            tx.sender(),
        ))
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

        assert_eq!(pool.hold_until(&expiring(sender).build(), 100), None);
        assert_eq!(
            pool.hold_until(&expiring(sender).valid_after(102).build(), 100),
            None
        );
        assert_eq!(
            pool.hold_until(&expiring(sender).valid_after(103).build(), 100),
            Some(103)
        );
    }

    #[test_case::test_case(U256::ZERO; "protocol")]
    #[test_case::test_case(U256::ONE; "2d")]
    fn holds_only_expiring_nonce_transactions(nonce_key: U256) {
        let pool = DelayedPool::default();
        let tx = TxBuilder::aa(Address::random())
            .nonce_key(nonce_key)
            .valid_after(1_000)
            .build();
        assert_eq!(pool.hold_until(&tx, 100), None);
    }

    #[test]
    fn rejects_second_transaction_for_held_expiring_nonce() {
        let mut pool = DelayedPool::default();
        let first = expiring(Address::random()).build();
        let replacement = resigned(&first);
        assert_ne!(first.hash(), replacement.hash());
        assert_eq!(
            first.expiring_nonce_hash(),
            replacement.expiring_nonce_hash()
        );

        assert_eq!(
            insert(&mut pool, valid(first), 100, Vec::new()),
            Ok(Vec::new())
        );
        assert_eq!(
            insert(&mut pool, valid(replacement), 100, Vec::new()),
            Err(Error::NonceConflict)
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn holds_independent_expiring_nonce_transactions() {
        let mut pool = DelayedPool::default();
        let sender = Address::random();
        for valid_before in [200, 201] {
            let tx = expiring(sender).valid_before(valid_before).build();
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
                valid(expiring(Address::random()).build()),
                100,
                Vec::new()
            ),
            Ok(Vec::new())
        );
        assert_eq!(
            insert(
                &mut pool,
                valid(expiring(Address::random()).build()),
                100,
                Vec::new()
            ),
            Err(Error::PoolFull)
        );

        let tx = expiring(Address::random()).build();
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
                valid(expiring(Address::random()).build()),
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
        let first = expiring(sender).build();
        let first_hash = *first.hash();

        assert_eq!(
            insert(&mut pool, valid(first), 100, vec![authority]),
            Ok(Vec::new())
        );
        assert_eq!(
            insert(&mut pool, valid(expiring(sender).build()), 100, Vec::new()),
            Err(Error::AuthorityLimit(sender))
        );
        let other_sender = expiring(Address::random()).build();
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
        let early = valid(expiring(Address::random()).build());
        let late = valid(expiring(Address::random()).build());
        insert(&mut pool, Arc::clone(&late), 110, Vec::new()).unwrap();
        insert(&mut pool, Arc::clone(&early), 105, Vec::new()).unwrap();

        assert!(pool.take_due(102).is_empty());
        assert_eq!(hashes(&pool.take_due(103)), vec![*early.hash()]);
        assert_eq!(hashes(&pool.take_due(108)), vec![*late.hash()]);
        assert_eq!(pool.len(), 2, "due must not remove transactions");
    }

    #[test]
    fn remove_frees_every_index() {
        let mut pool = DelayedPool::new(Config {
            max_per_authority: NonZeroUsize::MIN,
            ..Default::default()
        });
        let tx = expiring(Address::random()).build();
        let hash = *tx.hash();
        insert(&mut pool, valid(tx.clone()), 105, Vec::new()).unwrap();

        assert_eq!(hashes(&pool.remove_transactions([&hash])), vec![hash]);
        assert!(!pool.contains(&hash));
        assert_eq!((pool.len(), pool.size()), (0, 0));
        assert!(pool.take_due(u64::MAX).is_empty());
        assert_eq!(
            insert(&mut pool, valid(resigned(&tx)), 105, Vec::new()),
            Ok(Vec::new()),
            "the expiring nonce is free again"
        );
    }

    #[test]
    fn removes_transactions_by_sender() {
        let mut pool = DelayedPool::default();
        let sender = Address::random();
        let ours = [
            valid(expiring(sender).build()),
            valid(expiring(sender).valid_before(201).build()),
        ];
        let other = valid(expiring(Address::random()).build());
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
        let propagated = valid(expiring(Address::random()).build());
        let mut local = wrap_valid_tx(
            expiring(Address::random()).build(),
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
    fn naming_an_authority_does_not_use_up_its_own_sends() {
        let mut pool = DelayedPool::new(Config {
            max_per_authority: NonZeroUsize::MIN,
            ..Default::default()
        });
        let victim = Address::random();
        let replayed = valid(expiring(Address::random()).build());

        assert_eq!(
            insert(&mut pool, replayed, 105, vec![victim]),
            Ok(Vec::new())
        );
        assert_eq!(
            insert(&mut pool, valid(expiring(victim).build()), 105, Vec::new()),
            Ok(Vec::new())
        );
        assert_eq!(
            insert(
                &mut pool,
                valid(expiring(Address::random()).build()),
                105,
                vec![victim]
            ),
            Err(Error::AuthorityLimit(victim))
        );
    }

    #[test]
    fn take_due_hands_out_each_transaction_once() {
        let mut pool = DelayedPool::new(Config {
            lead_secs: 0,
            ..Default::default()
        });
        let first = valid(expiring(Address::random()).build());
        let second = valid(expiring(Address::random()).build());
        insert(&mut pool, Arc::clone(&first), 100, Vec::new()).unwrap();

        assert_eq!(hashes(&pool.take_due(100)), vec![*first.hash()]);
        insert(&mut pool, Arc::clone(&second), 100, Vec::new()).unwrap();
        assert_eq!(hashes(&pool.take_due(100)), vec![*second.hash()]);
        assert!(pool.take_due(100).is_empty());
        assert_eq!(pool.len(), 2, "taken transactions stay held until removed");
    }

    #[test]
    fn removes_held_transactions_whose_expiring_nonce_was_seen() {
        let mut pool = DelayedPool::default();
        let sender = Address::random();
        let seen = valid(expiring(sender).build());
        let unseen = valid(expiring(sender).valid_before(201).build());
        for tx in [&seen, &unseen] {
            insert(&mut pool, Arc::clone(tx), 105, Vec::new()).unwrap();
        }

        let mut storage = HashMap::default();
        storage.insert(
            seen.transaction.expiring_nonce_slot().unwrap(),
            StorageSlot::new_changed(U256::ZERO, U256::from(200)),
        );
        let mut state = AddressMap::default();
        state.insert(
            NONCE_PRECOMPILE_ADDRESS,
            BundleAccount::new(None, None, storage, AccountStatus::Changed),
        );

        assert_eq!(hashes(&pool.remove_consumed(&state)), vec![*seen.hash()]);
        assert!(pool.contains(unseen.hash()));
    }
}
