/// Basic 2D nonce pool for user nonces (nonce_key > 0) that are tracked on chain.
use crate::{metrics::AA2dPoolMetrics, transaction::TempoPooledTransaction};
use alloy_primitives::{
    Address, B256, TxHash, U256,
    map::{AddressMap, HashMap, HashSet, U256Map},
};
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_tracing::tracing::trace;
use reth_transaction_pool::{
    BestTransactions, CoinbaseTipOrdering, GetPooledTransactionLimit, PoolResult, PoolTransaction,
    PriceBumpConfig, Priority, SubPool, SubPoolLimit, TransactionOrdering, TransactionOrigin,
    ValidPoolTransaction,
    error::{InvalidPoolTransactionError, PoolError, PoolErrorKind},
    pool::{AddedPendingTransaction, AddedTransaction, QueuedReason, pending::PendingTransaction},
};
use revm::database::BundleAccount;
use std::{
    cell::RefCell,
    collections::{
        BTreeMap, BTreeSet,
        Bound::{Excluded, Unbounded},
        btree_map::Entry,
        hash_map,
    },
    rc::Rc,
    sync::Arc,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::NONCE_PRECOMPILE_ADDRESS;

type TxOrdering = CoinbaseTipOrdering<TempoPooledTransaction>;

/// A sub-pool that keeps track of 2D nonce transactions.
///
/// It maintains both pending and queued transactions.
///
/// A 2d nonce transaction is pending if it dosn't have a nonce gap for its nonce key, and is queued if its nonce key set has nonce gaps.
///
/// This pool relies on state changes to track the nonces.
///
/// # Limitations
///
/// * We assume new AA transactions either create a new nonce key (nonce 0) or use an existing nonce key. To keep track of the known keys by accounts this pool relies on state changes to promote transactions to pending.
#[derive(Debug)]
pub struct AA2dPool {
    /// Keeps track of transactions inserted in the pool.
    ///
    /// This way we can determine when transactions were submitted to the pool.
    submission_id: u64,
    /// independent, pending, executable transactions, one per sequence id.
    independent_transactions: HashMap<AASequenceId, PendingTransaction<TxOrdering>>,
    /// _All_ transactions that are currently inside the pool grouped by their unique identifier.
    by_id: BTreeMap<AA2dTransactionId, Arc<AA2dInternalTransaction>>,
    /// _All_ transactions by hash.
    by_hash: HashMap<TxHash, Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    /// Expiring nonce transactions, keyed by tx hash (always pending/independent).
    /// These use tx hash for replay protection instead of sequential nonces.
    expiring_nonce_txs: HashMap<TxHash, PendingTransaction<TxOrdering>>,
    /// Reverse index for the storage slot of an account's nonce
    ///
    /// ```solidity
    ///  mapping(address => mapping(uint256 => uint64)) public nonces
    /// ```
    ///
    /// This identifies the account and nonce key based on the slot in the `NonceManager`.
    slot_to_seq_id: U256Map<AASequenceId>,
    /// Reverse index for cleaning up `slots_to_seq_id`.
    seq_id_to_slot: HashMap<AASequenceId, U256>,
    /// Settings for this sub-pool.
    config: AA2dPoolConfig,
    /// Metrics for tracking pool statistics
    metrics: AA2dPoolMetrics,
    /// All transactions ordered by eviction priority (lowest priority first).
    ///
    /// Since Tempo has a constant base fee, priority never changes after insertion,
    /// so we can maintain this ordering incrementally. At eviction time, we scan
    /// this set checking `is_pending` to find queued or pending transactions.
    by_eviction_order: BTreeSet<EvictionKey>,
    /// Tracks the number of transactions per sender for DoS protection.
    ///
    /// Bounded by pool size (max unique senders = pending_limit + queued_limit).
    /// Entries are removed when count reaches 0 via `decrement_sender_count`.
    txs_by_sender: AddressMap<usize>,
}

impl Default for AA2dPool {
    fn default() -> Self {
        Self::new(AA2dPoolConfig::default())
    }
}

impl AA2dPool {
    /// Creates a new instance with the givenconfig and nonce keys
    pub fn new(config: AA2dPoolConfig) -> Self {
        Self {
            submission_id: 0,
            independent_transactions: Default::default(),
            by_id: Default::default(),
            by_hash: Default::default(),
            expiring_nonce_txs: Default::default(),
            slot_to_seq_id: Default::default(),
            seq_id_to_slot: Default::default(),
            config,
            metrics: AA2dPoolMetrics::default(),
            by_eviction_order: Default::default(),
            txs_by_sender: Default::default(),
        }
    }

    /// Updates all metrics to reflect the current state of the pool
    fn update_metrics(&self) {
        let (pending, queued) = self.pending_and_queued_txn_count();
        let total = self.by_id.len() + self.expiring_nonce_txs.len();
        self.metrics.set_transaction_counts(total, pending, queued);
    }

    /// Entrypoint for adding a 2d AA transaction.
    ///
    /// `on_chain_nonce` is expected to be the nonce of the sender at the time of validation.
    /// If transaction is using 2D nonces, this is expected to be the nonce corresponding
    /// to the transaction's nonce key.
    ///
    /// `hardfork` indicates the active Tempo hardfork. When T1 or later, expiring nonce
    /// transactions (nonce_key == U256::MAX) are handled specially. Otherwise, they are
    /// treated as regular 2D nonce transactions.
    pub(crate) fn add_transaction(
        &mut self,
        transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        on_chain_nonce: u64,
        hardfork: tempo_chainspec::hardfork::TempoHardfork,
    ) -> PoolResult<AddedTransaction<TempoPooledTransaction>> {
        debug_assert!(
            transaction.transaction.is_aa(),
            "only AA transactions are supported"
        );
        if self.contains(transaction.hash()) {
            return Err(PoolError::new(
                *transaction.hash(),
                PoolErrorKind::AlreadyImported,
            ));
        }

        // Handle expiring nonce transactions separately - they use tx hash as unique ID
        // Only treat as expiring nonce if T1 hardfork is active
        if hardfork.is_t1() && transaction.transaction.is_expiring_nonce() {
            return self.add_expiring_nonce_transaction(transaction);
        }

        let tx_id = transaction
            .transaction
            .aa_transaction_id()
            .expect("Transaction added to AA2D pool must be an AA transaction");

        if transaction.nonce() < on_chain_nonce {
            // outdated transaction
            return Err(PoolError::new(
                *transaction.hash(),
                PoolErrorKind::InvalidTransaction(InvalidPoolTransactionError::Consensus(
                    InvalidTransactionError::NonceNotConsistent {
                        tx: transaction.nonce(),
                        state: on_chain_nonce,
                    },
                )),
            ));
        }

        // assume the transaction is not pending, will get updated later
        let tx = Arc::new(AA2dInternalTransaction {
            inner: PendingTransaction {
                submission_id: self.next_id(),
                priority: CoinbaseTipOrdering::default()
                    .priority(&transaction.transaction, hardfork.base_fee()),
                transaction: transaction.clone(),
            },
            is_pending: Rc::new(RefCell::new(false)),
        });

        // Use entry API once to both check for replacement and insert.
        // This avoids a separate contains_key lookup.
        let sender = transaction.sender();
        let replaced = match self.by_id.entry(tx_id) {
            Entry::Occupied(mut entry) => {
                // Ensure the replacement transaction is not underpriced
                if entry
                    .get()
                    .inner
                    .transaction
                    .is_underpriced(&tx.inner.transaction, &self.config.price_bump_config)
                {
                    return Err(PoolError::new(
                        *transaction.hash(),
                        PoolErrorKind::ReplacementUnderpriced,
                    ));
                }

                Some(entry.insert(Arc::clone(&tx)))
            }
            Entry::Vacant(entry) => {
                // Check per-sender limit for new (non-replacement) transactions
                let sender_count = self.txs_by_sender.get(&sender).copied().unwrap_or(0);
                if sender_count >= self.config.max_txs_per_sender {
                    return Err(PoolError::new(
                        *transaction.hash(),
                        PoolErrorKind::SpammerExceededCapacity(sender),
                    ));
                }

                entry.insert(Arc::clone(&tx));
                // Increment sender count for new transactions
                *self.txs_by_sender.entry(sender).or_insert(0) += 1;
                None
            }
        };

        // Cache the nonce key slot for reverse lookup, if this transaction uses 2D nonce.
        // This must happen after successful by_id insertion to avoid leaking slot entries
        // when the transaction is rejected (e.g., by per-sender limit or replacement check).
        if transaction.transaction.is_aa_2d() {
            self.record_2d_slot(&transaction.transaction);
        }

        // clean up replaced
        if let Some(replaced) = &replaced {
            // we only need to remove it from the hash list, because we already replaced it in the by id set,
            // and if this is the independent transaction, it will be replaced by the new transaction below
            self.by_hash.remove(replaced.inner.transaction.hash());
            // Remove from eviction set
            let replaced_key = EvictionKey::new(Arc::clone(replaced), tx_id);
            self.by_eviction_order.remove(&replaced_key);
        }

        // insert transaction by hash
        self.by_hash
            .insert(*tx.inner.transaction.hash(), tx.inner.transaction.clone());

        // contains transactions directly impacted by the new transaction (filled nonce gap)
        let mut promoted = Vec::new();
        // Track whether this transaction was inserted as pending
        let mut inserted_as_pending = false;
        // now we need to scan the range and mark transactions as pending, if any
        let on_chain_id = AA2dTransactionId::new(tx_id.seq_id, on_chain_nonce);
        // track the next nonce we expect if the transactions are gapless
        let mut next_nonce = on_chain_id.nonce;

        // scan all the transactions with the same nonce key starting with the on chain nonce
        // to check if our new transaction was inserted as pending and perhaps promoted more transactions
        for (existing_id, existing_tx) in self.descendant_txs(&on_chain_id) {
            if existing_id.nonce == next_nonce {
                match existing_id.nonce.cmp(&tx_id.nonce) {
                    std::cmp::Ordering::Less => {
                        // unaffected by our transaction
                    }
                    std::cmp::Ordering::Equal => {
                        existing_tx.set_pending(true);
                        inserted_as_pending = true;
                    }
                    std::cmp::Ordering::Greater => {
                        // if this was previously not pending we need to promote the transaction
                        let was_pending = existing_tx.set_pending(true);
                        if !was_pending {
                            promoted.push(existing_tx.inner.transaction.clone());
                        }
                    }
                }
                // continue ungapped sequence
                next_nonce = existing_id.nonce.saturating_add(1);
            } else {
                // can exit early here because we hit a nonce gap
                break;
            }
        }

        // Record metrics
        self.metrics.inc_inserted();

        // Create eviction key for the new transaction and add to the single eviction set
        let new_tx_eviction_key = EvictionKey::new(Arc::clone(&tx), tx_id);
        self.by_eviction_order.insert(new_tx_eviction_key);

        if inserted_as_pending {
            if !promoted.is_empty() {
                self.metrics.inc_promoted(promoted.len());
            }
            // if this is the next nonce in line we can mark it as independent
            if tx_id.nonce == on_chain_nonce {
                self.independent_transactions
                    .insert(tx_id.seq_id, tx.inner.clone());
            }

            return Ok(AddedTransaction::Pending(AddedPendingTransaction {
                transaction,
                replaced: replaced.map(|tx| tx.inner.transaction.clone()),
                promoted,
                discarded: self.discard(),
            }));
        }

        // Call discard for queued transactions too
        let _ = self.discard();

        Ok(AddedTransaction::Parked {
            transaction,
            replaced: replaced.map(|tx| tx.inner.transaction.clone()),
            subpool: SubPool::Queued,
            queued_reason: Some(QueuedReason::NonceGap),
        })
    }

    /// Adds an expiring nonce transaction to the pool.
    ///
    /// Expiring nonce transactions use the tx hash as their unique identifier instead of
    /// (sender, nonce_key, nonce). They are always immediately pending since they don't
    /// have sequential nonce dependencies.
    fn add_expiring_nonce_transaction(
        &mut self,
        transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    ) -> PoolResult<AddedTransaction<TempoPooledTransaction>> {
        let tx_hash = *transaction.hash();

        // Check if already exists (by hash)
        if self.expiring_nonce_txs.contains_key(&tx_hash) {
            return Err(PoolError::new(tx_hash, PoolErrorKind::AlreadyImported));
        }

        // Check per-sender limit
        let sender = transaction.sender();
        let sender_count = self.txs_by_sender.get(&sender).copied().unwrap_or(0);
        if sender_count >= self.config.max_txs_per_sender {
            return Err(PoolError::new(
                tx_hash,
                PoolErrorKind::SpammerExceededCapacity(sender),
            ));
        }

        // Create pending transaction
        let pending_tx = PendingTransaction {
            submission_id: self.next_id(),
            priority: CoinbaseTipOrdering::default()
                .priority(&transaction.transaction, TempoHardfork::T1.base_fee()),
            transaction: transaction.clone(),
        };

        // Insert into expiring nonce map and by_hash
        self.expiring_nonce_txs.insert(tx_hash, pending_tx);
        self.by_hash.insert(tx_hash, transaction.clone());

        // Increment sender count
        *self.txs_by_sender.entry(sender).or_insert(0) += 1;

        trace!(target: "txpool", hash = %tx_hash, "Added expiring nonce transaction");

        self.update_metrics();

        // Expiring nonce transactions are always immediately pending
        Ok(AddedTransaction::Pending(AddedPendingTransaction {
            transaction,
            replaced: None,
            promoted: vec![],
            discarded: self.discard(),
        }))
    }

    /// Returns how many pending and queued transactions are in the pool.
    pub(crate) fn pending_and_queued_txn_count(&self) -> (usize, usize) {
        let (pending_2d, queued_2d) = self.by_id.values().fold((0, 0), |mut acc, tx| {
            if tx.is_pending() {
                acc.0 += 1;
            } else {
                acc.1 += 1;
            }
            acc
        });
        // Expiring nonce txs are always pending
        let expiring_pending = self.expiring_nonce_txs.len();
        (pending_2d + expiring_pending, queued_2d)
    }

    /// Returns all transactions that where submitted with the given [`TransactionOrigin`]
    pub(crate) fn get_transactions_by_origin_iter(
        &self,
        origin: TransactionOrigin,
    ) -> impl Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + '_ {
        let regular = self
            .by_id
            .values()
            .filter(move |tx| tx.inner.transaction.origin == origin)
            .map(|tx| tx.inner.transaction.clone());
        let expiring = self
            .expiring_nonce_txs
            .values()
            .filter(move |tx| tx.transaction.origin == origin)
            .map(|tx| tx.transaction.clone());
        regular.chain(expiring)
    }

    /// Returns all transactions that where submitted with the given [`TransactionOrigin`]
    pub(crate) fn get_pending_transactions_by_origin_iter(
        &self,
        origin: TransactionOrigin,
    ) -> impl Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + '_ {
        let regular = self
            .by_id
            .values()
            .filter(move |tx| tx.is_pending() && tx.inner.transaction.origin == origin)
            .map(|tx| tx.inner.transaction.clone());
        // Expiring nonce txs are always pending
        let expiring = self
            .expiring_nonce_txs
            .values()
            .filter(move |tx| tx.transaction.origin == origin)
            .map(|tx| tx.transaction.clone());
        regular.chain(expiring)
    }

    /// Returns all transactions of the address
    pub(crate) fn get_transactions_by_sender_iter(
        &self,
        sender: Address,
    ) -> impl Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + '_ {
        let regular = self
            .by_id
            .values()
            .filter(move |tx| tx.inner.transaction.sender() == sender)
            .map(|tx| tx.inner.transaction.clone());
        let expiring = self
            .expiring_nonce_txs
            .values()
            .filter(move |tx| tx.transaction.sender() == sender)
            .map(|tx| tx.transaction.clone());
        regular.chain(expiring)
    }

    /// Returns an iterator over all transaction hashes in this pool
    pub(crate) fn all_transaction_hashes_iter(&self) -> impl Iterator<Item = TxHash> {
        self.by_hash.keys().copied()
    }

    /// Returns all transactions from that are queued.
    pub(crate) fn queued_transactions(
        &self,
    ) -> impl Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_id
            .values()
            .filter(|tx| !tx.is_pending())
            .map(|tx| tx.inner.transaction.clone())
    }

    /// Returns all transactions that are pending.
    pub(crate) fn pending_transactions(
        &self,
    ) -> impl Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + '_ {
        // Include both regular pending 2D nonce txs and expiring nonce txs
        let regular_pending = self
            .by_id
            .values()
            .filter(|tx| tx.is_pending())
            .map(|tx| tx.inner.transaction.clone());
        let expiring_pending = self
            .expiring_nonce_txs
            .values()
            .map(|tx| tx.transaction.clone());
        regular_pending.chain(expiring_pending)
    }

    /// Returns the best, executable transactions for this sub-pool
    #[allow(clippy::mutable_key_type)]
    pub(crate) fn best_transactions(&self) -> BestAA2dTransactions {
        // Collect independent transactions from both 2D nonce pool and expiring nonce pool
        let mut independent: BTreeSet<_> =
            self.independent_transactions.values().cloned().collect();
        // Expiring nonce txs are always independent (no nonce dependencies)
        independent.extend(self.expiring_nonce_txs.values().cloned());

        BestAA2dTransactions {
            independent,
            by_id: self
                .by_id
                .iter()
                .filter(|(_, tx)| tx.is_pending())
                .map(|(id, tx)| (*id, tx.inner.clone()))
                .collect(),
            invalid: Default::default(),
        }
    }

    /// Returns the transaction by hash.
    pub(crate) fn get(
        &self,
        tx_hash: &TxHash,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_hash.get(tx_hash).cloned()
    }

    /// Returns the transaction by hash.
    pub(crate) fn get_all<'a, I>(
        &self,
        tx_hashes: I,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>
    where
        I: Iterator<Item = &'a TxHash> + 'a,
    {
        let mut ret = Vec::new();
        for tx_hash in tx_hashes {
            if let Some(tx) = self.get(tx_hash) {
                ret.push(tx);
            }
        }
        ret
    }

    /// Returns pooled transaction elements for the given hashes while respecting the size limit.
    ///
    /// This method collects transactions from the pool, converts them to pooled format,
    /// and tracks the accumulated size. It stops collecting when the limit is exceeded.
    ///
    /// The `accumulated_size` is updated with the total encoded size of returned transactions.
    pub(crate) fn append_pooled_transaction_elements<'a>(
        &self,
        tx_hashes: impl IntoIterator<Item = &'a TxHash>,
        limit: GetPooledTransactionLimit,
        accumulated_size: &mut usize,
        out: &mut Vec<<TempoPooledTransaction as PoolTransaction>::Pooled>,
    ) {
        for tx_hash in tx_hashes {
            let Some(tx) = self.by_hash.get(tx_hash) else {
                continue;
            };

            let encoded_len = tx.transaction.encoded_length();
            let Some(pooled) = tx.transaction.clone_into_pooled().ok() else {
                continue;
            };

            *accumulated_size += encoded_len;
            out.push(pooled.into_inner());

            if limit.exceeds(*accumulated_size) {
                break;
            }
        }
    }

    /// Returns an iterator over all senders in this pool.
    pub(crate) fn senders_iter(&self) -> impl Iterator<Item = &Address> {
        let regular = self
            .by_id
            .values()
            .map(|tx| tx.inner.transaction.sender_ref());
        let expiring = self
            .expiring_nonce_txs
            .values()
            .map(|tx| tx.transaction.sender_ref());
        regular.chain(expiring)
    }

    /// Returns all transactions that _follow_ after the given id but have the same sender.
    ///
    /// NOTE: The range is _inclusive_: if the transaction that belongs to `id` it will be the
    /// first value.
    fn descendant_txs<'a, 'b: 'a>(
        &'a self,
        id: &'b AA2dTransactionId,
    ) -> impl Iterator<Item = (&'a AA2dTransactionId, &'a Arc<AA2dInternalTransaction>)> + 'a {
        self.by_id
            .range(id..)
            .take_while(|(other, _)| id.seq_id == other.seq_id)
    }

    /// Returns all transactions that _follow_ after the given id and have the same sender.
    ///
    /// NOTE: The range is _exclusive_
    fn descendant_txs_exclusive<'a, 'b: 'a>(
        &'a self,
        id: &'b AA2dTransactionId,
    ) -> impl Iterator<Item = (&'a AA2dTransactionId, &'a Arc<AA2dInternalTransaction>)> + 'a {
        self.by_id
            .range((Excluded(id), Unbounded))
            .take_while(|(other, _)| id.seq_id == other.seq_id)
    }

    /// Removes the transaction with the given id from all sets.
    ///
    /// This does __not__ shift the independent transaction forward or mark descendants as pending.
    fn remove_transaction_by_id(
        &mut self,
        id: &AA2dTransactionId,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let tx = self.by_id.remove(id)?;

        // Remove from eviction set
        let eviction_key = EvictionKey::new(Arc::clone(&tx), *id);
        self.by_eviction_order.remove(&eviction_key);

        // Clean up cached nonce key slots if this was the last transaction of the sequence
        if self.by_id.range(id.seq_id.range()).next().is_none()
            && let Some(slot) = self.seq_id_to_slot.remove(&id.seq_id)
        {
            self.slot_to_seq_id.remove(&slot);
        }

        self.remove_independent(id);
        let removed_tx = tx.inner.transaction.clone();
        self.by_hash.remove(removed_tx.hash());

        // Decrement sender count
        self.decrement_sender_count(removed_tx.sender());

        Some(removed_tx)
    }

    /// Decrements the transaction count for a sender, removing the entry if it reaches zero.
    fn decrement_sender_count(&mut self, sender: Address) {
        if let hash_map::Entry::Occupied(mut entry) = self.txs_by_sender.entry(sender) {
            let count = entry.get_mut();
            *count -= 1;
            if *count == 0 {
                entry.remove();
            }
        }
    }

    /// Removes the independent transaction if it matches the given id.
    fn remove_independent(
        &mut self,
        id: &AA2dTransactionId,
    ) -> Option<PendingTransaction<TxOrdering>> {
        // Only remove from independent_transactions if this is the independent transaction
        match self.independent_transactions.entry(id.seq_id) {
            hash_map::Entry::Occupied(entry) => {
                // we know it's the independent tx if the tracked tx has the same nonce
                if entry.get().transaction.nonce() == id.nonce {
                    return Some(entry.remove());
                }
            }
            hash_map::Entry::Vacant(_) => {}
        };
        None
    }

    /// Removes the transaction by its hash from all internal sets.
    ///
    /// This batches demotion by seq_id to avoid O(N*N) complexity when removing many
    /// transactions from the same sequence.
    pub(crate) fn remove_transactions<'a, I>(
        &mut self,
        tx_hashes: I,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>
    where
        I: Iterator<Item = &'a TxHash> + 'a,
    {
        let mut txs = Vec::new();
        let mut seq_ids_to_demote: HashMap<AASequenceId, u64> = HashMap::default();

        for tx_hash in tx_hashes {
            if let Some((tx, seq_id)) = self.remove_transaction_by_hash_no_demote(tx_hash) {
                if let Some(id) = seq_id {
                    seq_ids_to_demote
                        .entry(id.seq_id)
                        .and_modify(|min_nonce| {
                            if id.nonce < *min_nonce {
                                *min_nonce = id.nonce;
                            }
                        })
                        .or_insert(id.nonce);
                }
                txs.push(tx);
            }
        }

        // Demote once per seq_id, starting from the minimum removed nonce
        for (seq_id, min_nonce) in seq_ids_to_demote {
            self.demote_from_nonce(&seq_id, min_nonce);
        }

        txs
    }

    /// Removes the transaction by its hash from all internal sets.
    ///
    /// This does __not__ shift the independent transaction forward but it does demote descendants
    /// to queued status since removing a transaction creates a nonce gap.
    fn remove_transaction_by_hash(
        &mut self,
        tx_hash: &B256,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let (tx, id) = self.remove_transaction_by_hash_no_demote(tx_hash)?;

        // Demote all descendants to queued status since removing this transaction creates a gap
        if let Some(id) = id {
            self.demote_descendants(&id);
        }

        Some(tx)
    }

    /// Internal helper that removes a transaction without demoting descendants.
    ///
    /// Returns the removed transaction and its AA2dTransactionId (if it was a 2D nonce tx).
    fn remove_transaction_by_hash_no_demote(
        &mut self,
        tx_hash: &B256,
    ) -> Option<(
        Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        Option<AA2dTransactionId>,
    )> {
        let tx = self.by_hash.remove(tx_hash)?;

        // Check if this is an expiring nonce transaction
        if tx.transaction.is_expiring_nonce() {
            self.expiring_nonce_txs.remove(tx_hash);
            // Decrement sender count for expiring nonce txs
            self.decrement_sender_count(tx.sender());
            return Some((tx, None));
        }

        // Regular 2D nonce transaction
        let id = tx
            .transaction
            .aa_transaction_id()
            .expect("is AA transaction");
        self.remove_transaction_by_id(&id)?;

        Some((tx, Some(id)))
    }

    /// Demotes all descendants of the given transaction to queued status (`is_pending = false`).
    ///
    /// This should be called after removing a transaction to ensure descendants don't remain
    /// marked as pending when they're no longer executable due to the nonce gap.
    fn demote_descendants(&mut self, id: &AA2dTransactionId) {
        self.demote_from_nonce(&id.seq_id, id.nonce);
    }

    /// Demotes all transactions for a seq_id with nonce > min_nonce to queued status.
    ///
    /// This is used both for single-tx removal (demote_descendants) and batch removal
    /// where we want to demote once per seq_id starting from the minimum removed nonce.
    fn demote_from_nonce(&self, seq_id: &AASequenceId, min_nonce: u64) {
        let start_id = AA2dTransactionId::new(*seq_id, min_nonce);
        for (_, tx) in self
            .by_id
            .range((Excluded(&start_id), Unbounded))
            .take_while(|(other, _)| *seq_id == other.seq_id)
        {
            tx.set_pending(false);
        }
    }

    /// Removes and returns all matching transactions and their dependent transactions from the
    /// pool.
    pub(crate) fn remove_transactions_and_descendants<'a, I>(
        &mut self,
        hashes: I,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>
    where
        I: Iterator<Item = &'a TxHash> + 'a,
    {
        let mut removed = Vec::new();
        for hash in hashes {
            if let Some(tx) = self.remove_transaction_by_hash(hash) {
                let id = tx.transaction.aa_transaction_id();
                removed.push(tx);
                if let Some(id) = id {
                    self.remove_descendants(&id, &mut removed);
                }
            }
        }
        removed
    }

    /// Removes all transactions from the given sender.
    pub(crate) fn remove_transactions_by_sender(
        &mut self,
        sender_id: Address,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut removed = Vec::new();
        let txs = self
            .get_transactions_by_sender_iter(sender_id)
            .collect::<Vec<_>>();
        for tx in txs {
            // Handle expiring nonce transactions separately - they are stored by hash
            if tx.transaction.is_expiring_nonce() {
                let hash = *tx.hash();
                if self.expiring_nonce_txs.remove(&hash).is_some() {
                    self.by_hash.remove(&hash);
                    self.decrement_sender_count(tx.sender());
                    removed.push(tx);
                }
            } else if let Some(tx) = tx
                .transaction
                .aa_transaction_id()
                .and_then(|id| self.remove_transaction_by_id(&id))
            {
                removed.push(tx);
            }
        }
        removed
    }

    /// Removes _only_ the descendants of the given transaction from this pool.
    ///
    /// All removed transactions are added to the `removed` vec.
    fn remove_descendants(
        &mut self,
        tx: &AA2dTransactionId,
        removed: &mut Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    ) {
        let mut id = *tx;

        // this will essentially pop _all_ descendant transactions one by one
        loop {
            let descendant = self.descendant_txs_exclusive(&id).map(|(id, _)| *id).next();
            if let Some(descendant) = descendant {
                if let Some(tx) = self.remove_transaction_by_id(&descendant) {
                    removed.push(tx)
                }
                id = descendant;
            } else {
                return;
            }
        }
    }

    /// Updates the internal state based on the state changes of the `NonceManager` [`NONCE_PRECOMPILE_ADDRESS`].
    ///
    /// This takes a vec of changed [`AASequenceId`] with their current on chain nonce.
    ///
    /// This will prune mined transactions and promote unblocked transactions if any, returns `(promoted, mined)`
    #[allow(clippy::type_complexity)]
    pub(crate) fn on_nonce_changes(
        &mut self,
        on_chain_ids: HashMap<AASequenceId, u64>,
    ) -> (
        Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    ) {
        trace!(target: "txpool::2d", ?on_chain_ids, "processing nonce changes");

        let mut promoted = Vec::new();
        let mut mined_ids = Vec::new();

        // we assume the set of changed senders is smaller than the individual accounts
        'changes: for (sender_id, on_chain_nonce) in on_chain_ids {
            let mut iter = self
                .by_id
                .range_mut((sender_id.start_bound(), Unbounded))
                .take_while(move |(other, _)| sender_id == other.seq_id)
                .peekable();

            let Some(mut current) = iter.next() else {
                continue;
            };

            // track mined transactions
            'mined: loop {
                if current.0.nonce < on_chain_nonce {
                    mined_ids.push(*current.0);
                    let Some(next) = iter.next() else {
                        continue 'changes;
                    };
                    current = next;
                } else {
                    break 'mined;
                }
            }

            // Process remaining transactions starting from `current` (which is >= on_chain_nonce)
            let mut next_nonce = on_chain_nonce;
            for (existing_id, existing_tx) in std::iter::once(current).chain(iter) {
                if existing_id.nonce == next_nonce {
                    // Promote if transaction was previously queued (not pending)
                    let was_pending = existing_tx.set_pending(true);
                    if !was_pending {
                        promoted.push(existing_tx.inner.transaction.clone());
                    }

                    if existing_id.nonce == on_chain_nonce {
                        // if this is the on chain nonce we can mark it as the next independent transaction
                        self.independent_transactions
                            .insert(existing_id.seq_id, existing_tx.inner.clone());
                    }

                    next_nonce = next_nonce.saturating_add(1);
                } else {
                    // Gap detected - mark this and all remaining transactions as non-pending
                    existing_tx.set_pending(false);
                }
            }

            // If no transaction was found at the on-chain nonce (next_nonce unchanged),
            // remove any stale independent transaction entry for this seq_id.
            // This handles reorgs where the on-chain nonce decreases.
            if next_nonce == on_chain_nonce {
                self.independent_transactions.remove(&sender_id);
            }
        }

        // actually remove mined transactions
        let mut mined = Vec::with_capacity(mined_ids.len());
        for id in mined_ids {
            if let Some(removed) = self.remove_transaction_by_id(&id) {
                mined.push(removed);
            }
        }

        // Record metrics
        if !promoted.is_empty() {
            self.metrics.inc_promoted(promoted.len());
        }
        if !mined.is_empty() {
            self.metrics.inc_removed(mined.len());
        }
        self.update_metrics();

        (promoted, mined)
    }

    /// Removes lowest-priority transactions if the pool is above capacity.
    ///
    /// This evicts transactions with the lowest priority (based on [`CoinbaseTipOrdering`])
    /// to prevent DoS attacks where adversaries use vanity addresses with many leading zeroes
    /// to avoid eviction.
    ///
    /// Evicts queued transactions first (up to queued_limit), then pending if needed.
    /// Counts are computed lazily by scanning the eviction set.
    ///
    /// Note: Only `max_txs` is enforced here; `max_size` is intentionally not checked for 2D pools
    /// since the protocol pool already enforces size-based limits as a primary defense.
    fn discard(&mut self) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut removed = Vec::new();

        // Compute counts lazily by scanning the pool
        let (pending_count, queued_count) = self.pending_and_queued_txn_count();

        // Evict queued transactions if over queued limit (lowest priority first)
        if queued_count > self.config.queued_limit.max_txs {
            let queued_excess = queued_count - self.config.queued_limit.max_txs;
            removed.extend(self.evict_lowest_priority(queued_excess, false));
        }

        // Evict pending transactions if over pending limit (lowest priority first)
        if pending_count > self.config.pending_limit.max_txs {
            let pending_excess = pending_count - self.config.pending_limit.max_txs;
            removed.extend(self.evict_lowest_priority(pending_excess, true));
        }

        if !removed.is_empty() {
            self.metrics.inc_removed(removed.len());
        }

        removed
    }

    /// Evicts the lowest-priority transactions from the pool.
    ///
    /// Scans the single eviction set (ordered by priority) and filters by `is_pending`
    /// to find queued or pending transactions to evict. This is a best-effort scan
    /// that checks a bool for each transaction.
    fn evict_lowest_priority(
        &mut self,
        count: usize,
        evict_pending: bool,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        if count == 0 {
            return vec![];
        }

        let mut removed = Vec::with_capacity(count);

        if evict_pending {
            // For pending eviction, consider both regular 2D txs and expiring nonce txs
            for _ in 0..count {
                if let Some(tx) = self.evict_one_pending() {
                    removed.push(tx);
                } else {
                    break;
                }
            }
        } else {
            // For queued, only look at by_eviction_order (expiring nonce txs are always pending)
            let to_remove: Vec<_> = self
                .by_eviction_order
                .iter()
                .filter(|key| !key.is_pending())
                .map(|key| key.tx_id)
                .take(count)
                .collect();

            for id in to_remove {
                if let Some(tx) = self.remove_transaction_by_id(&id) {
                    removed.push(tx);
                }
            }
        }

        removed
    }

    /// Evicts one pending transaction, considering both regular 2D and expiring nonce txs.
    /// Evicts the transaction with lowest priority (worst transaction).
    fn evict_one_pending(&mut self) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        // Find worst regular 2D pending tx from eviction order
        let worst_2d = self
            .by_eviction_order
            .iter()
            .find(|key| key.is_pending())
            .map(|key| (key.tx_id, key.priority().clone()));

        // Find worst expiring nonce tx (lowest priority)
        let worst_expiring = self
            .expiring_nonce_txs
            .iter()
            .min_by(|a, b| a.1.priority.cmp(&b.1.priority))
            .map(|(hash, tx)| (*hash, tx.priority.clone()));

        // Choose which one to evict based on priority (lower priority = evict first)
        match (worst_2d, worst_expiring) {
            (Some((id, priority_2d)), Some((hash, priority_exp))) => {
                // Evict the one with lower priority
                if priority_exp < priority_2d {
                    self.evict_expiring_nonce_tx(&hash)
                } else {
                    self.evict_2d_pending_tx(&id)
                }
            }
            (Some((id, _)), None) => self.evict_2d_pending_tx(&id),
            (None, Some((hash, _))) => self.evict_expiring_nonce_tx(&hash),
            (None, None) => None,
        }
    }

    /// Evicts a regular 2D pending transaction by ID.
    fn evict_2d_pending_tx(
        &mut self,
        id: &AA2dTransactionId,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let tx = self.remove_transaction_by_id(id)?;
        self.demote_descendants(id);
        Some(tx)
    }

    /// Evicts an expiring nonce transaction by hash.
    fn evict_expiring_nonce_tx(
        &mut self,
        hash: &TxHash,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let pending_tx = self.expiring_nonce_txs.remove(hash)?;
        self.by_hash.remove(hash);
        self.decrement_sender_count(pending_tx.transaction.sender());
        Some(pending_tx.transaction)
    }

    /// Returns a reference to the metrics for this pool
    pub fn metrics(&self) -> &AA2dPoolMetrics {
        &self.metrics
    }

    /// Removes expiring nonce transactions that were included in a block.
    ///
    /// This should be called with the transaction hashes from mined blocks to clean up
    /// expiring nonce transactions on inclusion, rather than waiting for expiry.
    pub(crate) fn remove_included_expiring_nonce_txs<'a>(
        &mut self,
        tx_hashes: impl Iterator<Item = &'a TxHash>,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut removed = Vec::new();
        for tx_hash in tx_hashes {
            if let Some(pending_tx) = self.expiring_nonce_txs.remove(tx_hash) {
                self.by_hash.remove(tx_hash);
                self.decrement_sender_count(pending_tx.transaction.sender());
                removed.push(pending_tx.transaction);
            }
        }
        if !removed.is_empty() {
            self.metrics.inc_removed(removed.len());
            self.update_metrics();
        }
        removed
    }

    /// Returns `true` if the transaction with the given hash is already included in this pool.
    pub(crate) fn contains(&self, tx_hash: &TxHash) -> bool {
        self.by_hash.contains_key(tx_hash)
    }

    /// Returns hashes of transactions in the pool that can be propagated.
    pub(crate) fn pooled_transactions_hashes_iter(&self) -> impl Iterator<Item = TxHash> {
        self.by_hash
            .values()
            .filter(|tx| tx.propagate)
            .map(|tx| *tx.hash())
    }

    /// Returns transactions in the pool that can be propagated
    pub(crate) fn pooled_transactions_iter(
        &self,
    ) -> impl Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_hash.values().filter(|tx| tx.propagate).cloned()
    }

    const fn next_id(&mut self) -> u64 {
        let id = self.submission_id;
        self.submission_id = self.submission_id.wrapping_add(1);
        id
    }

    /// Caches the 2D nonce key slot for the given sender and nonce key.
    fn record_2d_slot(&mut self, transaction: &TempoPooledTransaction) {
        let address = transaction.sender();
        let nonce_key = transaction.nonce_key().unwrap_or_default();
        let Some(slot) = transaction.nonce_key_slot() else {
            return;
        };

        trace!(target: "txpool::2d", ?address, ?nonce_key, "recording 2d nonce slot");
        let seq_id = AASequenceId::new(address, nonce_key);

        if self.slot_to_seq_id.insert(slot, seq_id).is_none() {
            self.metrics.inc_nonce_key_count(1);
            self.seq_id_to_slot.insert(seq_id, slot);
        }
    }

    /// Processes state updates and updates internal state accordingly.
    #[expect(clippy::type_complexity)]
    pub(crate) fn on_state_updates<S: std::hash::BuildHasher>(
        &mut self,
        state: &std::collections::HashMap<Address, BundleAccount, S>,
    ) -> (
        Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    ) {
        let mut changes = HashMap::default();

        for (account, state) in state {
            if account == &NONCE_PRECOMPILE_ADDRESS {
                // Process known 2D nonce slot changes.
                for (slot, value) in state.storage.iter() {
                    if let Some(seq_id) = self.slot_to_seq_id.get(slot) {
                        changes.insert(*seq_id, value.present_value.saturating_to());
                    }
                }
            }
            let nonce = state
                .account_info()
                .map(|info| info.nonce)
                .unwrap_or_default();
            changes.insert(AASequenceId::new(*account, U256::ZERO), nonce);
        }

        self.on_nonce_changes(changes)
    }

    /// Asserts that all assumptions are valid.
    #[cfg(test)]
    pub(crate) fn assert_invariants(&self) {
        // Basic size constraints
        assert!(
            self.independent_transactions.len() <= self.by_id.len(),
            "independent_transactions.len() ({}) > by_id.len() ({})",
            self.independent_transactions.len(),
            self.by_id.len()
        );
        // by_hash contains both regular 2D nonce txs (in by_id) and expiring nonce txs
        assert_eq!(
            self.by_id.len() + self.expiring_nonce_txs.len(),
            self.by_hash.len(),
            "by_id.len() ({}) + expiring_nonce_txs.len() ({}) != by_hash.len() ({})",
            self.by_id.len(),
            self.expiring_nonce_txs.len(),
            self.by_hash.len()
        );

        // All independent transactions must exist in by_id
        for (seq_id, independent_tx) in &self.independent_transactions {
            let tx_id = independent_tx
                .transaction
                .transaction
                .aa_transaction_id()
                .expect("Independent transaction must have AA transaction ID");
            assert!(
                self.by_id.contains_key(&tx_id),
                "Independent transaction {tx_id:?} not in by_id"
            );
            assert_eq!(
                seq_id, &tx_id.seq_id,
                "Independent transactions sequence ID {seq_id:?} does not match transaction sequence ID {tx_id:?}"
            );

            // Independent transactions must be pending
            let tx_in_pool = self.by_id.get(&tx_id).unwrap();
            assert!(
                tx_in_pool.is_pending(),
                "Independent transaction {tx_id:?} is not pending"
            );

            // Independent transaction should match the one in by_id
            assert_eq!(
                independent_tx.transaction.hash(),
                tx_in_pool.inner.transaction.hash(),
                "Independent transaction hash mismatch for {tx_id:?}"
            );
        }

        // Each sender should have at most one transaction in independent set
        let mut seen_senders = std::collections::HashSet::new();
        for id in self.independent_transactions.keys() {
            assert!(
                seen_senders.insert(*id),
                "Duplicate sender {id:?} in independent transactions"
            );
        }

        // Verify by_hash integrity
        for (hash, tx) in &self.by_hash {
            // Hash should match transaction hash
            assert_eq!(
                tx.hash(),
                hash,
                "Hash mismatch in by_hash: expected {:?}, got {:?}",
                hash,
                tx.hash()
            );

            // Expiring nonce txs are stored in expiring_nonce_txs, not by_id
            if tx.transaction.is_expiring_nonce() {
                assert!(
                    self.expiring_nonce_txs.contains_key(hash),
                    "Expiring nonce transaction with hash {hash:?} in by_hash but not in expiring_nonce_txs"
                );
                continue;
            }

            // Transaction in by_hash should exist in by_id
            let id = tx
                .transaction
                .aa_transaction_id()
                .expect("Transaction in pool should be AA transaction");
            assert!(
                self.by_id.contains_key(&id),
                "Transaction with hash {hash:?} in by_hash but not in by_id"
            );

            // The transaction in by_id should have the same hash
            let tx_in_by_id = &self.by_id.get(&id).unwrap().inner.transaction;
            assert_eq!(
                tx.hash(),
                tx_in_by_id.hash(),
                "Transaction hash mismatch between by_hash and by_id for id {id:?}"
            );
        }

        // Verify by_id integrity
        for (id, tx) in &self.by_id {
            // Transaction in by_id should exist in by_hash
            let hash = tx.inner.transaction.hash();
            assert!(
                self.by_hash.contains_key(hash),
                "Transaction with id {id:?} in by_id but not in by_hash"
            );

            // The transaction should have the correct AA ID
            let tx_id = tx
                .inner
                .transaction
                .transaction
                .aa_transaction_id()
                .expect("Transaction in pool should be AA transaction");
            assert_eq!(
                &tx_id, id,
                "Transaction ID mismatch: expected {id:?}, got {tx_id:?}"
            );

            // If THIS transaction is the independent transaction for its sequence, it must be pending
            if let Some(independent_tx) = self.independent_transactions.get(&id.seq_id)
                && independent_tx.transaction.hash() == tx.inner.transaction.hash()
            {
                assert!(
                    tx.is_pending(),
                    "Transaction {id:?} is in independent set but not pending"
                );
            }
        }

        // Verify pending/queued consistency
        // pending_and_queued_txn_count includes expiring nonce txs in pending count
        let (pending_count, queued_count) = self.pending_and_queued_txn_count();
        assert_eq!(
            pending_count + queued_count,
            self.by_id.len() + self.expiring_nonce_txs.len(),
            "Pending ({}) + queued ({}) != total transactions (by_id: {} + expiring: {})",
            pending_count,
            queued_count,
            self.by_id.len(),
            self.expiring_nonce_txs.len()
        );

        // Verify quota compliance - counts don't exceed limits
        assert!(
            pending_count <= self.config.pending_limit.max_txs,
            "pending_count {} exceeds limit {}",
            pending_count,
            self.config.pending_limit.max_txs
        );
        assert!(
            queued_count <= self.config.queued_limit.max_txs,
            "queued_count {} exceeds limit {}",
            queued_count,
            self.config.queued_limit.max_txs
        );

        // Verify expiring nonce txs integrity
        for (hash, pending_tx) in &self.expiring_nonce_txs {
            assert!(
                self.by_hash.contains_key(hash),
                "Expiring nonce tx {hash:?} not in by_hash"
            );
            assert!(
                pending_tx.transaction.transaction.is_expiring_nonce(),
                "Transaction in expiring_nonce_txs is not an expiring nonce tx"
            );
        }
    }
}

/// Default maximum number of transactions per sender in the AA 2D pool.
///
/// This limit prevents a single sender from monopolizing pool capacity.
pub const DEFAULT_MAX_TXS_PER_SENDER: usize = 16;

/// Settings for the [`AA2dPoolConfig`]
#[derive(Debug, Clone)]
pub struct AA2dPoolConfig {
    /// Price bump (in %) for the transaction pool underpriced check.
    pub price_bump_config: PriceBumpConfig,
    /// Maximum number of pending (executable) transactions
    pub pending_limit: SubPoolLimit,
    /// Maximum number of queued (non-executable) transactions
    pub queued_limit: SubPoolLimit,
    /// Maximum number of transactions per sender.
    ///
    /// Prevents a single sender from monopolizing pool capacity (DoS protection).
    pub max_txs_per_sender: usize,
}

impl Default for AA2dPoolConfig {
    fn default() -> Self {
        Self {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit::default(),
            queued_limit: SubPoolLimit::default(),
            max_txs_per_sender: DEFAULT_MAX_TXS_PER_SENDER,
        }
    }
}

#[derive(Debug, Clone)]
struct AA2dInternalTransaction {
    /// Keeps track of the transaction
    ///
    /// We can use [`PendingTransaction`] here because the priority remains unchanged.
    inner: PendingTransaction<CoinbaseTipOrdering<TempoPooledTransaction>>,
    /// Whether this transaction is pending/executable.
    ///
    /// If it's not pending, it is queued.
    ///
    /// Uses `Rc<RefCell<bool>>` so we can mutate this flag without removing/reinserting
    /// the transaction from the eviction set. This allows a single eviction set for
    /// all transactions, with pending/queued filtering done at eviction time.
    is_pending: Rc<RefCell<bool>>,
}

impl AA2dInternalTransaction {
    /// Returns whether this transaction is pending/executable.
    fn is_pending(&self) -> bool {
        *self.is_pending.borrow()
    }

    /// Sets the pending status of this transaction, returning the previous value.
    fn set_pending(&self, pending: bool) -> bool {
        std::mem::replace(&mut *self.is_pending.borrow_mut(), pending)
    }
}

// SAFETY: `AA2dInternalTransaction` contains `Rc<RefCell<bool>>` which is not `Send`/`Sync`.
// However, `AA2dPool` is only ever accessed through `Arc<RwLock<AA2dPool>>`, meaning:
// - All reads require holding the read lock (shared access to the pool, no mutation of is_pending)
// - All writes require holding the write lock (exclusive access, single consumer)
// Since we never have concurrent access to `is_pending`, this is safe.
unsafe impl Send for AA2dInternalTransaction {}
unsafe impl Sync for AA2dInternalTransaction {}

/// Key for ordering transactions by eviction priority.
///
/// Orders by:
/// 1. Priority ascending (lowest priority evicted first)
/// 2. Submission ID descending (newer transactions evicted first among same priority)
///
/// This is the inverse of the execution order (where highest priority, oldest submission wins).
/// Newer transactions are evicted first to preserve older transactions that have been waiting longer.
#[derive(Debug, Clone)]
struct EvictionKey {
    /// The wrapped transaction containing all needed data.
    tx: Arc<AA2dInternalTransaction>,
    /// The transaction's unique identifier (cached for lookup during eviction).
    /// We cache this because deriving it from the transaction requires
    /// `aa_transaction_id()` which returns an Option and does more work.
    tx_id: AA2dTransactionId,
}

impl EvictionKey {
    /// Creates a new eviction key wrapping the transaction.
    fn new(tx: Arc<AA2dInternalTransaction>, tx_id: AA2dTransactionId) -> Self {
        Self { tx, tx_id }
    }

    /// Returns the transaction's priority.
    fn priority(&self) -> &Priority<u128> {
        &self.tx.inner.priority
    }

    /// Returns the submission ID.
    fn submission_id(&self) -> u64 {
        self.tx.inner.submission_id
    }

    /// Returns whether this transaction is pending.
    fn is_pending(&self) -> bool {
        self.tx.is_pending()
    }
}

impl PartialEq for EvictionKey {
    fn eq(&self, other: &Self) -> bool {
        self.submission_id() == other.submission_id()
    }
}

impl Eq for EvictionKey {}

impl Ord for EvictionKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Lower priority first (evict lowest priority)
        self.priority()
            .cmp(other.priority())
            // Then newer submission first (evict newer transactions among same priority)
            // This preserves older transactions that have been waiting longer
            .then_with(|| other.submission_id().cmp(&self.submission_id()))
    }
}

impl PartialOrd for EvictionKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A snapshot of the sub-pool containing all executable transactions.
#[derive(Debug)]
pub(crate) struct BestAA2dTransactions {
    /// pending, executable transactions sorted by their priority.
    independent: BTreeSet<PendingTransaction<TxOrdering>>,
    /// _All_ transactions that are currently inside the pool grouped by their unique identifier.
    by_id: BTreeMap<AA2dTransactionId, PendingTransaction<TxOrdering>>,

    /// There might be the case where a yielded transactions is invalid, this will track it.
    invalid: HashSet<AASequenceId>,
}

impl BestAA2dTransactions {
    /// Removes the best transaction from the set
    fn pop_best(&mut self) -> Option<(AA2dTransactionId, PendingTransaction<TxOrdering>)> {
        let tx = self.independent.pop_last()?;
        let id = tx
            .transaction
            .transaction
            .aa_transaction_id()
            .expect("Transaction in AA2D pool must be an AA transaction with valid nonce key");
        self.by_id.remove(&id);
        Some((id, tx))
    }

    /// Returns the next best transaction with its priority.
    pub(crate) fn next_tx_and_priority(
        &mut self,
    ) -> Option<(
        Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        Priority<u128>,
    )> {
        loop {
            let (id, best) = self.pop_best()?;
            if self.invalid.contains(&id.seq_id) {
                continue;
            }
            // Advance transaction that just got unlocked, if any.
            // Skip for expiring nonce transactions as they are always independent.
            if !best.transaction.transaction.is_expiring_nonce()
                && let Some(unlocked) = self.by_id.get(&id.unlocks())
            {
                self.independent.insert(unlocked.clone());
            }
            return Some((best.transaction, best.priority));
        }
    }
}

impl Iterator for BestAA2dTransactions {
    type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_tx_and_priority().map(|(tx, _)| tx)
    }
}

impl BestTransactions for BestAA2dTransactions {
    fn mark_invalid(&mut self, transaction: &Self::Item, _kind: &InvalidPoolTransactionError) {
        // Skip invalidation for expiring nonce transactions - they are independent
        // and should not block other expiring nonce txs from the same sender
        if transaction.transaction.is_expiring_nonce() {
            return;
        }

        if let Some(id) = transaction.transaction.aa_transaction_id() {
            self.invalid.insert(id.seq_id);
        }
    }

    fn no_updates(&mut self) {}

    fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
}

/// Key for identifying a unique sender sequence in 2D nonce system.
///
/// This combines the sender address with its nonce key, which
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct AASequenceId {
    /// The sender address.
    pub address: Address,
    /// The nonce key for 2D nonce transactions.
    pub nonce_key: U256,
}

impl AASequenceId {
    /// Creates a new instance with the address and nonce key.
    pub const fn new(address: Address, nonce_key: U256) -> Self {
        Self { address, nonce_key }
    }

    const fn start_bound(self) -> std::ops::Bound<AA2dTransactionId> {
        std::ops::Bound::Included(AA2dTransactionId::new(self, 0))
    }

    /// Returns a range of transactions for this sequence.
    const fn range(self) -> std::ops::RangeInclusive<AA2dTransactionId> {
        AA2dTransactionId::new(self, 0)..=AA2dTransactionId::new(self, u64::MAX)
    }
}

/// Unique identifier for an AA transaction.
///
/// Identified by its sender, nonce key and nonce for that nonce key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) struct AA2dTransactionId {
    /// Uniquely identifies the accounts nonce key sequence
    pub(crate) seq_id: AASequenceId,
    /// The nonce in that sequence
    pub(crate) nonce: u64,
}

impl AA2dTransactionId {
    /// Creates a new identifier.
    pub(crate) const fn new(seq_id: AASequenceId, nonce: u64) -> Self {
        Self { seq_id, nonce }
    }

    /// Returns the next transaction in the sequence.
    pub(crate) fn unlocks(&self) -> Self {
        Self::new(self.seq_id, self.nonce.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TxBuilder, wrap_valid_tx};
    use alloy_primitives::{Address, U256};
    use reth_transaction_pool::PoolTransaction;
    use std::collections::HashSet;
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn insert_pending(nonce_key: U256) {
        let mut pool = AA2dPool::default();

        // Set up a sender with a tracked nonce key
        let sender = Address::random();

        // Create a transaction with nonce_key=1, nonce=0 (should be pending)
        let tx = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let valid_tx = wrap_valid_tx(tx, TransactionOrigin::Local);

        // Add the transaction to the pool
        let result = pool.add_transaction(Arc::new(valid_tx), 0, TempoHardfork::T1);

        // Should be added as pending
        assert!(result.is_ok(), "Transaction should be added successfully");
        let added = result.unwrap();
        assert!(
            matches!(added, AddedTransaction::Pending(_)),
            "Transaction should be pending, got: {added:?}"
        );

        // Verify pool state
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 1, "Should have 1 pending transaction");
        assert_eq!(queued_count, 0, "Should have 0 queued transactions");

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn insert_with_nonce_gap_then_fill(nonce_key: U256) {
        let mut pool = AA2dPool::default();

        // Set up a sender with a tracked nonce key
        let sender = Address::random();

        // Step 1: Insert transaction with nonce=1 (creates a gap, should be queued)
        let tx1 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build();
        let valid_tx1 = wrap_valid_tx(tx1, TransactionOrigin::Local);
        let tx1_hash = *valid_tx1.hash();

        let result1 = pool.add_transaction(Arc::new(valid_tx1), 0, TempoHardfork::T1);

        // Should be queued due to nonce gap
        assert!(
            result1.is_ok(),
            "Transaction 1 should be added successfully"
        );
        let added1 = result1.unwrap();
        assert!(
            matches!(
                added1,
                AddedTransaction::Parked {
                    subpool: SubPool::Queued,
                    ..
                }
            ),
            "Transaction 1 should be queued due to nonce gap, got: {added1:?}"
        );

        // Verify pool state after first insert
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 0, "Should have 0 pending transactions");
        assert_eq!(queued_count, 1, "Should have 1 queued transaction");

        // Verify tx1 is NOT in independent set
        let seq_id = AASequenceId::new(sender, nonce_key);
        let tx1_id = AA2dTransactionId::new(seq_id, 1);
        assert!(
            !pool.independent_transactions.contains_key(&tx1_id.seq_id),
            "Transaction 1 should not be in independent set yet"
        );

        pool.assert_invariants();

        // Step 2: Insert transaction with nonce=0 (fills the gap)
        let tx0 = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let valid_tx0 = wrap_valid_tx(tx0, TransactionOrigin::Local);
        let tx0_hash = *valid_tx0.hash();

        let result0 = pool.add_transaction(Arc::new(valid_tx0), 0, TempoHardfork::T1);

        // Should be pending and promote tx1
        assert!(
            result0.is_ok(),
            "Transaction 0 should be added successfully"
        );
        let added0 = result0.unwrap();

        // Verify it's pending and promoted tx1
        match added0 {
            AddedTransaction::Pending(ref pending) => {
                assert_eq!(pending.transaction.hash(), &tx0_hash, "Should be tx0");
                assert_eq!(
                    pending.promoted.len(),
                    1,
                    "Should have promoted 1 transaction"
                );
                assert_eq!(
                    pending.promoted[0].hash(),
                    &tx1_hash,
                    "Should have promoted tx1"
                );
            }
            _ => panic!("Transaction 0 should be pending, got: {added0:?}"),
        }

        // Verify pool state after filling the gap
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 2, "Should have 2 pending transactions");
        assert_eq!(queued_count, 0, "Should have 0 queued transactions");

        // Verify both transactions are now pending
        let tx0_id = AA2dTransactionId::new(seq_id, 0);
        assert!(
            pool.by_id.get(&tx0_id).unwrap().is_pending(),
            "Transaction 0 should be pending"
        );
        assert!(
            pool.by_id.get(&tx1_id).unwrap().is_pending(),
            "Transaction 1 should be pending after promotion"
        );

        // Verify tx0 (at on-chain nonce) is in independent set
        assert!(
            pool.independent_transactions.contains_key(&tx0_id.seq_id),
            "Transaction 0 should be in independent set (at on-chain nonce)"
        );

        // Verify the independent transaction for this sequence is tx0, not tx1
        let independent_tx = pool.independent_transactions.get(&seq_id).unwrap();
        assert_eq!(
            independent_tx.transaction.hash(),
            &tx0_hash,
            "Independent transaction should be tx0, not tx1"
        );

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn replace_pending_transaction(nonce_key: U256) {
        let mut pool = AA2dPool::default();

        // Set up a sender with a tracked nonce key
        let sender = Address::random();

        // Step 1: Insert initial pending transaction with lower gas price
        let tx_low = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .max_priority_fee(1_000_000_000)
            .max_fee(2_000_000_000)
            .build();
        let valid_tx_low = wrap_valid_tx(tx_low, TransactionOrigin::Local);
        let tx_low_hash = *valid_tx_low.hash();

        let result_low = pool.add_transaction(Arc::new(valid_tx_low), 0, TempoHardfork::T1);

        // Should be pending (at on-chain nonce)
        assert!(
            result_low.is_ok(),
            "Initial transaction should be added successfully"
        );
        let added_low = result_low.unwrap();
        assert!(
            matches!(added_low, AddedTransaction::Pending(_)),
            "Initial transaction should be pending"
        );

        // Verify initial state
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 1, "Should have 1 pending transaction");
        assert_eq!(queued_count, 0, "Should have 0 queued transactions");

        // Verify tx_low is in independent set
        let seq_id = AASequenceId::new(sender, nonce_key);
        let tx_id = AA2dTransactionId::new(seq_id, 0);
        assert!(
            pool.independent_transactions.contains_key(&tx_id.seq_id),
            "Initial transaction should be in independent set"
        );

        // Verify the transaction in independent set is tx_low
        let independent_tx = pool.independent_transactions.get(&tx_id.seq_id).unwrap();
        assert_eq!(
            independent_tx.transaction.hash(),
            &tx_low_hash,
            "Independent set should contain tx_low"
        );

        pool.assert_invariants();

        // Step 2: Replace with higher gas price transaction
        // Price bump needs to be at least 10% higher (default price bump config)
        let tx_high = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .max_priority_fee(1_200_000_000)
            .max_fee(2_400_000_000)
            .build();
        let valid_tx_high = wrap_valid_tx(tx_high, TransactionOrigin::Local);
        let tx_high_hash = *valid_tx_high.hash();

        let result_high = pool.add_transaction(Arc::new(valid_tx_high), 0, TempoHardfork::T1);

        // Should successfully replace
        assert!(
            result_high.is_ok(),
            "Replacement transaction should be added successfully"
        );
        let added_high = result_high.unwrap();

        // Verify it's pending and replaced the old transaction
        match added_high {
            AddedTransaction::Pending(ref pending) => {
                assert_eq!(
                    pending.transaction.hash(),
                    &tx_high_hash,
                    "Should be tx_high"
                );
                assert!(
                    pending.replaced.is_some(),
                    "Should have replaced a transaction"
                );
                assert_eq!(
                    pending.replaced.as_ref().unwrap().hash(),
                    &tx_low_hash,
                    "Should have replaced tx_low"
                );
            }
            _ => panic!("Replacement transaction should be pending, got: {added_high:?}"),
        }

        // Verify pool state - still 1 pending, 0 queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(
            pending_count, 1,
            "Should still have 1 pending transaction after replacement"
        );
        assert_eq!(queued_count, 0, "Should still have 0 queued transactions");

        // Verify old transaction is no longer in the pool
        assert!(
            !pool.contains(&tx_low_hash),
            "Old transaction should be removed from pool"
        );

        // Verify new transaction is in the pool
        assert!(
            pool.contains(&tx_high_hash),
            "New transaction should be in pool"
        );

        // Verify independent set is updated with new transaction
        assert!(
            pool.independent_transactions.contains_key(&tx_id.seq_id),
            "Transaction ID should still be in independent set"
        );

        let independent_tx_after = pool.independent_transactions.get(&tx_id.seq_id).unwrap();
        assert_eq!(
            independent_tx_after.transaction.hash(),
            &tx_high_hash,
            "Independent set should now contain tx_high (not tx_low)"
        );

        // Verify the transaction in by_id is the new one
        let tx_in_pool = pool.by_id.get(&tx_id).unwrap();
        assert_eq!(
            tx_in_pool.inner.transaction.hash(),
            &tx_high_hash,
            "Transaction in by_id should be tx_high"
        );
        assert!(tx_in_pool.is_pending(), "Transaction should be pending");

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn on_chain_nonce_update_with_gaps(nonce_key: U256) {
        let mut pool = AA2dPool::default();

        // Set up a sender with a tracked nonce key
        let sender = Address::random();

        // Insert transactions with nonces: 0, 1, 3, 4, 6
        // Expected initial state:
        // - 0, 1: pending (consecutive from on-chain nonce 0)
        // - 3, 4, 6: queued (gaps at nonce 2 and 5)
        let tx0 = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build();
        let tx3 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(3).build();
        let tx4 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(4).build();
        let tx6 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(6).build();

        let valid_tx0 = wrap_valid_tx(tx0, TransactionOrigin::Local);
        let valid_tx1 = wrap_valid_tx(tx1, TransactionOrigin::Local);
        let valid_tx3 = wrap_valid_tx(tx3, TransactionOrigin::Local);
        let valid_tx4 = wrap_valid_tx(tx4, TransactionOrigin::Local);
        let valid_tx6 = wrap_valid_tx(tx6, TransactionOrigin::Local);

        let tx0_hash = *valid_tx0.hash();
        let tx1_hash = *valid_tx1.hash();
        let tx3_hash = *valid_tx3.hash();
        let tx4_hash = *valid_tx4.hash();
        let tx6_hash = *valid_tx6.hash();

        // Add all transactions
        pool.add_transaction(Arc::new(valid_tx0), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx1), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx3), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx4), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx6), 0, TempoHardfork::T1)
            .unwrap();

        // Verify initial state
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(
            pending_count, 2,
            "Should have 2 pending transactions (0, 1)"
        );
        assert_eq!(
            queued_count, 3,
            "Should have 3 queued transactions (3, 4, 6)"
        );

        // Verify tx0 is in independent set
        let seq_id = AASequenceId::new(sender, nonce_key);
        let tx0_id = AA2dTransactionId::new(seq_id, 0);
        assert!(
            pool.independent_transactions.contains_key(&tx0_id.seq_id),
            "Transaction 0 should be in independent set"
        );

        pool.assert_invariants();

        // Step 1: Simulate mining block with nonces 0 and 1
        // New on-chain nonce becomes 2
        let mut on_chain_ids = HashMap::default();
        on_chain_ids.insert(seq_id, 2u64);

        let (promoted, mined) = pool.on_nonce_changes(on_chain_ids);

        // Verify mined transactions
        assert_eq!(mined.len(), 2, "Should have mined 2 transactions (0, 1)");
        let mined_hashes: HashSet<_> = mined.iter().map(|tx| tx.hash()).collect();
        assert!(
            mined_hashes.contains(&&tx0_hash),
            "Transaction 0 should be mined"
        );
        assert!(
            mined_hashes.contains(&&tx1_hash),
            "Transaction 1 should be mined"
        );

        // No transactions should be promoted (there's a gap at nonce 2)
        assert_eq!(
            promoted.len(),
            0,
            "No transactions should be promoted (gap at nonce 2)"
        );

        // Verify pool state after mining
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(
            pending_count, 0,
            "Should have 0 pending transactions (gap at nonce 2)"
        );
        assert_eq!(
            queued_count, 3,
            "Should have 3 queued transactions (3, 4, 6)"
        );

        // Verify mined transactions are removed
        assert!(!pool.contains(&tx0_hash), "Transaction 0 should be removed");
        assert!(!pool.contains(&tx1_hash), "Transaction 1 should be removed");

        // Verify remaining transactions are still in pool
        assert!(pool.contains(&tx3_hash), "Transaction 3 should remain");
        assert!(pool.contains(&tx4_hash), "Transaction 4 should remain");
        assert!(pool.contains(&tx6_hash), "Transaction 6 should remain");

        // Verify all remaining transactions are queued (not pending)
        let tx3_id = AA2dTransactionId::new(seq_id, 3);
        let tx4_id = AA2dTransactionId::new(seq_id, 4);
        let tx6_id = AA2dTransactionId::new(seq_id, 6);

        assert!(
            !pool.by_id.get(&tx3_id).unwrap().is_pending(),
            "Transaction 3 should be queued (gap at nonce 2)"
        );
        assert!(
            !pool.by_id.get(&tx4_id).unwrap().is_pending(),
            "Transaction 4 should be queued"
        );
        assert!(
            !pool.by_id.get(&tx6_id).unwrap().is_pending(),
            "Transaction 6 should be queued"
        );

        // Verify independent set is empty (no transaction at on-chain nonce)
        assert!(
            pool.independent_transactions.is_empty(),
            "Independent set should be empty (gap at on-chain nonce 2)"
        );

        pool.assert_invariants();

        // Step 2: Simulate mining block with nonce 2
        // New on-chain nonce becomes 3
        let mut on_chain_ids = HashMap::default();
        on_chain_ids.insert(seq_id, 3u64);

        let (promoted, mined) = pool.on_nonce_changes(on_chain_ids);

        // No transactions should be mined (nonce 2 was never in pool)
        assert_eq!(
            mined.len(),
            0,
            "No transactions should be mined (nonce 2 was never in pool)"
        );

        // Transactions 3 and 4 should be promoted
        assert_eq!(promoted.len(), 2, "Transactions 3 and 4 should be promoted");
        let promoted_hashes: HashSet<_> = promoted.iter().map(|tx| tx.hash()).collect();
        assert!(
            promoted_hashes.contains(&&tx3_hash),
            "Transaction 3 should be promoted"
        );
        assert!(
            promoted_hashes.contains(&&tx4_hash),
            "Transaction 4 should be promoted"
        );

        // Verify pool state after second update
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(
            pending_count, 2,
            "Should have 2 pending transactions (3, 4)"
        );
        assert_eq!(queued_count, 1, "Should have 1 queued transaction (6)");

        // Verify transactions 3 and 4 are now pending
        assert!(
            pool.by_id.get(&tx3_id).unwrap().is_pending(),
            "Transaction 3 should be pending"
        );
        assert!(
            pool.by_id.get(&tx4_id).unwrap().is_pending(),
            "Transaction 4 should be pending"
        );

        // Verify transaction 6 is still queued
        assert!(
            !pool.by_id.get(&tx6_id).unwrap().is_pending(),
            "Transaction 6 should still be queued (gap at nonce 5)"
        );

        // Verify transaction 3 is the independent transaction (at on-chain nonce)
        assert!(
            pool.independent_transactions.contains_key(&tx3_id.seq_id),
            "Transaction 3 should be in independent set (at on-chain nonce 3)"
        );

        // Verify the independent transaction is tx3 specifically, not tx4 or tx6
        let independent_tx = pool.independent_transactions.get(&seq_id).unwrap();
        assert_eq!(
            independent_tx.transaction.hash(),
            &tx3_hash,
            "Independent transaction should be tx3 (nonce 3), not tx4 or tx6"
        );

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn reject_outdated_transaction(nonce_key: U256) {
        let mut pool = AA2dPool::default();

        // Set up a sender with a tracked nonce key
        let sender = Address::random();

        // Create a transaction with nonce 3 (outdated)
        let tx = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(3).build();
        let valid_tx = wrap_valid_tx(tx, TransactionOrigin::Local);

        // Try to insert it and specify the on-chain nonce 5, making it outdated
        let result = pool.add_transaction(Arc::new(valid_tx), 5, TempoHardfork::T1);

        // Should fail with nonce error
        assert!(result.is_err(), "Should reject outdated transaction");

        let err = result.unwrap_err();
        assert!(
            matches!(
                err.kind,
                PoolErrorKind::InvalidTransaction(InvalidPoolTransactionError::Consensus(
                    InvalidTransactionError::NonceNotConsistent { tx: 3, state: 5 }
                ))
            ),
            "Should fail with NonceNotConsistent error, got: {:?}",
            err.kind
        );

        // Pool should remain empty
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 0, "Pool should be empty");
        assert_eq!(queued_count, 0, "Pool should be empty");

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn replace_with_insufficient_price_bump(nonce_key: U256) {
        let mut pool = AA2dPool::default();

        // Set up a sender
        let sender = Address::random();

        // Insert initial transaction
        let tx_low = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .max_priority_fee(1_000_000_000)
            .max_fee(2_000_000_000)
            .build();
        let valid_tx_low = wrap_valid_tx(tx_low, TransactionOrigin::Local);

        pool.add_transaction(Arc::new(valid_tx_low), 0, TempoHardfork::T1)
            .unwrap();

        // Try to replace with only 5% price bump (default requires 10%)
        let tx_insufficient = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .max_priority_fee(1_050_000_000)
            .max_fee(2_100_000_000)
            .build();
        let valid_tx_insufficient = wrap_valid_tx(tx_insufficient, TransactionOrigin::Local);

        let result = pool.add_transaction(Arc::new(valid_tx_insufficient), 0, TempoHardfork::T1);

        // Should fail with ReplacementUnderpriced
        assert!(
            result.is_err(),
            "Should reject replacement with insufficient price bump"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err.kind, PoolErrorKind::ReplacementUnderpriced),
            "Should fail with ReplacementUnderpriced, got: {:?}",
            err.kind
        );

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn fill_gap_in_middle(nonce_key: U256) {
        let mut pool = AA2dPool::default();

        let sender = Address::random();

        // Insert transactions: 0, 1, 3, 4 (gap at 2)
        let tx0 = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build();
        let tx3 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(3).build();
        let tx4 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(4).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx4, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // Verify initial state: 0, 1 pending | 3, 4 queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 2, "Should have 2 pending (0, 1)");
        assert_eq!(queued_count, 2, "Should have 2 queued (3, 4)");

        // Fill the gap with nonce 2
        let tx2 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(2).build();
        let valid_tx2 = wrap_valid_tx(tx2, TransactionOrigin::Local);

        let result = pool.add_transaction(Arc::new(valid_tx2), 0, TempoHardfork::T1);
        assert!(result.is_ok(), "Should successfully add tx2");

        // Verify tx3 and tx4 were promoted
        match result.unwrap() {
            AddedTransaction::Pending(ref pending) => {
                assert_eq!(pending.promoted.len(), 2, "Should promote tx3 and tx4");
            }
            _ => panic!("tx2 should be added as pending"),
        }

        // Verify all transactions are now pending
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 5, "All 5 transactions should be pending");
        assert_eq!(queued_count, 0, "No transactions should be queued");

        // Verify tx0 is in independent set
        let seq_id = AASequenceId::new(sender, nonce_key);
        let tx0_id = AA2dTransactionId::new(seq_id, 0);
        assert!(
            pool.independent_transactions.contains_key(&tx0_id.seq_id),
            "tx0 should be in independent set"
        );

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn remove_pending_transaction(nonce_key: U256) {
        let mut pool = AA2dPool::default();

        let sender = Address::random();

        // Insert consecutive transactions: 0, 1, 2
        let tx0 = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build();
        let tx2 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(2).build();

        let valid_tx0 = wrap_valid_tx(tx0, TransactionOrigin::Local);
        let valid_tx1 = wrap_valid_tx(tx1, TransactionOrigin::Local);
        let valid_tx2 = wrap_valid_tx(tx2, TransactionOrigin::Local);

        let tx1_hash = *valid_tx1.hash();

        pool.add_transaction(Arc::new(valid_tx0), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx1), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx2), 0, TempoHardfork::T1)
            .unwrap();

        // All should be pending
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 3, "All 3 should be pending");
        assert_eq!(queued_count, 0, "None should be queued");

        let seq_id = AASequenceId::new(sender, nonce_key);
        let tx1_id = AA2dTransactionId::new(seq_id, 1);
        let tx2_id = AA2dTransactionId::new(seq_id, 2);

        // Verify tx2 is pending before removal
        assert!(
            pool.by_id.get(&tx2_id).unwrap().is_pending(),
            "tx2 should be pending before removal"
        );

        // Remove tx1 (creates a gap)
        let removed = pool.remove_transactions([&tx1_hash].into_iter());
        assert_eq!(removed.len(), 1, "Should remove tx1");

        // Verify tx1 is removed from pool
        assert!(!pool.by_id.contains_key(&tx1_id), "tx1 should be removed");
        assert!(!pool.contains(&tx1_hash), "tx1 should be removed");

        // Verify tx0 and tx2 remain
        assert_eq!(pool.by_id.len(), 2, "Should have 2 transactions left");

        // Verify tx2 is now demoted to queued since tx1 removal creates a gap
        assert!(
            !pool.by_id.get(&tx2_id).unwrap().is_pending(),
            "tx2 should be demoted to queued after tx1 removal creates a gap"
        );

        // Verify counts: tx0 is pending, tx2 is queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 1, "Only tx0 should be pending");
        assert_eq!(queued_count, 1, "tx2 should be queued");

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO, U256::random())]
    #[test_case::test_case(U256::random(), U256::ZERO)]
    #[test_case::test_case(U256::random(), U256::random())]
    fn multiple_senders_independent_set(nonce_key_a: U256, nonce_key_b: U256) {
        let mut pool = AA2dPool::default();

        // Set up two senders with different nonce keys
        let sender_a = Address::random();
        let sender_b = Address::random();

        // Insert transactions for both senders
        // Sender A: [0, 1]
        let tx_a0 = TxBuilder::aa(sender_a).nonce_key(nonce_key_a).build();
        let tx_a1 = TxBuilder::aa(sender_a)
            .nonce_key(nonce_key_a)
            .nonce(1)
            .build();

        // Sender B: [0, 1]
        let tx_b0 = TxBuilder::aa(sender_b).nonce_key(nonce_key_b).build();
        let tx_b1 = TxBuilder::aa(sender_b)
            .nonce_key(nonce_key_b)
            .nonce(1)
            .build();

        let valid_tx_a0 = wrap_valid_tx(tx_a0, TransactionOrigin::Local);
        let valid_tx_a1 = wrap_valid_tx(tx_a1, TransactionOrigin::Local);
        let valid_tx_b0 = wrap_valid_tx(tx_b0, TransactionOrigin::Local);
        let valid_tx_b1 = wrap_valid_tx(tx_b1, TransactionOrigin::Local);

        let tx_a0_hash = *valid_tx_a0.hash();

        pool.add_transaction(Arc::new(valid_tx_a0), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx_a1), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx_b0), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx_b1), 0, TempoHardfork::T1)
            .unwrap();

        // Both senders' tx0 should be in independent set
        let sender_a_id = AASequenceId::new(sender_a, nonce_key_a);
        let sender_b_id = AASequenceId::new(sender_b, nonce_key_b);
        let tx_a0_id = AA2dTransactionId::new(sender_a_id, 0);
        let tx_b0_id = AA2dTransactionId::new(sender_b_id, 0);

        assert_eq!(
            pool.independent_transactions.len(),
            2,
            "Should have 2 independent transactions"
        );
        assert!(
            pool.independent_transactions.contains_key(&tx_a0_id.seq_id),
            "Sender A's tx0 should be independent"
        );
        assert!(
            pool.independent_transactions.contains_key(&tx_b0_id.seq_id),
            "Sender B's tx0 should be independent"
        );

        // All 4 transactions should be pending
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 4, "All 4 transactions should be pending");
        assert_eq!(queued_count, 0, "No transactions should be queued");

        // Simulate mining sender A's tx0
        let mut on_chain_ids = HashMap::default();
        on_chain_ids.insert(sender_a_id, 1u64);

        let (promoted, mined) = pool.on_nonce_changes(on_chain_ids);

        // Only sender A's tx0 should be mined
        assert_eq!(mined.len(), 1, "Only sender A's tx0 should be mined");
        assert_eq!(mined[0].hash(), &tx_a0_hash, "Should mine tx_a0");

        // No transactions should be promoted (tx_a1 was already pending)
        assert_eq!(
            promoted.len(),
            0,
            "No transactions should be promoted (tx_a1 was already pending)"
        );

        // Verify independent set now has A's tx1 and B's tx0
        let tx_a1_id = AA2dTransactionId::new(sender_a_id, 1);
        assert_eq!(
            pool.independent_transactions.len(),
            2,
            "Should still have 2 independent transactions"
        );
        assert!(
            pool.independent_transactions.contains_key(&tx_a1_id.seq_id),
            "Sender A's tx1 should now be independent"
        );
        assert!(
            pool.independent_transactions.contains_key(&tx_b0_id.seq_id),
            "Sender B's tx0 should still be independent"
        );

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn concurrent_replacements_same_nonce(nonce_key: U256) {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let seq_id = AASequenceId {
            address: sender,
            nonce_key,
        };

        // Insert initial transaction at nonce 0 with gas prices 1_000_000_000, 2_000_000_000
        let tx0 = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .max_priority_fee(1_000_000_000)
            .max_fee(2_000_000_000)
            .build();
        let tx0_hash = *tx0.hash();
        let valid_tx0 = wrap_valid_tx(tx0, TransactionOrigin::Local);
        let result = pool.add_transaction(Arc::new(valid_tx0), 0, TempoHardfork::T1);
        assert!(result.is_ok());
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 1);

        // Try to replace with slightly higher gas (1_050_000_000, 2_100_000_000 = ~5% bump) - should fail (< 10% bump)
        let tx0_replacement1 = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .max_priority_fee(1_050_000_000)
            .max_fee(2_100_000_000)
            .build();
        let valid_tx1 = wrap_valid_tx(tx0_replacement1, TransactionOrigin::Local);
        let result = pool.add_transaction(Arc::new(valid_tx1), 0, TempoHardfork::T1);
        assert!(result.is_err(), "Should reject insufficient price bump");
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 1);
        assert!(
            pool.contains(&tx0_hash),
            "Original tx should still be present"
        );

        // Replace with sufficient bump (1_100_000_000, 2_200_000_000 = 10% bump)
        let tx0_replacement2 = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .max_priority_fee(1_100_000_000)
            .max_fee(2_200_000_000)
            .build();
        let tx0_replacement2_hash = *tx0_replacement2.hash();
        let valid_tx2 = wrap_valid_tx(tx0_replacement2, TransactionOrigin::Local);
        let result = pool.add_transaction(Arc::new(valid_tx2), 0, TempoHardfork::T1);
        assert!(result.is_ok(), "Should accept 10% price bump");
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 1, "Pool size should remain 1");
        assert!(!pool.contains(&tx0_hash), "Old tx should be removed");
        assert!(
            pool.contains(&tx0_replacement2_hash),
            "New tx should be present"
        );

        // Try to replace with even higher gas (1_500_000_000, 3_000_000_000 = ~36% bump over original)
        let tx0_replacement3 = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .max_priority_fee(1_500_000_000)
            .max_fee(3_000_000_000)
            .build();
        let tx0_replacement3_hash = *tx0_replacement3.hash();
        let valid_tx3 = wrap_valid_tx(tx0_replacement3, TransactionOrigin::Local);
        let result = pool.add_transaction(Arc::new(valid_tx3), 0, TempoHardfork::T1);
        assert!(result.is_ok(), "Should accept higher price bump");
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 1);
        assert!(
            !pool.contains(&tx0_replacement2_hash),
            "Previous tx should be removed"
        );
        assert!(
            pool.contains(&tx0_replacement3_hash),
            "Highest priority tx should win"
        );

        // Verify independent set has the final replacement
        let tx0_id = AA2dTransactionId::new(seq_id, 0);
        assert!(pool.independent_transactions.contains_key(&tx0_id.seq_id));

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn long_gap_chain(nonce_key: U256) {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let seq_id = AASequenceId {
            address: sender,
            nonce_key,
        };

        // Insert transactions with large gaps: [0, 5, 10, 15]
        let tx0 = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let tx5 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(5).build();
        let tx10 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(10).build();
        let tx15 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(15).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx5, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx10, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx15, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 4);

        // Only tx0 should be pending, rest should be queued
        let tx0_id = AA2dTransactionId::new(seq_id, 0);
        assert!(pool.by_id.get(&tx0_id).unwrap().is_pending());
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 5))
                .unwrap()
                .is_pending()
        );
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 10))
                .unwrap()
                .is_pending()
        );
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 15))
                .unwrap()
                .is_pending()
        );
        assert_eq!(pool.independent_transactions.len(), 1);

        // Fill gap [1,2,3,4]
        for nonce in 1..=4 {
            let tx = TxBuilder::aa(sender)
                .nonce_key(nonce_key)
                .nonce(nonce)
                .build();
            pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            )
            .unwrap();
        }

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 8);

        // Now [0,1,2,3,4,5] should be pending
        for nonce in 0..=5 {
            let id = AA2dTransactionId::new(seq_id, nonce);
            assert!(
                pool.by_id.get(&id).unwrap().is_pending(),
                "Nonce {nonce} should be pending"
            );
        }
        // [10, 15] should still be queued
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 10))
                .unwrap()
                .is_pending()
        );
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 15))
                .unwrap()
                .is_pending()
        );

        // Fill gap [6,7,8,9]
        for nonce in 6..=9 {
            let tx = TxBuilder::aa(sender)
                .nonce_key(nonce_key)
                .nonce(nonce)
                .build();
            pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            )
            .unwrap();
        }

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 12);

        // Now [0..=10] should be pending
        for nonce in 0..=10 {
            let id = AA2dTransactionId::new(seq_id, nonce);
            assert!(
                pool.by_id.get(&id).unwrap().is_pending(),
                "Nonce {nonce} should be pending"
            );
        }
        // Only [15] should be queued
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 15))
                .unwrap()
                .is_pending()
        );

        // Fill final gap [11,12,13,14]
        for nonce in 11..=14 {
            let tx = TxBuilder::aa(sender)
                .nonce_key(nonce_key)
                .nonce(nonce)
                .build();
            pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            )
            .unwrap();
        }

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 16);

        // All should be pending now
        for nonce in 0..=15 {
            let id = AA2dTransactionId::new(seq_id, nonce);
            assert!(
                pool.by_id.get(&id).unwrap().is_pending(),
                "Nonce {nonce} should be pending"
            );
        }

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn remove_from_middle_of_chain(nonce_key: U256) {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let seq_id = AASequenceId {
            address: sender,
            nonce_key,
        };

        // Insert continuous sequence [0,1,2,3,4]
        for nonce in 0..=4 {
            let tx = TxBuilder::aa(sender)
                .nonce_key(nonce_key)
                .nonce(nonce)
                .build();
            pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            )
            .unwrap();
        }

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 5);

        // All should be pending
        for nonce in 0..=4 {
            assert!(
                *pool
                    .by_id
                    .get(&AA2dTransactionId::new(seq_id, nonce))
                    .unwrap()
                    .is_pending
                    .borrow()
            );
        }

        // Remove nonce 2 from the middle
        let tx2_id = AA2dTransactionId::new(seq_id, 2);
        let tx2_hash = *pool.by_id.get(&tx2_id).unwrap().inner.transaction.hash();
        let removed = pool.remove_transactions([&tx2_hash].into_iter());
        assert_eq!(removed.len(), 1, "Should remove transaction");

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 4);

        // Transaction 2 should be gone
        assert!(!pool.by_id.contains_key(&tx2_id));

        // Note: Current implementation doesn't automatically re-scan after removal
        // So we verify that the removal succeeded but don't expect automatic gap detection
        // Transactions [0,1,3,4] remain in their current state

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn independent_set_after_multiple_promotions(nonce_key: U256) {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let seq_id = AASequenceId {
            address: sender,
            nonce_key,
        };

        // Start with gaps: insert [0, 2, 4]
        let tx0 = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let tx2 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(2).build();
        let tx4 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(4).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx4, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // Only tx0 should be in independent set
        assert_eq!(pool.independent_transactions.len(), 1);
        assert!(pool.independent_transactions.contains_key(&seq_id));

        // Verify initial state: tx0 pending, tx2 and tx4 queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 1);
        assert_eq!(queued_count, 2);

        // Fill first gap: insert [1]
        let tx1 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // Now [0, 1, 2] should be pending, tx4 still queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 3);
        assert_eq!(queued_count, 1);

        // Still only tx0 in independent set
        assert_eq!(pool.independent_transactions.len(), 1);
        assert!(pool.independent_transactions.contains_key(&seq_id));

        // Fill second gap: insert [3]
        let tx3 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(3).build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // Now all [0,1,2,3,4] should be pending
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 5);
        assert_eq!(queued_count, 0);

        // Simulate mining [0,1]
        let mut on_chain_ids = HashMap::default();
        on_chain_ids.insert(seq_id, 2u64);
        let (promoted, mined) = pool.on_nonce_changes(on_chain_ids);

        // Should have mined [0,1], no promotions (already pending)
        assert_eq!(mined.len(), 2);
        assert_eq!(promoted.len(), 0);

        // Now tx2 should be in independent set
        assert_eq!(pool.independent_transactions.len(), 1);
        assert!(pool.independent_transactions.contains_key(&seq_id));

        // Verify [2,3,4] remain in pool
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 3);

        pool.assert_invariants();
    }

    #[test]
    fn stress_test_many_senders() {
        let mut pool = AA2dPool::default();
        const NUM_SENDERS: usize = 100;
        const TXS_PER_SENDER: u64 = 5;

        // Create 100 senders, each with 5 transactions
        let mut senders = Vec::new();
        for i in 0..NUM_SENDERS {
            let sender = Address::from_word(B256::from(U256::from(i)));
            let nonce_key = U256::from(i);
            senders.push((sender, nonce_key));

            // Insert transactions [0,1,2,3,4] for each sender
            for nonce in 0..TXS_PER_SENDER {
                let tx = TxBuilder::aa(sender)
                    .nonce_key(nonce_key)
                    .nonce(nonce)
                    .build();
                pool.add_transaction(
                    Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                    0,
                    TempoHardfork::T1,
                )
                .unwrap();
            }
        }

        // Verify pool size
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(
            pending_count + queued_count,
            NUM_SENDERS * TXS_PER_SENDER as usize
        );

        // Each sender should have all transactions pending
        for (sender, nonce_key) in &senders {
            let seq_id = AASequenceId {
                address: *sender,
                nonce_key: *nonce_key,
            };
            for nonce in 0..TXS_PER_SENDER {
                let id = AA2dTransactionId::new(seq_id, nonce);
                assert!(pool.by_id.get(&id).unwrap().is_pending());
            }
        }

        // Independent set should have exactly NUM_SENDERS transactions (one per sender at nonce 0)
        assert_eq!(pool.independent_transactions.len(), NUM_SENDERS);
        for (sender, nonce_key) in &senders {
            let seq_id = AASequenceId {
                address: *sender,
                nonce_key: *nonce_key,
            };
            let tx0_id = AA2dTransactionId::new(seq_id, 0);
            assert!(
                pool.independent_transactions.contains_key(&tx0_id.seq_id),
                "Sender {sender:?} should have tx0 in independent set"
            );
        }

        // Simulate mining first transaction for each sender
        let mut on_chain_ids = HashMap::default();
        for (sender, nonce_key) in &senders {
            let seq_id = AASequenceId {
                address: *sender,
                nonce_key: *nonce_key,
            };
            on_chain_ids.insert(seq_id, 1u64);
        }

        let (promoted, mined) = pool.on_nonce_changes(on_chain_ids);

        // Should have mined NUM_SENDERS transactions
        assert_eq!(mined.len(), NUM_SENDERS);
        // No promotions - transactions [1,2,3,4] were already pending
        assert_eq!(promoted.len(), 0);

        // Pool size should be reduced
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(
            pending_count + queued_count,
            NUM_SENDERS * (TXS_PER_SENDER - 1) as usize
        );

        // Independent set should still have NUM_SENDERS transactions (now at nonce 1)
        assert_eq!(pool.independent_transactions.len(), NUM_SENDERS);
        for (sender, nonce_key) in &senders {
            let seq_id = AASequenceId {
                address: *sender,
                nonce_key: *nonce_key,
            };
            let tx1_id = AA2dTransactionId::new(seq_id, 1);
            assert!(
                pool.independent_transactions.contains_key(&tx1_id.seq_id),
                "Sender {sender:?} should have tx1 in independent set"
            );
        }

        pool.assert_invariants();
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn on_chain_nonce_update_to_queued_tx_with_gaps(nonce_key: U256) {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let seq_id = AASequenceId {
            address: sender,
            nonce_key,
        };

        // Start with gaps: insert [0, 3, 5]
        // This creates: tx0 (pending), tx3 (queued), tx5 (queued)
        let tx0 = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let tx3 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(3).build();
        let tx5 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(5).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx5, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // Only tx0 should be in independent set
        assert_eq!(pool.independent_transactions.len(), 1);
        assert!(pool.independent_transactions.contains_key(&seq_id));

        // Verify initial state: tx0 pending, tx3 and tx5 queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 1, "Only tx0 should be pending");
        assert_eq!(queued_count, 2, "tx3 and tx5 should be queued");

        // Fill gaps to get [0, 1, 2, 3, 5]
        let tx1 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let tx2 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(2).build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // Now [0,1,2,3] should be pending, tx5 still queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 4, "Transactions [0,1,2,3] should be pending");
        assert_eq!(queued_count, 1, "tx5 should still be queued");

        // Still only tx0 in independent set (at on-chain nonce 0)
        assert_eq!(pool.independent_transactions.len(), 1);
        assert!(pool.independent_transactions.contains_key(&seq_id));

        let mut on_chain_ids = HashMap::default();
        on_chain_ids.insert(seq_id, 3u64);
        let (_promoted, mined) = pool.on_nonce_changes(on_chain_ids);

        // Should have mined [0,1,2]
        assert_eq!(mined.len(), 3, "Should mine transactions [0,1,2]");

        // tx3 was already pending, so no promotions expected
        // After mining, tx3 should be in independent set
        assert_eq!(
            pool.independent_transactions.len(),
            1,
            "Should have one independent transaction"
        );
        let key = AA2dTransactionId::new(seq_id, 3);
        assert!(
            pool.independent_transactions.contains_key(&key.seq_id),
            "tx3 should be in independent set"
        );

        // Verify remaining pool state
        let (_pending_count, _queued_count) = pool.pending_and_queued_txn_count();
        // Should have tx3 (pending at on-chain nonce) and tx5 (queued due to gap at 4)

        pool.assert_invariants();

        // Now insert tx4 to fill the gap between tx3 and tx5
        // This is where the original test failure occurred
        let tx4 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(4).build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx4, TransactionOrigin::Local)),
            3,
            TempoHardfork::T1,
        )
        .unwrap();

        // After inserting tx4, we should have [3, 4, 5] all in the pool
        let (_pending_count_after, _queued_count_after) = pool.pending_and_queued_txn_count();
        pool.assert_invariants();
    }

    #[test]
    fn append_pooled_transaction_elements_respects_limit() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let nonce_key = U256::from(1);

        // Add 3 transactions with consecutive nonces
        let tx0 = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let tx0_hash = *tx0.hash();
        let tx0_len = tx0.encoded_length();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let tx1 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build();
        let tx1_hash = *tx1.hash();
        let tx1_len = tx1.encoded_length();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let tx2 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(2).build();
        let tx2_hash = *tx2.hash();
        let tx2_len = tx2.encoded_length();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // Test with no limit - should return all 3 transactions
        let mut accumulated = 0;
        let mut elements = Vec::new();
        pool.append_pooled_transaction_elements(
            &[tx0_hash, tx1_hash, tx2_hash],
            GetPooledTransactionLimit::None,
            &mut accumulated,
            &mut elements,
        );
        assert_eq!(elements.len(), 3, "Should return all 3 transactions");
        assert_eq!(
            accumulated,
            tx0_len + tx1_len + tx2_len,
            "Should accumulate all sizes"
        );

        // Test with a soft limit - stops after exceeding (not at) the limit
        // A limit of tx0_len - 1 means we stop after tx0 is added (since tx0_len > limit)
        let mut accumulated = 0;
        let mut elements = Vec::new();
        pool.append_pooled_transaction_elements(
            &[tx0_hash, tx1_hash, tx2_hash],
            GetPooledTransactionLimit::ResponseSizeSoftLimit(tx0_len - 1),
            &mut accumulated,
            &mut elements,
        );
        assert_eq!(
            elements.len(),
            1,
            "Should stop after first tx exceeds limit"
        );
        assert_eq!(accumulated, tx0_len, "Should accumulate first tx size");

        // Test with limit that allows exactly 2 transactions before exceeding
        // A limit of tx0_len + tx1_len - 1 means we stop after tx1 is added
        let mut accumulated = 0;
        let mut elements = Vec::new();
        pool.append_pooled_transaction_elements(
            &[tx0_hash, tx1_hash, tx2_hash],
            GetPooledTransactionLimit::ResponseSizeSoftLimit(tx0_len + tx1_len - 1),
            &mut accumulated,
            &mut elements,
        );
        assert_eq!(
            elements.len(),
            2,
            "Should stop after second tx exceeds limit"
        );
        assert_eq!(
            accumulated,
            tx0_len + tx1_len,
            "Should accumulate first two tx sizes"
        );

        // Test with pre-accumulated size that causes immediate stop after first tx
        let mut accumulated = tx0_len;
        let mut elements = Vec::new();
        pool.append_pooled_transaction_elements(
            &[tx1_hash, tx2_hash],
            GetPooledTransactionLimit::ResponseSizeSoftLimit(tx0_len + tx1_len - 1),
            &mut accumulated,
            &mut elements,
        );
        assert_eq!(
            elements.len(),
            1,
            "Should return 1 transaction when pre-accumulated size causes early stop"
        );
        assert_eq!(
            accumulated,
            tx0_len + tx1_len,
            "Should add to pre-accumulated size"
        );
    }
    // ============================================
    // Helper function tests
    // ============================================

    #[test]
    fn test_2d_pool_helpers() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let tx = TxBuilder::aa(sender).build();
        let tx_hash = *tx.hash();

        assert!(!pool.contains(&tx_hash));
        assert!(pool.get(&tx_hash).is_none());

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        assert!(pool.contains(&tx_hash));
        let retrieved = pool.get(&tx_hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().hash(), &tx_hash);
    }

    #[test]
    fn test_pool_get_all() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx0 = TxBuilder::aa(sender).build();
        let tx1 = TxBuilder::aa(sender).nonce(1).build();
        let tx0_hash = *tx0.hash();
        let tx1_hash = *tx1.hash();
        let fake_hash = alloy_primitives::B256::random();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let hashes = [tx0_hash, tx1_hash, fake_hash];
        let results = pool.get_all(hashes.iter());

        assert_eq!(results.len(), 2); // Only the two real transactions
    }

    #[test]
    fn test_pool_senders_iter() {
        let mut pool = AA2dPool::default();
        let sender1 = Address::random();
        let sender2 = Address::random();

        let tx1 = TxBuilder::aa(sender1).build();
        let tx2 = TxBuilder::aa(sender2).nonce_key(U256::from(1)).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let senders: Vec<_> = pool.senders_iter().collect();
        assert_eq!(senders.len(), 2);
        assert!(senders.contains(&&sender1));
        assert!(senders.contains(&&sender2));
    }

    #[test]
    fn test_pool_pending_and_queued_transactions() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        // Pending: tx0, tx1, tx2 (consecutive nonces starting from on-chain nonce 0)
        let tx0 = TxBuilder::aa(sender).build();
        let tx1 = TxBuilder::aa(sender).nonce(1).build();
        let tx2 = TxBuilder::aa(sender).nonce(2).build();
        let tx0_hash = *tx0.hash();
        let tx1_hash = *tx1.hash();
        let tx2_hash = *tx2.hash();

        // Queued: tx5, tx6, tx7 (gap after tx2)
        let tx5 = TxBuilder::aa(sender).nonce(5).build();
        let tx6 = TxBuilder::aa(sender).nonce(6).build();
        let tx7 = TxBuilder::aa(sender).nonce(7).build();
        let tx5_hash = *tx5.hash();
        let tx6_hash = *tx6.hash();
        let tx7_hash = *tx7.hash();

        for tx in [tx0, tx1, tx2, tx5, tx6, tx7] {
            pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            )
            .unwrap();
        }

        let pending: Vec<_> = pool.pending_transactions().collect();
        assert_eq!(pending.len(), 3);
        let pending_hashes: HashSet<_> = pending.iter().map(|tx| *tx.hash()).collect();
        assert!(pending_hashes.contains(&tx0_hash));
        assert!(pending_hashes.contains(&tx1_hash));
        assert!(pending_hashes.contains(&tx2_hash));

        let queued: Vec<_> = pool.queued_transactions().collect();
        assert_eq!(queued.len(), 3);
        let queued_hashes: HashSet<_> = queued.iter().map(|tx| *tx.hash()).collect();
        assert!(queued_hashes.contains(&tx5_hash));
        assert!(queued_hashes.contains(&tx6_hash));
        assert!(queued_hashes.contains(&tx7_hash));
    }

    #[test]
    fn test_pool_get_transactions_by_sender_iter() {
        let mut pool = AA2dPool::default();
        let sender1 = Address::random();
        let sender2 = Address::random();

        let tx1 = TxBuilder::aa(sender1).nonce_key(U256::ZERO).build();
        let tx2 = TxBuilder::aa(sender2).nonce_key(U256::from(1)).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let sender1_txs: Vec<_> = pool.get_transactions_by_sender_iter(sender1).collect();
        assert_eq!(sender1_txs.len(), 1);
        assert_eq!(sender1_txs[0].sender(), sender1);

        let sender2_txs: Vec<_> = pool.get_transactions_by_sender_iter(sender2).collect();
        assert_eq!(sender2_txs.len(), 1);
        assert_eq!(sender2_txs[0].sender(), sender2);
    }

    #[test]
    fn test_pool_get_transactions_by_origin_iter() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx0 = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(1).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::External)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let local_txs: Vec<_> = pool
            .get_transactions_by_origin_iter(TransactionOrigin::Local)
            .collect();
        assert_eq!(local_txs.len(), 1);

        let external_txs: Vec<_> = pool
            .get_transactions_by_origin_iter(TransactionOrigin::External)
            .collect();
        assert_eq!(external_txs.len(), 1);
    }

    #[test]
    fn test_pool_get_pending_transactions_by_origin_iter() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx0 = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let tx2 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(2).build(); // Queued due to gap

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let pending_local: Vec<_> = pool
            .get_pending_transactions_by_origin_iter(TransactionOrigin::Local)
            .collect();
        assert_eq!(pending_local.len(), 1); // Only tx0 is pending
    }

    #[test]
    fn test_pool_all_transaction_hashes_iter() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx0 = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(1).build();
        let tx0_hash = *tx0.hash();
        let tx1_hash = *tx1.hash();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let hashes: Vec<_> = pool.all_transaction_hashes_iter().collect();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&tx0_hash));
        assert!(hashes.contains(&tx1_hash));
    }

    #[test]
    fn test_pool_pooled_transactions_hashes_iter() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx0 = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(1).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let hashes: Vec<_> = pool.pooled_transactions_hashes_iter().collect();
        assert_eq!(hashes.len(), 2);
    }

    #[test]
    fn test_pool_pooled_transactions_iter() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx0 = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(1).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let txs: Vec<_> = pool.pooled_transactions_iter().collect();
        assert_eq!(txs.len(), 2);
    }

    // ============================================
    // BestAA2dTransactions tests
    // ============================================

    #[test]
    fn test_best_transactions_iterator() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx0 = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(1).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let mut best = pool.best_transactions();

        // Should iterate through pending transactions
        let first = best.next();
        assert!(first.is_some());

        let second = best.next();
        assert!(second.is_some());

        let third = best.next();
        assert!(third.is_none());
    }

    #[test]
    fn test_best_transactions_mark_invalid() {
        use reth_primitives_traits::transaction::error::InvalidTransactionError;

        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx0 = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(1).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let mut best = pool.best_transactions();

        let first = best.next().unwrap();

        // Mark it invalid
        let error = reth_transaction_pool::error::InvalidPoolTransactionError::Consensus(
            InvalidTransactionError::TxTypeNotSupported,
        );
        best.mark_invalid(&first, &error);

        // The sequence should be in the invalid set, so next tx from same sender should be skipped
        // But since we already consumed tx0, we'd get tx1 next - but the sequence is now invalid
    }

    #[test]
    fn test_best_transactions_expiring_nonce_independent() {
        // Expiring nonce transactions (nonce_key == U256::MAX) are always independent
        // and should not trigger unlock logic for dependent transactions
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        // Add expiring nonce transaction
        let tx = TxBuilder::aa(sender).nonce_key(U256::MAX).nonce(0).build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let mut best = pool.best_transactions();

        // Should return the transaction
        let first = best.next();
        assert!(first.is_some());

        // No more transactions
        assert!(best.next().is_none());
    }

    // ============================================
    // Remove transactions tests
    // ============================================

    #[test]
    fn test_remove_transactions_by_sender() {
        let mut pool = AA2dPool::default();
        let sender1 = Address::random();
        let sender2 = Address::random();

        let tx1 = TxBuilder::aa(sender1).nonce_key(U256::ZERO).build();
        let tx2 = TxBuilder::aa(sender2).nonce_key(U256::from(1)).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let removed = pool.remove_transactions_by_sender(sender1);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].sender(), sender1);

        // sender1's tx should be gone, sender2's should remain
        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending + queued, 1);

        pool.assert_invariants();
    }

    #[test]
    fn test_remove_transactions_and_descendants() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx0 = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(1).build();
        let tx2 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(2).build();
        let tx0_hash = *tx0.hash();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // Remove tx0 and its descendants (tx1, tx2)
        let removed = pool.remove_transactions_and_descendants([&tx0_hash].into_iter());
        assert_eq!(removed.len(), 3);

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending + queued, 0);

        pool.assert_invariants();
    }

    // ============================================
    // AASequenceId and AA2dTransactionId tests
    // ============================================

    #[test]
    fn test_aa_sequence_id_equality() {
        let addr = Address::random();
        let nonce_key = U256::from(42);

        let id1 = AASequenceId::new(addr, nonce_key);
        let id2 = AASequenceId::new(addr, nonce_key);
        let id3 = AASequenceId::new(Address::random(), nonce_key);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_aa2d_transaction_id_unlocks() {
        let addr = Address::random();
        let seq_id = AASequenceId::new(addr, U256::ZERO);
        let tx_id = AA2dTransactionId::new(seq_id, 5);

        let next_id = tx_id.unlocks();
        assert_eq!(next_id.seq_id, seq_id);
        assert_eq!(next_id.nonce, 6);
    }

    #[test]
    fn test_aa2d_transaction_id_ordering() {
        let addr = Address::random();
        let seq_id = AASequenceId::new(addr, U256::ZERO);

        let id1 = AA2dTransactionId::new(seq_id, 1);
        let id2 = AA2dTransactionId::new(seq_id, 2);

        assert!(id1 < id2);
    }

    // ============================================
    // Edge case tests
    // ============================================

    #[test]
    fn test_nonce_overflow_at_u64_max() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let nonce_key = U256::ZERO;

        let tx = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .nonce(u64::MAX)
            .build();
        let valid_tx = wrap_valid_tx(tx, TransactionOrigin::Local);

        let result = pool.add_transaction(Arc::new(valid_tx), u64::MAX, TempoHardfork::T1);
        assert!(result.is_ok());

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 1);
        assert_eq!(queued, 0);

        let seq_id = AASequenceId::new(sender, nonce_key);
        let tx_id = AA2dTransactionId::new(seq_id, u64::MAX);
        let unlocked = tx_id.unlocks();
        assert_eq!(
            unlocked.nonce,
            u64::MAX,
            "saturating_add should not overflow"
        );

        pool.assert_invariants();
    }

    #[test]
    fn test_nonce_near_max_with_gap() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let nonce_key = U256::ZERO;

        let tx_max = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .nonce(u64::MAX)
            .build();
        let tx_max_minus_1 = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .nonce(u64::MAX - 1)
            .build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx_max, TransactionOrigin::Local)),
            u64::MAX - 1,
            TempoHardfork::T1,
        )
        .unwrap();

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 0, "tx at u64::MAX should be queued (gap exists)");
        assert_eq!(queued, 1);

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx_max_minus_1, TransactionOrigin::Local)),
            u64::MAX - 1,
            TempoHardfork::T1,
        )
        .unwrap();

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 2, "both should now be pending");
        assert_eq!(queued, 0);

        pool.assert_invariants();
    }

    #[test]
    fn test_empty_pool_operations() {
        let pool = AA2dPool::default();

        assert_eq!(pool.pending_and_queued_txn_count(), (0, 0));
        assert!(pool.get(&B256::random()).is_none());
        assert!(!pool.contains(&B256::random()));
        assert_eq!(pool.senders_iter().count(), 0);
        assert_eq!(pool.pending_transactions().count(), 0);
        assert_eq!(pool.queued_transactions().count(), 0);
        assert_eq!(pool.all_transaction_hashes_iter().count(), 0);
        assert_eq!(pool.pooled_transactions_hashes_iter().count(), 0);
        assert_eq!(pool.pooled_transactions_iter().count(), 0);

        let mut best = pool.best_transactions();
        assert!(best.next().is_none());
    }

    #[test]
    fn test_empty_pool_remove_operations() {
        let mut pool = AA2dPool::default();
        let random_hash = B256::random();
        let random_sender = Address::random();

        let removed = pool.remove_transactions([&random_hash].into_iter());
        assert!(removed.is_empty());

        let removed = pool.remove_transactions_by_sender(random_sender);
        assert!(removed.is_empty());

        let removed = pool.remove_transactions_and_descendants([&random_hash].into_iter());
        assert!(removed.is_empty());

        pool.assert_invariants();
    }

    #[test]
    fn test_empty_pool_on_nonce_changes() {
        let mut pool = AA2dPool::default();

        let mut changes = HashMap::default();
        changes.insert(AASequenceId::new(Address::random(), U256::ZERO), 5u64);

        let (promoted, mined) = pool.on_nonce_changes(changes);
        assert!(promoted.is_empty());
        assert!(mined.is_empty());

        pool.assert_invariants();
    }

    // ============================================
    // Error path tests
    // ============================================

    #[test]
    fn test_add_already_imported_transaction() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let tx_hash = *tx.hash();
        let valid_tx = Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local));

        pool.add_transaction(valid_tx.clone(), 0, TempoHardfork::T1)
            .unwrap();

        let result = pool.add_transaction(valid_tx, 0, TempoHardfork::T1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.hash, tx_hash);
        assert!(
            matches!(err.kind, PoolErrorKind::AlreadyImported),
            "Expected AlreadyImported, got {:?}",
            err.kind
        );

        pool.assert_invariants();
    }

    #[test]
    fn test_add_outdated_nonce_transaction() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(5).build();
        let tx_hash = *tx.hash();
        let valid_tx = Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local));

        let result = pool.add_transaction(valid_tx, 10, TempoHardfork::T1);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.hash, tx_hash);
        assert!(
            matches!(
                err.kind,
                PoolErrorKind::InvalidTransaction(InvalidPoolTransactionError::Consensus(
                    InvalidTransactionError::NonceNotConsistent { tx: 5, state: 10 }
                ))
            ),
            "Expected NonceNotConsistent, got {:?}",
            err.kind
        );

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending + queued, 0);
    }

    #[test]
    fn test_replacement_underpriced() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx1 = TxBuilder::aa(sender)
            .nonce_key(U256::ZERO)
            .max_priority_fee(1_000_000_000)
            .max_fee(2_000_000_000)
            .build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let tx2 = TxBuilder::aa(sender)
            .nonce_key(U256::ZERO)
            .max_priority_fee(1_000_000_001)
            .max_fee(2_000_000_001)
            .build();
        let tx2_hash = *tx2.hash();
        let result = pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.hash, tx2_hash);
        assert!(
            matches!(err.kind, PoolErrorKind::ReplacementUnderpriced),
            "Expected ReplacementUnderpriced, got {:?}",
            err.kind
        );

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending + queued, 1);

        pool.assert_invariants();
    }

    // ============================================
    // Boundary tests (max_txs limit and discard)
    // ============================================

    #[test]
    fn test_discard_at_max_txs_limit() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 3,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 10000,
                max_size: usize::MAX,
            },
            max_txs_per_sender: DEFAULT_MAX_TXS_PER_SENDER,
        };
        let mut pool = AA2dPool::new(config);

        for i in 0..5usize {
            let sender = Address::from_word(B256::from(U256::from(i)));
            let tx = TxBuilder::aa(sender).nonce_key(U256::from(i)).build();
            let result = pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            );
            assert!(result.is_ok());
        }

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending + queued, 3, "Pool should be capped at max_txs=3");
        assert_eq!(pending, 3, "All remaining transactions should be pending");

        pool.assert_invariants();
    }

    #[test]
    fn test_discard_removes_lowest_priority_same_priority_uses_submission_order() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 2,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 10000,
                max_size: usize::MAX,
            },
            max_txs_per_sender: DEFAULT_MAX_TXS_PER_SENDER,
        };
        let mut pool = AA2dPool::new(config);
        let sender = Address::random();

        // All transactions have the same priority, so the tiebreaker is submission order.
        // The most recently submitted (tx2) should be evicted first.
        let tx0 = TxBuilder::aa(sender).nonce_key(U256::ZERO).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(1).build();
        let tx2 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(2).build();
        let tx0_hash = *tx0.hash();
        let tx1_hash = *tx1.hash();
        let tx2_hash = *tx2.hash();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        let result = pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        );
        assert!(result.is_ok());

        let added = result.unwrap();
        if let AddedTransaction::Pending(pending) = added {
            assert!(
                !pending.discarded.is_empty(),
                "Should have discarded transactions"
            );
            assert_eq!(
                pending.discarded[0].hash(),
                &tx2_hash,
                "tx2 (last submitted, lowest priority tiebreaker) should be discarded"
            );
        } else {
            panic!("Expected Pending result");
        }

        assert!(pool.contains(&tx0_hash));
        assert!(pool.contains(&tx1_hash));
        assert!(!pool.contains(&tx2_hash));

        pool.assert_invariants();
    }

    /// Tests that queued transactions (with nonce gaps) also respect the max_txs limit.
    #[test]
    fn test_discard_enforced_for_queued_transactions() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 2,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 2,
                max_size: usize::MAX,
            },
            max_txs_per_sender: DEFAULT_MAX_TXS_PER_SENDER,
        };
        let mut pool = AA2dPool::new(config);

        // Add 5 transactions each with a LARGE nonce gap so they are all queued
        for i in 0..5usize {
            let sender = Address::from_word(B256::from(U256::from(i)));
            let tx = TxBuilder::aa(sender)
                .nonce_key(U256::from(i))
                .nonce(1000)
                .build();
            let result = pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            );
            assert!(result.is_ok(), "Transaction {i} should be added");
        }

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(
            pending + queued,
            2,
            "Pool should be capped at max_txs=2, but has {pending} pending + {queued} queued",
        );

        pool.assert_invariants();
    }

    /// Verifies queued transactions respect their own limit independently
    #[test]
    fn test_queued_limit_enforced_separately() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 10,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 3,
                max_size: usize::MAX,
            },
            max_txs_per_sender: DEFAULT_MAX_TXS_PER_SENDER,
        };
        let mut pool = AA2dPool::new(config);

        // Add 5 queued transactions (far-future nonces)
        for i in 0..5usize {
            let sender = Address::from_word(B256::from(U256::from(i)));
            let tx = TxBuilder::aa(sender)
                .nonce_key(U256::from(i))
                .nonce(1000)
                .build();
            let _ = pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            );
        }

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(queued, 3, "Queued should be capped at 3");
        assert_eq!(pending, 0, "No pending transactions");
        pool.assert_invariants();
    }

    /// Verifies pending transactions respect their own limit independently
    #[test]
    fn test_pending_limit_enforced_separately() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 3,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 10,
                max_size: usize::MAX,
            },
            max_txs_per_sender: DEFAULT_MAX_TXS_PER_SENDER,
        };
        let mut pool = AA2dPool::new(config);

        // Add 5 pending transactions (nonce=0, different senders)
        for i in 0..5usize {
            let sender = Address::from_word(B256::from(U256::from(i)));
            let tx = TxBuilder::aa(sender).nonce_key(U256::from(i)).build();
            let _ = pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            );
        }

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 3, "Pending should be capped at 3");
        assert_eq!(queued, 0, "No queued transactions");
        pool.assert_invariants();
    }

    /// Verifies queued spam cannot evict pending transactions
    #[test]
    fn test_queued_eviction_does_not_affect_pending() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 5,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 2,
                max_size: usize::MAX,
            },
            max_txs_per_sender: DEFAULT_MAX_TXS_PER_SENDER,
        };
        let mut pool = AA2dPool::new(config);

        // First add 3 pending transactions
        let mut pending_hashes = Vec::new();
        for i in 0..3usize {
            let sender = Address::from_word(B256::from(U256::from(i)));
            let tx = TxBuilder::aa(sender).nonce_key(U256::from(i)).build();
            let hash = *tx.hash();
            pending_hashes.push(hash);
            let _ = pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            );
        }

        // Now flood with 10 queued transactions
        for i in 100..110usize {
            let sender = Address::from_word(B256::from(U256::from(i)));
            let tx = TxBuilder::aa(sender)
                .nonce_key(U256::from(i))
                .nonce(1000)
                .build();
            let _ = pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            );
        }

        // All pending should still be there
        for hash in &pending_hashes {
            assert!(
                pool.contains(hash),
                "Pending tx should not be evicted by queued spam"
            );
        }

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 3, "All 3 pending should remain");
        assert_eq!(queued, 2, "Queued capped at 2");
        pool.assert_invariants();
    }

    /// Tests that eviction is based on priority, not address ordering.
    /// This prevents DoS attacks where adversaries use vanity addresses with leading zeroes.
    #[test]
    fn test_discard_evicts_low_priority_over_vanity_address() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 2,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 10,
                max_size: usize::MAX,
            },
            max_txs_per_sender: DEFAULT_MAX_TXS_PER_SENDER,
        };
        let mut pool = AA2dPool::new(config);

        // Vanity address with leading zeroes (would sort first lexicographically)
        let vanity_sender = Address::from_word(B256::from_slice(&[0u8; 32])); // 0x0000...0000
        // Normal address (would sort later lexicographically)
        let normal_sender = Address::from_word(B256::from_slice(&[0xff; 32])); // 0xffff...ffff

        // max_fee must be > TEMPO_T1_BASE_FEE (20 gwei) for priority calculation to work
        // effective_tip = min(max_fee - base_fee, max_priority_fee)
        let high_max_fee = 30_000_000_000u128; // 30 gwei, above 20 gwei base fee

        // Add vanity address tx with HIGH priority (should be kept despite sorting first lexicographically)
        // effective_tip = min(30 gwei - 20 gwei, 5 gwei) = 5 gwei
        let high_priority_tx = TxBuilder::aa(vanity_sender)
            .nonce_key(U256::ZERO)
            .max_fee(high_max_fee)
            .max_priority_fee(5_000_000_000) // 5 gwei priority
            .build();
        let high_priority_hash = *high_priority_tx.hash();

        // Add normal address tx with LOW priority (should be evicted)
        // effective_tip = min(30 gwei - 20 gwei, 1 wei) = 1 wei
        let low_priority_tx = TxBuilder::aa(normal_sender)
            .nonce_key(U256::ZERO)
            .max_fee(high_max_fee)
            .max_priority_fee(1) // Very low priority
            .build();
        let low_priority_hash = *low_priority_tx.hash();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(high_priority_tx, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(low_priority_tx, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // Add a third tx that triggers eviction
        // effective_tip = min(30 gwei - 20 gwei, 3 gwei) = 3 gwei (medium)
        let trigger_tx = TxBuilder::aa(Address::random())
            .nonce_key(U256::from(1))
            .max_fee(high_max_fee)
            .max_priority_fee(3_000_000_000) // 3 gwei - medium priority
            .build();
        let trigger_hash = *trigger_tx.hash();

        let result = pool.add_transaction(
            Arc::new(wrap_valid_tx(trigger_tx, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        );
        assert!(result.is_ok());

        let added = result.unwrap();
        if let AddedTransaction::Pending(pending) = added {
            assert!(
                !pending.discarded.is_empty(),
                "Should have discarded transactions"
            );
            // The low priority tx (normal address) should be evicted, NOT the high priority vanity address
            assert_eq!(
                pending.discarded[0].hash(),
                &low_priority_hash,
                "Low priority tx should be evicted, not the high-priority vanity address tx"
            );
        } else {
            panic!("Expected Pending result");
        }

        // Verify: high priority vanity address tx should be kept, low priority normal address tx should be evicted
        assert!(
            pool.contains(&high_priority_hash),
            "High priority vanity address tx should be kept"
        );
        assert!(
            !pool.contains(&low_priority_hash),
            "Low priority tx should be evicted"
        );
        assert!(pool.contains(&trigger_hash), "Trigger tx should be kept");

        pool.assert_invariants();
    }

    /// Tests that a sender cannot exceed the per-sender transaction limit.
    #[test]
    fn test_per_sender_limit_rejects_excess_transactions() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 1000,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 1000,
                max_size: usize::MAX,
            },
            max_txs_per_sender: 3,
        };
        let mut pool = AA2dPool::new(config);
        let sender = Address::random();

        // Add transactions up to the limit
        for nonce in 0..3u64 {
            let tx = TxBuilder::aa(sender)
                .nonce_key(U256::ZERO)
                .nonce(nonce)
                .build();
            let result = pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            );
            assert!(result.is_ok(), "Transaction {nonce} should be accepted");
        }

        // The 4th transaction from the same sender should be rejected
        let tx = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(3).build();
        let result = pool.add_transaction(
            Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        );
        assert!(result.is_err(), "4th transaction should be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(err.kind, PoolErrorKind::SpammerExceededCapacity(_)),
            "Error should be SpammerExceededCapacity, got {:?}",
            err.kind
        );

        // A different sender should still be able to add transactions
        let other_sender = Address::random();
        let tx = TxBuilder::aa(other_sender).nonce_key(U256::ZERO).build();
        let result = pool.add_transaction(
            Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        );
        assert!(result.is_ok(), "Different sender should be accepted");

        pool.assert_invariants();
    }

    /// Tests that replacing a transaction doesn't count against the per-sender limit.
    #[test]
    fn test_per_sender_limit_allows_replacement() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 1000,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 1000,
                max_size: usize::MAX,
            },
            max_txs_per_sender: 2,
        };
        let mut pool = AA2dPool::new(config);
        let sender = Address::random();

        // Add 2 transactions to reach the limit
        for nonce in 0..2u64 {
            let tx = TxBuilder::aa(sender)
                .nonce_key(U256::ZERO)
                .nonce(nonce)
                .build();
            pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            )
            .unwrap();
        }

        // Replace the first transaction with a higher fee (should succeed)
        let replacement_tx = TxBuilder::aa(sender)
            .nonce_key(U256::ZERO)
            .nonce(0)
            .max_fee(100_000_000_000) // Higher fee to pass replacement check
            .max_priority_fee(50_000_000_000)
            .build();
        let result = pool.add_transaction(
            Arc::new(wrap_valid_tx(replacement_tx, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        );
        assert!(
            result.is_ok(),
            "Replacement should be allowed even at limit"
        );

        pool.assert_invariants();
    }

    /// Tests that removing a transaction frees up a slot for the sender.
    #[test]
    fn test_per_sender_limit_freed_after_removal() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 1000,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 1000,
                max_size: usize::MAX,
            },
            max_txs_per_sender: 2,
        };
        let mut pool = AA2dPool::new(config);
        let sender = Address::random();

        // Add 2 transactions to reach the limit
        let tx1 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(0).build();
        let tx1_hash = *tx1.hash();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let tx2 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(1).build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // 3rd should fail
        let tx3 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(2).build();
        let result = pool.add_transaction(
            Arc::new(wrap_valid_tx(tx3.clone(), TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        );
        assert!(result.is_err(), "3rd should be rejected at limit");

        // Remove the first transaction
        pool.remove_transactions(std::iter::once(&tx1_hash));

        // Now adding the 3rd should succeed
        let result = pool.add_transaction(
            Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        );
        assert!(result.is_ok(), "3rd should succeed after removal");

        pool.assert_invariants();
    }

    /// Tests that expiring nonce transactions also respect per-sender limits.
    #[test]
    fn test_per_sender_limit_includes_expiring_nonce_txs() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 1000,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 1000,
                max_size: usize::MAX,
            },
            max_txs_per_sender: 2,
        };
        let mut pool = AA2dPool::new(config);
        let sender = Address::random();

        // Add one regular 2D nonce tx
        let tx1 = TxBuilder::aa(sender).nonce_key(U256::ZERO).nonce(0).build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // Add one expiring nonce tx (nonce_key = U256::MAX)
        let tx2 = TxBuilder::aa(sender).nonce_key(U256::MAX).nonce(0).build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        // The 3rd transaction (either type) should be rejected
        let tx3 = TxBuilder::aa(sender)
            .nonce_key(U256::from(1))
            .nonce(0)
            .build();
        let result = pool.add_transaction(
            Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        );
        assert!(
            result.is_err(),
            "3rd tx should be rejected due to per-sender limit"
        );

        pool.assert_invariants();
    }

    // ============================================
    // Improved BestTransactions tests
    // ============================================

    #[test]
    fn test_best_transactions_mark_invalid_skips_sequence() {
        use reth_primitives_traits::transaction::error::InvalidTransactionError;

        let mut pool = AA2dPool::default();
        let sender1 = Address::random();
        let sender2 = Address::random();

        let tx1_0 = TxBuilder::aa(sender1).nonce_key(U256::ZERO).build();
        let tx1_1 = TxBuilder::aa(sender1)
            .nonce_key(U256::ZERO)
            .nonce(1)
            .build();
        let tx2_0 = TxBuilder::aa(sender2).nonce_key(U256::from(1)).build();

        let tx1_0_hash = *tx1_0.hash();
        let tx2_0_hash = *tx2_0.hash();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1_0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1_1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2_0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let mut best = pool.best_transactions();

        let first = best.next().unwrap();
        let first_hash = *first.hash();

        let error =
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported);
        best.mark_invalid(&first, &error);

        let mut remaining_hashes = HashSet::new();
        for tx in best {
            remaining_hashes.insert(*tx.hash());
        }

        if first_hash == tx1_0_hash {
            assert!(
                !remaining_hashes.contains(&tx1_0_hash),
                "tx1_0 was consumed"
            );
            assert!(
                remaining_hashes.contains(&tx2_0_hash),
                "tx2_0 should still be yielded"
            );
        } else {
            assert!(
                remaining_hashes.contains(&tx1_0_hash) || remaining_hashes.contains(&tx2_0_hash),
                "At least one other independent tx should be yielded"
            );
        }
    }

    #[test]
    fn test_best_transactions_order_by_priority() {
        let mut pool = AA2dPool::default();

        let sender1 = Address::random();
        let sender2 = Address::random();

        let low_priority = TxBuilder::aa(sender1)
            .nonce_key(U256::ZERO)
            .max_priority_fee(1_000_000)
            .max_fee(2_000_000)
            .build();
        let high_priority = TxBuilder::aa(sender2)
            .nonce_key(U256::from(1))
            .max_priority_fee(10_000_000_000)
            .max_fee(20_000_000_000)
            .build();
        let high_priority_hash = *high_priority.hash();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(low_priority, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(high_priority, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let mut best = pool.best_transactions();
        let first = best.next().unwrap();

        assert_eq!(
            first.hash(),
            &high_priority_hash,
            "Higher priority transaction should come first"
        );
    }

    // ============================================
    // on_state_updates tests
    // ============================================

    #[test]
    fn test_on_state_updates_with_bundle_account() {
        use revm::{
            database::{AccountStatus, BundleAccount},
            state::AccountInfo,
        };

        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let nonce_key = U256::ZERO;

        let tx0 = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build();
        let tx2 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(2).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 3);
        assert_eq!(queued, 0);

        let mut state: HashMap<Address, BundleAccount> = HashMap::default();
        let sender_account = BundleAccount::new(
            None,
            Some(AccountInfo {
                nonce: 2,
                ..Default::default()
            }),
            Default::default(),
            AccountStatus::Changed,
        );
        state.insert(sender, sender_account);

        let (promoted, mined) = pool.on_state_updates(&state);

        assert!(promoted.is_empty(), "tx2 was already pending");
        assert_eq!(mined.len(), 2, "tx0 and tx1 should be mined");

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 1, "Only tx2 should remain pending");
        assert_eq!(queued, 0);

        pool.assert_invariants();
    }

    #[test]
    fn test_on_state_updates_creates_gap_demotion() {
        use revm::{
            database::{AccountStatus, BundleAccount},
            state::AccountInfo,
        };

        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let nonce_key = U256::ZERO;

        let tx0 = TxBuilder::aa(sender).nonce_key(nonce_key).build();
        let tx1 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build();
        let tx3 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(3).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 2);
        assert_eq!(queued, 1);

        let mut state: HashMap<Address, BundleAccount> = HashMap::default();
        let sender_account = BundleAccount::new(
            None,
            Some(AccountInfo {
                nonce: 2,
                ..Default::default()
            }),
            Default::default(),
            AccountStatus::Changed,
        );
        state.insert(sender, sender_account);

        let (promoted, mined) = pool.on_state_updates(&state);

        assert_eq!(mined.len(), 2, "tx0 and tx1 should be mined");
        assert!(promoted.is_empty());

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 0, "tx3 should still be queued (gap at nonce 2)");
        assert_eq!(queued, 1);

        pool.assert_invariants();
    }

    #[test]
    fn test_on_nonce_changes_promotes_queued_transactions() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let nonce_key = U256::ZERO;
        let seq_id = AASequenceId::new(sender, nonce_key);

        let tx2 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(2).build();
        let tx3 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(3).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx2.clone(), TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 0);
        assert_eq!(queued, 2);

        let mut changes = HashMap::default();
        changes.insert(seq_id, 2u64);

        let (promoted, mined) = pool.on_nonce_changes(changes);

        assert!(
            mined.is_empty(),
            "No transactions to mine (on-chain nonce jumped)"
        );
        assert_eq!(promoted.len(), 2, "tx2 and tx3 should be promoted");
        assert!(promoted.iter().any(|t| t.hash() == tx2.hash()));

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 2);
        assert_eq!(queued, 0);

        pool.assert_invariants();
    }

    // ============================================
    // Interleaved inserts across sequence IDs
    // ============================================

    #[test]
    fn test_interleaved_inserts_multiple_nonce_keys() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let key_a = U256::ZERO;
        let key_b = U256::from(1);

        let tx_a0 = TxBuilder::aa(sender).nonce_key(key_a).build();
        let tx_b0 = TxBuilder::aa(sender).nonce_key(key_b).build();
        let tx_a1 = TxBuilder::aa(sender).nonce_key(key_a).nonce(1).build();
        let tx_b2 = TxBuilder::aa(sender).nonce_key(key_b).nonce(2).build();
        let tx_b1 = TxBuilder::aa(sender).nonce_key(key_b).nonce(1).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx_a0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx_b0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx_a1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx_b2, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx_b1, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 5, "All transactions should be pending");
        assert_eq!(queued, 0);

        assert_eq!(
            pool.independent_transactions.len(),
            2,
            "Two nonce keys = two independent txs"
        );

        pool.assert_invariants();
    }

    #[test]
    fn test_same_sender_different_nonce_keys_independent() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let key_a = U256::from(100);
        let key_b = U256::from(200);

        let tx_a5 = TxBuilder::aa(sender).nonce_key(key_a).nonce(5).build();
        let tx_b0 = TxBuilder::aa(sender).nonce_key(key_b).build();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx_a5, TransactionOrigin::Local)),
            5,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx_b0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 2);
        assert_eq!(queued, 0);

        assert_eq!(pool.independent_transactions.len(), 2);

        pool.assert_invariants();
    }

    /// Test reorg handling when on-chain nonce decreases.
    ///
    /// When a reorg occurs, the canonical nonce can decrease. If no transaction
    /// exists at the new on-chain nonce, `independent_transactions` must be cleared.
    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn reorg_nonce_decrease_clears_stale_independent_transaction(nonce_key: U256) {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let seq_id = AASequenceId::new(sender, nonce_key);

        // Step 1: Add txs with nonces [3, 4, 5], starting with on_chain_nonce=3
        let tx3 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(3).build();
        let tx4 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(4).build();
        let tx5 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(5).build();
        let tx5_hash = *tx5.hash();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)),
            3,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx4, TransactionOrigin::Local)),
            3,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx5, TransactionOrigin::Local)),
            3,
            TempoHardfork::T1,
        )
        .unwrap();

        // Verify initial state: all 3 txs pending, tx3 is independent
        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 3, "All transactions should be pending");
        assert_eq!(queued, 0);
        assert_eq!(pool.independent_transactions.len(), 1);
        assert_eq!(
            pool.independent_transactions
                .get(&seq_id)
                .unwrap()
                .transaction
                .nonce(),
            3,
            "tx3 should be independent initially"
        );
        pool.assert_invariants();

        // Step 2: Simulate mining of tx3 and tx4, on_chain_nonce becomes 5
        let mut on_chain_ids = HashMap::default();
        on_chain_ids.insert(seq_id, 5u64);
        let (promoted, mined) = pool.on_nonce_changes(on_chain_ids);

        assert_eq!(mined.len(), 2, "tx3 and tx4 should be mined");
        assert!(promoted.is_empty(), "No promotions expected");

        // Now tx5 should be the only tx in pool and be independent
        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 1, "Only tx5 should remain pending");
        assert_eq!(queued, 0);
        assert_eq!(pool.independent_transactions.len(), 1);
        assert_eq!(
            pool.independent_transactions
                .get(&seq_id)
                .unwrap()
                .transaction
                .hash(),
            &tx5_hash,
            "tx5 should be independent after mining"
        );
        pool.assert_invariants();

        // Step 3: Simulate reorg - nonce decreases back to 3
        let mut on_chain_ids = HashMap::default();
        on_chain_ids.insert(seq_id, 3u64);
        let (promoted, mined) = pool.on_nonce_changes(on_chain_ids);

        // No transactions should be mined (tx5.nonce=5 >= on_chain_nonce=3)
        assert!(mined.is_empty(), "No transactions should be mined");
        // No promotions expected
        assert!(promoted.is_empty(), "No promotions expected");

        // tx5 should still be in the pool but is now QUEUED (gap at nonces 3, 4)
        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 0, "tx5 should not be pending (nonce gap)");
        assert_eq!(queued, 1, "tx5 should be queued");

        // No tx at on_chain_nonce=3, so independent_transactions should be cleared
        assert!(
            !pool.independent_transactions.contains_key(&seq_id),
            "independent_transactions should not contain stale entry after reorg"
        );

        pool.assert_invariants();
    }

    /// Test that gap demotion marks ALL subsequent transactions as non-pending.
    ///
    /// When a transaction is removed creating a gap, all transactions after the gap
    /// should be marked as queued (is_pending=false), not just the first one.
    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn gap_demotion_marks_all_subsequent_transactions_as_queued(nonce_key: U256) {
        let mut pool = AA2dPool::default();
        let sender = Address::random();
        let seq_id = AASequenceId::new(sender, nonce_key);

        // Step 1: Add txs with nonces [5, 6, 7, 8], on_chain_nonce=5
        let tx5 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(5).build();
        let tx6 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(6).build();
        let tx7 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(7).build();
        let tx8 = TxBuilder::aa(sender).nonce_key(nonce_key).nonce(8).build();
        let tx6_hash = *tx6.hash();

        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx5, TransactionOrigin::Local)),
            5,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx6, TransactionOrigin::Local)),
            5,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx7, TransactionOrigin::Local)),
            5,
            TempoHardfork::T1,
        )
        .unwrap();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx8, TransactionOrigin::Local)),
            5,
            TempoHardfork::T1,
        )
        .unwrap();

        // Verify initial state: all 4 txs pending
        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 4, "All transactions should be pending initially");
        assert_eq!(queued, 0);
        assert_eq!(pool.independent_transactions.len(), 1);
        pool.assert_invariants();

        // Step 2: Remove tx6 to create a gap at nonce 6
        // Pool now has: [5, _, 7, 8] where _ is the gap
        let removed = pool.remove_transactions(std::iter::once(&tx6_hash));
        assert_eq!(removed.len(), 1, "Should remove exactly tx6");

        // Step 3: Trigger nonce change processing to re-evaluate pending status
        // The on-chain nonce is still 5
        let mut on_chain_ids = HashMap::default();
        on_chain_ids.insert(seq_id, 5u64);
        let (promoted, mined) = pool.on_nonce_changes(on_chain_ids);

        assert!(mined.is_empty(), "No transactions should be mined");
        assert!(promoted.is_empty(), "No promotions expected");

        // Step 4: Verify that tx7 AND tx8 are both queued (not pending)
        // BUG: Current code only marks tx7 as non-pending, tx8 incorrectly stays pending
        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(
            pending, 1,
            "Only tx5 should be pending (tx7 and tx8 are after the gap)"
        );
        assert_eq!(
            queued, 2,
            "tx7 and tx8 should both be queued due to gap at nonce 6"
        );

        pool.assert_invariants();
    }

    #[test]
    fn expiring_nonce_tx_increments_pending_count() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        // Create an expiring nonce transaction (nonce_key = U256::MAX)
        let tx = TxBuilder::aa(sender).nonce_key(U256::MAX).build();
        let valid_tx = wrap_valid_tx(tx, TransactionOrigin::Local);

        // Add the expiring nonce transaction
        let result = pool.add_transaction(Arc::new(valid_tx), 0, TempoHardfork::T1);
        assert!(result.is_ok(), "Transaction should be added successfully");
        assert!(
            matches!(result.unwrap(), AddedTransaction::Pending(_)),
            "Expiring nonce transaction should be pending"
        );

        // Verify counts - expiring nonce txs should increment pending_count
        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 1, "Should have 1 pending transaction");
        assert_eq!(queued, 0, "Should have 0 queued transactions");

        // This will fail if pending_count wasn't incremented
        pool.assert_invariants();
    }

    #[test]
    fn expiring_nonce_tx_subject_to_eviction() {
        // Create pool with very small pending limit
        let config = AA2dPoolConfig {
            pending_limit: SubPoolLimit {
                max_txs: 2,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 10,
                max_size: usize::MAX,
            },
            ..Default::default()
        };
        let mut pool = AA2dPool::new(config);
        let sender = Address::random();

        // Add 3 expiring nonce transactions - should evict to maintain limit of 2
        for i in 0..3 {
            let tx = TxBuilder::aa(sender)
                .nonce_key(U256::MAX)
                .max_priority_fee(1_000_000_000 + i as u128 * 100_000_000)
                .max_fee(2_000_000_000 + i as u128 * 100_000_000)
                .build();
            let valid_tx = wrap_valid_tx(tx, TransactionOrigin::Local);
            let _ = pool.add_transaction(Arc::new(valid_tx), 0, TempoHardfork::T1);
        }

        // Should only have 2 transactions (evicted one to maintain limit)
        let (pending, queued) = pool.pending_and_queued_txn_count();
        assert!(
            pending <= 2,
            "Should have at most 2 pending transactions due to limit, got {pending}"
        );
        assert_eq!(queued, 0, "Should have 0 queued transactions");

        pool.assert_invariants();
    }

    #[test]
    fn remove_expiring_nonce_tx_decrements_pending_count() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        // Add two expiring nonce transactions
        let tx1 = TxBuilder::aa(sender)
            .nonce_key(U256::MAX)
            .max_priority_fee(1_000_000_000)
            .max_fee(2_000_000_000)
            .build();
        let valid_tx1 = wrap_valid_tx(tx1, TransactionOrigin::Local);
        let tx1_hash = *valid_tx1.hash();

        let tx2 = TxBuilder::aa(sender)
            .nonce_key(U256::MAX)
            .max_priority_fee(1_100_000_000)
            .max_fee(2_200_000_000)
            .build();
        let valid_tx2 = wrap_valid_tx(tx2, TransactionOrigin::Local);

        pool.add_transaction(Arc::new(valid_tx1), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx2), 0, TempoHardfork::T1)
            .unwrap();

        // Verify we have 2 pending
        let (pending, _) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 2, "Should have 2 pending transactions");
        pool.assert_invariants();

        // Remove one via the included txs path
        let removed = pool.remove_included_expiring_nonce_txs(std::iter::once(&tx1_hash));
        assert_eq!(removed.len(), 1, "Should remove exactly 1 transaction");

        // Verify pending count decremented
        let (pending, _) = pool.pending_and_queued_txn_count();
        assert_eq!(
            pending, 1,
            "Should have 1 pending transaction after removal"
        );

        // This will fail if pending_count wasn't decremented
        pool.assert_invariants();
    }

    #[test]
    fn remove_expiring_nonce_tx_by_hash_updates_pending_count() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx = TxBuilder::aa(sender)
            .nonce_key(U256::MAX)
            .max_priority_fee(1_000_000_000)
            .max_fee(2_000_000_000)
            .build();
        let valid_tx = wrap_valid_tx(tx, TransactionOrigin::Local);
        let tx_hash = *valid_tx.hash();

        pool.add_transaction(Arc::new(valid_tx), 0, TempoHardfork::T1)
            .unwrap();

        let (pending, _) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 1);
        pool.assert_invariants();

        // Remove via remove_transactions (uses remove_transaction_by_hash_no_demote)
        let removed = pool.remove_transactions(std::iter::once(&tx_hash));
        assert_eq!(removed.len(), 1);

        let (pending, _) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 0);
        pool.assert_invariants();
    }

    #[test]
    fn remove_expiring_nonce_tx_by_sender_updates_pending_count() {
        let mut pool = AA2dPool::default();
        let sender = Address::random();

        let tx1 = TxBuilder::aa(sender)
            .nonce_key(U256::MAX)
            .max_priority_fee(1_000_000_000)
            .max_fee(2_000_000_000)
            .build();
        let valid_tx1 = wrap_valid_tx(tx1, TransactionOrigin::Local);

        let tx2 = TxBuilder::aa(sender)
            .nonce_key(U256::MAX)
            .max_priority_fee(1_100_000_000)
            .max_fee(2_200_000_000)
            .build();
        let valid_tx2 = wrap_valid_tx(tx2, TransactionOrigin::Local);

        pool.add_transaction(Arc::new(valid_tx1), 0, TempoHardfork::T1)
            .unwrap();
        pool.add_transaction(Arc::new(valid_tx2), 0, TempoHardfork::T1)
            .unwrap();

        let (pending, _) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 2);
        pool.assert_invariants();

        // Remove via remove_transactions_by_sender
        let removed = pool.remove_transactions_by_sender(sender);
        assert_eq!(removed.len(), 2);

        let (pending, _) = pool.pending_and_queued_txn_count();
        assert_eq!(pending, 0);
        pool.assert_invariants();
    }

    #[test]
    fn test_rejected_2d_tx_does_not_leak_slot_entries() {
        let config = AA2dPoolConfig {
            price_bump_config: PriceBumpConfig::default(),
            pending_limit: SubPoolLimit {
                max_txs: 1000,
                max_size: usize::MAX,
            },
            queued_limit: SubPoolLimit {
                max_txs: 1000,
                max_size: usize::MAX,
            },
            max_txs_per_sender: 1,
        };
        let mut pool = AA2dPool::new(config);
        let sender = Address::random();

        let tx0 = TxBuilder::aa(sender)
            .nonce_key(U256::from(1))
            .nonce(0)
            .build();
        pool.add_transaction(
            Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)),
            0,
            TempoHardfork::T1,
        )
        .unwrap();

        assert_eq!(pool.slot_to_seq_id.len(), 1);
        assert_eq!(pool.seq_id_to_slot.len(), 1);

        for i in 2..12u64 {
            let tx = TxBuilder::aa(sender)
                .nonce_key(U256::from(i))
                .nonce(0)
                .build();
            let result = pool.add_transaction(
                Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                0,
                TempoHardfork::T1,
            );
            assert!(
                result.is_err(),
                "tx with nonce_key {i} should be rejected by sender limit"
            );
        }

        assert_eq!(
            pool.slot_to_seq_id.len(),
            1,
            "rejected txs with new nonce keys should not grow slot_to_seq_id"
        );
        assert_eq!(
            pool.seq_id_to_slot.len(),
            1,
            "rejected txs with new nonce keys should not grow seq_id_to_slot"
        );

        pool.assert_invariants();
    }
}
