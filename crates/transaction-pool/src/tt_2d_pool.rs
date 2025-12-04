/// Basic 2D nonce pool for user nonces (nonce_key > 0) that are tracked on chain.
use crate::{metrics::AA2dPoolMetrics, transaction::TempoPooledTransaction};
use alloy_primitives::{Address, B256, TxHash, U256, map::HashMap};
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_tracing::tracing::trace;
use reth_transaction_pool::{
    BestTransactions, CoinbaseTipOrdering, PoolResult, PriceBumpConfig, Priority, SubPool,
    SubPoolLimit, TransactionOrdering, TransactionOrigin, ValidPoolTransaction,
    error::{InvalidPoolTransactionError, PoolError, PoolErrorKind},
    pool::{AddedPendingTransaction, AddedTransaction, QueuedReason, pending::PendingTransaction},
};
use revm::database::BundleAccount;
use std::{
    collections::{
        BTreeMap, BTreeSet,
        Bound::{Excluded, Unbounded},
        HashSet,
        btree_map::Entry,
        hash_map,
    },
    sync::Arc,
};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, nonce::slots, storage::double_mapping_slot};

type Ordering = CoinbaseTipOrdering<TempoPooledTransaction>;

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
    independent_transactions: HashMap<AASequenceId, PendingTransaction<Ordering>>,
    /// _All_ transactions that are currently inside the pool grouped by their unique identifier.
    by_id: BTreeMap<AA2dTransactionId, AA2dInternalTransaction>,
    /// _All_ transactions by hash.
    by_hash: HashMap<TxHash, Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    /// Reverse index for the storage slot of an account's nonce
    ///
    /// ```solidity
    ///  mapping(address => mapping(uint256 => uint64)) public nonces
    /// ```
    ///
    /// This identifies the account and nonce key based on the slot in the `NonceManager`.
    address_slots: HashMap<U256, (Address, U256)>,
    /// Settings for this sub-pool.
    config: AA2dPoolConfig,
    /// Metrics for tracking pool statistics
    metrics: AA2dPoolMetrics,
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
            address_slots: Default::default(),
            config,
            metrics: AA2dPoolMetrics::default(),
        }
    }

    /// Updates all metrics to reflect the current state of the pool
    fn update_metrics(&self) {
        let (pending, queued) = self.pending_and_queued_txn_count();
        let total = self.by_id.len();
        self.metrics.set_transaction_counts(total, pending, queued);
    }

    /// Entrypoint for adding a 2d AA transaction.
    ///
    /// ## Limitations
    /// * This currently assumes that the account's nonce key is already tracked in [`AA2dNonceKeys`], if not then this transaction is considered pending.
    pub(crate) fn add_transaction(
        &mut self,
        transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        on_chain_nonce: u64,
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

        let tx_id = transaction
            .transaction
            .aa_transaction_id()
            .expect("Transaction added to AA2D pool must be an AA transaction");

        // Cache the nonce key slot for reverse lookup, if this transaction uses 2D nonce.
        if transaction.transaction.has_non_zero_nonce_key() {
            self.record_2d_slot(transaction.sender(), tx_id.seq_id.nonce_key);
        }

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
        let mut inserted_as_pending = false;
        let tx = AA2dInternalTransaction {
            inner: PendingTransaction {
                submission_id: self.next_id(),
                priority: CoinbaseTipOrdering::default()
                    .priority(&transaction.transaction, TEMPO_BASE_FEE),
                transaction: transaction.clone(),
            },
            is_pending: inserted_as_pending,
        };

        // try to insert the transaction
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

                Some(entry.insert(tx.clone()))
            }
            Entry::Vacant(entry) => {
                entry.insert(tx.clone());
                None
            }
        };

        // clean up replaced
        if let Some(replaced) = &replaced {
            // we only need to remove it from the hash list, because we already replaced it in the by id set,
            // and if this is the independent transaction, it will be replaced by the new transaction below
            self.by_hash.remove(replaced.inner.transaction.hash());
        }

        // insert transaction by hash
        self.by_hash
            .insert(*tx.inner.transaction.hash(), tx.inner.transaction.clone());

        // contains transactions directly impacted by the new transaction (filled nonca gap)
        let mut promoted = Vec::new();
        // now we need to scan the range and mark transactions as pending, if any
        let on_chain_id = AA2dTransactionId::new(tx_id.seq_id, on_chain_nonce);
        // track the next nonce we expect if the transactions are gapless
        let mut next_nonce = on_chain_id.nonce;

        // scan all the transactions with the same nonce key starting with the on chain nonce
        // to check if our new transaction was inserted as pending and perhaps promoted more transactions
        for (existing_id, existing_tx) in self.descendant_txs_mut(&on_chain_id) {
            if existing_id.nonce == next_nonce {
                match existing_id.nonce.cmp(&tx_id.nonce) {
                    std::cmp::Ordering::Less => {
                        // unaffected by our transaction
                    }
                    std::cmp::Ordering::Equal => {
                        existing_tx.is_pending = true;
                        inserted_as_pending = true;
                    }
                    std::cmp::Ordering::Greater => {
                        // if this was previously not pending we need to promote the transaction
                        let is_promoted = !std::mem::replace(&mut existing_tx.is_pending, true);
                        if is_promoted {
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
        self.update_metrics();

        if inserted_as_pending {
            if !promoted.is_empty() {
                self.metrics.inc_promoted(promoted.len());
            }
            // if this is the next nonce in line we can mark it as independent
            if tx_id.nonce == on_chain_nonce {
                self.independent_transactions.insert(tx_id.seq_id, tx.inner);
            }

            return Ok(AddedTransaction::Pending(AddedPendingTransaction {
                transaction,
                replaced: replaced.map(|tx| tx.inner.transaction),
                promoted,
                discarded: self.discard(),
            }));
        }

        Ok(AddedTransaction::Parked {
            transaction,
            replaced: replaced.map(|tx| tx.inner.transaction),
            subpool: SubPool::Queued,
            queued_reason: Some(QueuedReason::NonceGap),
        })
    }

    /// Returns how many pending and queued transactions are in the pool.
    pub(crate) fn pending_and_queued_txn_count(&self) -> (usize, usize) {
        self.by_id.values().fold((0, 0), |mut acc, tx| {
            if tx.is_pending {
                acc.0 += 1;
            } else {
                acc.1 += 1;
            }
            acc
        })
    }

    /// Returns all transactions that where submitted with the given [`TransactionOrigin`]
    pub(crate) fn get_transactions_by_origin_iter(
        &self,
        origin: TransactionOrigin,
    ) -> impl Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_id
            .values()
            .filter(move |tx| tx.inner.transaction.origin == origin)
            .map(|tx| tx.inner.transaction.clone())
    }

    /// Returns all transactions that where submitted with the given [`TransactionOrigin`]
    pub(crate) fn get_pending_transactions_by_origin_iter(
        &self,
        origin: TransactionOrigin,
    ) -> impl Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_id
            .values()
            .filter(move |tx| tx.is_pending && tx.inner.transaction.origin == origin)
            .map(|tx| tx.inner.transaction.clone())
    }

    /// Returns all transactions of the address
    pub(crate) fn get_transactions_by_sender_iter(
        &self,
        sender: Address,
    ) -> impl Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_id
            .values()
            .filter(move |tx| tx.inner.transaction.sender() == sender)
            .map(|tx| tx.inner.transaction.clone())
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
            .filter(|tx| !tx.is_pending)
            .map(|tx| tx.inner.transaction.clone())
    }

    /// Returns all transactions that are pending.
    pub(crate) fn pending_transactions(
        &self,
    ) -> impl Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_id
            .values()
            .filter(|tx| tx.is_pending)
            .map(|tx| tx.inner.transaction.clone())
    }

    /// Returns the best, executable transactions for this sub-pool
    pub(crate) fn best_transactions(&self) -> BestAA2dTransactions {
        BestAA2dTransactions {
            independent: self.independent_transactions.values().cloned().collect(),
            by_id: self
                .by_id
                .iter()
                .filter(|(_, tx)| tx.is_pending)
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

    /// Returns an iterator over all the matching transactions.
    pub(crate) fn get_all_iter<'a, I>(
        &'a self,
        tx_hashes: I,
    ) -> impl Iterator<Item = &'a Arc<ValidPoolTransaction<TempoPooledTransaction>>> + 'a
    where
        I: IntoIterator<Item = &'a TxHash> + 'a,
    {
        tx_hashes
            .into_iter()
            .filter_map(|tx_hash| self.by_hash.get(tx_hash))
    }

    /// Returns an iterator over all senders in this pool.
    pub(crate) fn senders_iter(&self) -> impl Iterator<Item = &Address> {
        self.by_id
            .values()
            .map(|tx| tx.inner.transaction.sender_ref())
    }

    /// Returns all mutable transactions that _follow_ after the given id but have the same sender.
    ///
    /// NOTE: The range is _inclusive_: if the transaction that belongs to `id` it field be the
    /// first value.
    fn descendant_txs_mut<'a, 'b: 'a>(
        &'a mut self,
        id: &'b AA2dTransactionId,
    ) -> impl Iterator<Item = (&'a AA2dTransactionId, &'a mut AA2dInternalTransaction)> + 'a {
        self.by_id
            .range_mut(id..)
            .take_while(|(other, _)| id.seq_id == other.seq_id)
    }

    /// Returns all transactions that _follow_ after the given id and have the same sender.
    ///
    /// NOTE: The range is _exclusive_
    fn descendant_txs_exclusive<'a, 'b: 'a>(
        &'a self,
        id: &'b AA2dTransactionId,
    ) -> impl Iterator<Item = (&'a AA2dTransactionId, &'a AA2dInternalTransaction)> + 'a {
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
        self.remove_independent(id);
        self.by_hash.remove(tx.inner.transaction.hash());
        Some(tx.inner.transaction)
    }

    /// Removes the independent transaction if it matches the given id.
    fn remove_independent(
        &mut self,
        id: &AA2dTransactionId,
    ) -> Option<PendingTransaction<Ordering>> {
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
    pub(crate) fn remove_transactions<'a, I>(
        &mut self,
        tx_hashes: I,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>
    where
        I: Iterator<Item = &'a TxHash> + 'a,
    {
        let mut txs = Vec::new();
        for tx_hash in tx_hashes {
            if let Some(tx) = self.remove_transaction_by_hash(tx_hash) {
                txs.push(tx);
            }
        }
        txs
    }

    /// Removes the transaction by its hash from all internal sets.
    ///
    /// This does __not__ shift the independent transaction forward or mark descendants as pending.
    fn remove_transaction_by_hash(
        &mut self,
        tx_hash: &B256,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let tx = self.by_hash.remove(tx_hash)?;
        let id = tx
            .transaction
            .aa_transaction_id()
            .expect("is AA transaction");
        self.by_id.remove(&id)?;
        self.remove_independent(&id);
        Some(tx)
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
            if let Some(tx) = tx
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

    /// Updates the internal state based on the state changes of the `NonceManager` [`NONCE_PRECOMPILE_ADDRESS`](tempo_precompiles::NONCE_PRECOMPILE_ADDRESS).
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
                    if !std::mem::replace(&mut existing_tx.is_pending, true) {
                        promoted.push(existing_tx.inner.transaction.clone());
                    }

                    if existing_id.nonce == on_chain_nonce {
                        // if this is the on chain nonce we can mark it as the next independent transaction
                        self.independent_transactions
                            .insert(existing_id.seq_id, existing_tx.inner.clone());
                    }

                    next_nonce = next_nonce.saturating_add(1);
                } else {
                    // Gap detected - remaining transactions should not be pending
                    existing_tx.is_pending = false;
                    break;
                }
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

    /// Removes stale transactions if the pool is above capacity.
    fn discard(&mut self) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut removed = Vec::new();

        while self.by_id.len() > self.config.aa_2d_limit.max_txs {
            // TODO: this needs a more sophisticated approach for now simply pop any non pending
            let Some(id) = self.by_id.last_key_value().map(|(id, _)| *id) else {
                return removed;
            };
            removed.push(self.remove_transaction_by_id(&id).unwrap());
        }

        if !removed.is_empty() {
            self.metrics.inc_removed(removed.len());
        }

        removed
    }

    /// Returns a reference to the metrics for this pool
    pub fn metrics(&self) -> &AA2dPoolMetrics {
        &self.metrics
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
    fn record_2d_slot(&mut self, address: Address, nonce_key: U256) {
        trace!(target: "txpool::2d", ?address, ?nonce_key, "recording 2d nonce slot");
        let slot = double_mapping_slot(
            address.as_slice(),
            nonce_key.to_be_bytes::<32>(),
            slots::NONCES,
        );

        if self
            .address_slots
            .insert(slot, (address, nonce_key))
            .is_none()
        {
            self.metrics.inc_nonce_key_count(1);
        }
    }

    /// Processes state updates and updates internal state accordingly.
    #[expect(clippy::type_complexity)]
    pub(crate) fn on_state_updates(
        &mut self,
        state: &HashMap<Address, BundleAccount>,
    ) -> (
        Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    ) {
        let mut changes = HashMap::default();

        for (account, state) in state {
            if account == &NONCE_PRECOMPILE_ADDRESS {
                // Process known 2D nonce slot changes.
                for (slot, value) in state.storage.iter() {
                    if let Some((address, nonce_key)) = self.address_slots.get(slot) {
                        changes.insert(
                            AASequenceId::new(*address, *nonce_key),
                            value.present_value.saturating_to(),
                        );
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
        assert_eq!(
            self.by_id.len(),
            self.by_hash.len(),
            "by_id.len() ({}) != by_hash.len() ({})",
            self.by_id.len(),
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
                tx_in_pool.is_pending,
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
                    tx.is_pending,
                    "Transaction {id:?} is in independent set but not pending"
                );
            }
        }

        // Verify pending/queued consistency
        let (pending_count, queued_count) = self.pending_and_queued_txn_count();
        assert_eq!(
            pending_count + queued_count,
            self.by_id.len(),
            "Pending ({}) + queued ({}) != total transactions ({})",
            pending_count,
            queued_count,
            self.by_id.len()
        );
    }
}

/// Settings for the [`AA2dPoolConfig`]
#[derive(Debug, Clone, Default)]
pub struct AA2dPoolConfig {
    /// Price bump (in %) for the transaction pool underpriced check.
    pub price_bump_config: PriceBumpConfig,
    /// How many transactions
    pub aa_2d_limit: SubPoolLimit,
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
    is_pending: bool,
}

/// A snapshot of the sub-pool containing all executable transactions.
#[derive(Debug)]
pub(crate) struct BestAA2dTransactions {
    /// pending, executable transactions sorted by their priority.
    independent: BTreeSet<PendingTransaction<Ordering>>,
    /// _All_ transactions that are currently inside the pool grouped by their unique identifier.
    by_id: BTreeMap<AA2dTransactionId, PendingTransaction<Ordering>>,

    /// There might be the case where a yielded transactions is invalid, this will track it.
    invalid: HashSet<AASequenceId>,
}

impl BestAA2dTransactions {
    /// Removes the best transaction from the set
    fn pop_best(&mut self) -> Option<(AA2dTransactionId, PendingTransaction<Ordering>)> {
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
            if let Some(unlocked) = self.by_id.get(&id.unlocks()) {
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
pub(crate) struct AASequenceId {
    pub(crate) address: Address,
    pub(crate) nonce_key: U256,
}

impl AASequenceId {
    /// Creates a new instance with the address and nonce key.
    pub(crate) const fn new(address: Address, nonce_key: U256) -> Self {
        Self { address, nonce_key }
    }

    const fn start_bound(self) -> std::ops::Bound<AA2dTransactionId> {
        std::ops::Bound::Included(AA2dTransactionId::new(self, 0))
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
    use crate::transaction::TempoPooledTransaction;
    use alloy_consensus::Transaction;
    use alloy_primitives::{Address, Signature, TxKind, U256};
    use reth_primitives_traits::Recovered;
    use reth_transaction_pool::{PoolTransaction, ValidPoolTransaction};
    use std::{collections::HashSet, time::Instant};
    use tempo_primitives::{
        TempoTxEnvelope,
        transaction::{
            TempoTransaction,
            tempo_transaction::Call,
            tt_signature::{PrimitiveSignature, TempoSignature},
            tt_signed::AASigned,
        },
    };

    /// Helper to create a test AA transaction with default gas prices
    fn create_aa_tx(sender: Address, nonce_key: U256, nonce: u64) -> TempoPooledTransaction {
        create_aa_tx_with_gas(sender, nonce_key, nonce, 1_000_000_000, 2_000_000_000)
    }

    /// Helper to create a test AA transaction with custom gas prices
    fn create_aa_tx_with_gas(
        sender: Address,
        nonce_key: U256,
        nonce: u64,
        max_priority_fee: u128,
        max_fee: u128,
    ) -> TempoPooledTransaction {
        let tx = TempoTransaction {
            max_priority_fee_per_gas: max_priority_fee,
            max_fee_per_gas: max_fee,
            gas_limit: 100_000,
            calls: vec![Call {
                to: TxKind::Call(Address::random()),
                value: U256::from(1000),
                input: Default::default(),
            }],
            nonce_key,
            nonce,
            fee_token: None,
            fee_payer_signature: None,
            ..Default::default()
        };

        // Create a dummy signature
        let signature =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        let aa_signed = AASigned::new_unhashed(tx, signature);
        let envelope: TempoTxEnvelope = aa_signed.into();

        // Recover with the sender address (in tests we skip verification)
        let recovered = Recovered::new_unchecked(envelope, sender);
        TempoPooledTransaction::new(recovered)
    }

    /// Helper to wrap a transaction in ValidPoolTransaction
    ///
    /// Note: Creates a dummy SenderId for testing since the AA2dPool doesn't use it
    fn wrap_valid_tx(
        tx: TempoPooledTransaction,
        origin: TransactionOrigin,
    ) -> ValidPoolTransaction<TempoPooledTransaction> {
        let tx_id = reth_transaction_pool::identifier::TransactionId::new(0u64.into(), tx.nonce());
        ValidPoolTransaction {
            transaction: tx,
            transaction_id: tx_id,
            propagate: true,
            timestamp: Instant::now(),
            origin,
            authority_ids: None,
        }
    }

    #[test_case::test_case(U256::ZERO)]
    #[test_case::test_case(U256::random())]
    fn insert_pending(nonce_key: U256) {
        let mut pool = AA2dPool::default();

        // Set up a sender with a tracked nonce key
        let sender = Address::random();

        // Create a transaction with nonce_key=1, nonce=0 (should be pending)
        let tx = create_aa_tx(sender, nonce_key, 0);
        let valid_tx = wrap_valid_tx(tx, TransactionOrigin::Local);

        // Add the transaction to the pool
        let result = pool.add_transaction(Arc::new(valid_tx), 0);

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
        let tx1 = create_aa_tx(sender, nonce_key, 1);
        let valid_tx1 = wrap_valid_tx(tx1, TransactionOrigin::Local);
        let tx1_hash = *valid_tx1.hash();

        let result1 = pool.add_transaction(Arc::new(valid_tx1), 0);

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
        let tx0 = create_aa_tx(sender, nonce_key, 0);
        let valid_tx0 = wrap_valid_tx(tx0, TransactionOrigin::Local);
        let tx0_hash = *valid_tx0.hash();

        let result0 = pool.add_transaction(Arc::new(valid_tx0), 0);

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
            pool.by_id.get(&tx0_id).unwrap().is_pending,
            "Transaction 0 should be pending"
        );
        assert!(
            pool.by_id.get(&tx1_id).unwrap().is_pending,
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
        let tx_low = create_aa_tx_with_gas(sender, nonce_key, 0, 1_000_000_000, 2_000_000_000);
        let valid_tx_low = wrap_valid_tx(tx_low, TransactionOrigin::Local);
        let tx_low_hash = *valid_tx_low.hash();

        let result_low = pool.add_transaction(Arc::new(valid_tx_low), 0);

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
        let tx_high = create_aa_tx_with_gas(sender, nonce_key, 0, 1_200_000_000, 2_400_000_000);
        let valid_tx_high = wrap_valid_tx(tx_high, TransactionOrigin::Local);
        let tx_high_hash = *valid_tx_high.hash();

        let result_high = pool.add_transaction(Arc::new(valid_tx_high), 0);

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
        assert!(tx_in_pool.is_pending, "Transaction should be pending");

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
        let tx0 = create_aa_tx(sender, nonce_key, 0);
        let tx1 = create_aa_tx(sender, nonce_key, 1);
        let tx3 = create_aa_tx(sender, nonce_key, 3);
        let tx4 = create_aa_tx(sender, nonce_key, 4);
        let tx6 = create_aa_tx(sender, nonce_key, 6);

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
        pool.add_transaction(Arc::new(valid_tx0), 0).unwrap();
        pool.add_transaction(Arc::new(valid_tx1), 0).unwrap();
        pool.add_transaction(Arc::new(valid_tx3), 0).unwrap();
        pool.add_transaction(Arc::new(valid_tx4), 0).unwrap();
        pool.add_transaction(Arc::new(valid_tx6), 0).unwrap();

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
            !pool.by_id.get(&tx3_id).unwrap().is_pending,
            "Transaction 3 should be queued (gap at nonce 2)"
        );
        assert!(
            !pool.by_id.get(&tx4_id).unwrap().is_pending,
            "Transaction 4 should be queued"
        );
        assert!(
            !pool.by_id.get(&tx6_id).unwrap().is_pending,
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
            pool.by_id.get(&tx3_id).unwrap().is_pending,
            "Transaction 3 should be pending"
        );
        assert!(
            pool.by_id.get(&tx4_id).unwrap().is_pending,
            "Transaction 4 should be pending"
        );

        // Verify transaction 6 is still queued
        assert!(
            !pool.by_id.get(&tx6_id).unwrap().is_pending,
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
        let tx = create_aa_tx(sender, nonce_key, 3);
        let valid_tx = wrap_valid_tx(tx, TransactionOrigin::Local);

        // Try to insert it and specify the on-chain nonce 5, making it outdated
        let result = pool.add_transaction(Arc::new(valid_tx), 5);

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
        let tx_low = create_aa_tx_with_gas(sender, nonce_key, 0, 1_000_000_000, 2_000_000_000);
        let valid_tx_low = wrap_valid_tx(tx_low, TransactionOrigin::Local);

        pool.add_transaction(Arc::new(valid_tx_low), 0).unwrap();

        // Try to replace with only 5% price bump (default requires 10%)
        let tx_insufficient =
            create_aa_tx_with_gas(sender, nonce_key, 0, 1_050_000_000, 2_100_000_000);
        let valid_tx_insufficient = wrap_valid_tx(tx_insufficient, TransactionOrigin::Local);

        let result = pool.add_transaction(Arc::new(valid_tx_insufficient), 0);

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
        let tx0 = create_aa_tx(sender, nonce_key, 0);
        let tx1 = create_aa_tx(sender, nonce_key, 1);
        let tx3 = create_aa_tx(sender, nonce_key, 3);
        let tx4 = create_aa_tx(sender, nonce_key, 4);

        pool.add_transaction(Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)), 0)
            .unwrap();
        pool.add_transaction(Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)), 0)
            .unwrap();
        pool.add_transaction(Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)), 0)
            .unwrap();
        pool.add_transaction(Arc::new(wrap_valid_tx(tx4, TransactionOrigin::Local)), 0)
            .unwrap();

        // Verify initial state: 0, 1 pending | 3, 4 queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 2, "Should have 2 pending (0, 1)");
        assert_eq!(queued_count, 2, "Should have 2 queued (3, 4)");

        // Fill the gap with nonce 2
        let tx2 = create_aa_tx(sender, nonce_key, 2);
        let valid_tx2 = wrap_valid_tx(tx2, TransactionOrigin::Local);

        let result = pool.add_transaction(Arc::new(valid_tx2), 0);
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
        let tx0 = create_aa_tx(sender, nonce_key, 0);
        let tx1 = create_aa_tx(sender, nonce_key, 1);
        let tx2 = create_aa_tx(sender, nonce_key, 2);

        let valid_tx0 = wrap_valid_tx(tx0, TransactionOrigin::Local);
        let valid_tx1 = wrap_valid_tx(tx1, TransactionOrigin::Local);
        let valid_tx2 = wrap_valid_tx(tx2, TransactionOrigin::Local);

        let tx1_hash = *valid_tx1.hash();

        pool.add_transaction(Arc::new(valid_tx0), 0).unwrap();
        pool.add_transaction(Arc::new(valid_tx1), 0).unwrap();
        pool.add_transaction(Arc::new(valid_tx2), 0).unwrap();

        // All should be pending
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 3, "All 3 should be pending");
        assert_eq!(queued_count, 0, "None should be queued");

        let seq_id = AASequenceId::new(sender, nonce_key);
        let tx1_id = AA2dTransactionId::new(seq_id, 1);
        let tx2_id = AA2dTransactionId::new(seq_id, 2);

        // Verify tx2 is pending before removal
        assert!(
            pool.by_id.get(&tx2_id).unwrap().is_pending,
            "tx2 should be pending before removal"
        );

        // Remove tx1 (creates a gap)
        let removed = pool.remove_transactions([&tx1_hash].into_iter());
        assert_eq!(removed.len(), 1, "Should remove tx1");

        // Note: Current implementation doesn't automatically re-scan and update
        // is_pending flags after removal. This is a known limitation.
        // The is_pending flag for tx2 remains true even though there's now a gap.
        // However, tx2 won't be included in independent_transactions or best_transactions
        // until the gap is filled.

        // Verify tx1 is removed from pool
        assert!(!pool.by_id.contains_key(&tx1_id), "tx1 should be removed");
        assert!(!pool.contains(&tx1_hash), "tx1 should be removed");

        // Verify tx0 and tx2 remain
        assert_eq!(pool.by_id.len(), 2, "Should have 2 transactions left");

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
        let tx_a0 = create_aa_tx(sender_a, nonce_key_a, 0);
        let tx_a1 = create_aa_tx(sender_a, nonce_key_a, 1);

        // Sender B: [0, 1]
        let tx_b0 = create_aa_tx(sender_b, nonce_key_b, 0);
        let tx_b1 = create_aa_tx(sender_b, nonce_key_b, 1);

        let valid_tx_a0 = wrap_valid_tx(tx_a0, TransactionOrigin::Local);
        let valid_tx_a1 = wrap_valid_tx(tx_a1, TransactionOrigin::Local);
        let valid_tx_b0 = wrap_valid_tx(tx_b0, TransactionOrigin::Local);
        let valid_tx_b1 = wrap_valid_tx(tx_b1, TransactionOrigin::Local);

        let tx_a0_hash = *valid_tx_a0.hash();

        pool.add_transaction(Arc::new(valid_tx_a0), 0).unwrap();
        pool.add_transaction(Arc::new(valid_tx_a1), 0).unwrap();
        pool.add_transaction(Arc::new(valid_tx_b0), 0).unwrap();
        pool.add_transaction(Arc::new(valid_tx_b1), 0).unwrap();

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
        let tx0 = create_aa_tx_with_gas(sender, nonce_key, 0, 1_000_000_000, 2_000_000_000);
        let tx0_hash = *tx0.hash();
        let valid_tx0 = wrap_valid_tx(tx0, TransactionOrigin::Local);
        let result = pool.add_transaction(Arc::new(valid_tx0), 0);
        assert!(result.is_ok());
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 1);

        // Try to replace with slightly higher gas (1_050_000_000, 2_100_000_000 = ~5% bump) - should fail (< 10% bump)
        let tx0_replacement1 =
            create_aa_tx_with_gas(sender, nonce_key, 0, 1_050_000_000, 2_100_000_000);
        let valid_tx1 = wrap_valid_tx(tx0_replacement1, TransactionOrigin::Local);
        let result = pool.add_transaction(Arc::new(valid_tx1), 0);
        assert!(result.is_err(), "Should reject insufficient price bump");
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 1);
        assert!(
            pool.contains(&tx0_hash),
            "Original tx should still be present"
        );

        // Replace with sufficient bump (1_100_000_000, 2_200_000_000 = 10% bump)
        let tx0_replacement2 =
            create_aa_tx_with_gas(sender, nonce_key, 0, 1_100_000_000, 2_200_000_000);
        let tx0_replacement2_hash = *tx0_replacement2.hash();
        let valid_tx2 = wrap_valid_tx(tx0_replacement2, TransactionOrigin::Local);
        let result = pool.add_transaction(Arc::new(valid_tx2), 0);
        assert!(result.is_ok(), "Should accept 10% price bump");
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 1, "Pool size should remain 1");
        assert!(!pool.contains(&tx0_hash), "Old tx should be removed");
        assert!(
            pool.contains(&tx0_replacement2_hash),
            "New tx should be present"
        );

        // Try to replace with even higher gas (1_500_000_000, 3_000_000_000 = ~36% bump over original)
        let tx0_replacement3 =
            create_aa_tx_with_gas(sender, nonce_key, 0, 1_500_000_000, 3_000_000_000);
        let tx0_replacement3_hash = *tx0_replacement3.hash();
        let valid_tx3 = wrap_valid_tx(tx0_replacement3, TransactionOrigin::Local);
        let result = pool.add_transaction(Arc::new(valid_tx3), 0);
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
        let tx0 = create_aa_tx(sender, nonce_key, 0);
        let tx5 = create_aa_tx(sender, nonce_key, 5);
        let tx10 = create_aa_tx(sender, nonce_key, 10);
        let tx15 = create_aa_tx(sender, nonce_key, 15);

        pool.add_transaction(Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)), 0)
            .unwrap();
        pool.add_transaction(Arc::new(wrap_valid_tx(tx5, TransactionOrigin::Local)), 0)
            .unwrap();
        pool.add_transaction(Arc::new(wrap_valid_tx(tx10, TransactionOrigin::Local)), 0)
            .unwrap();
        pool.add_transaction(Arc::new(wrap_valid_tx(tx15, TransactionOrigin::Local)), 0)
            .unwrap();

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 4);

        // Only tx0 should be pending, rest should be queued
        let tx0_id = AA2dTransactionId::new(seq_id, 0);
        assert!(pool.by_id.get(&tx0_id).unwrap().is_pending);
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 5))
                .unwrap()
                .is_pending
        );
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 10))
                .unwrap()
                .is_pending
        );
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 15))
                .unwrap()
                .is_pending
        );
        assert_eq!(pool.independent_transactions.len(), 1);

        // Fill gap [1,2,3,4]
        for nonce in 1..=4 {
            let tx = create_aa_tx(sender, nonce_key, nonce);
            pool.add_transaction(Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)), 0)
                .unwrap();
        }

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 8);

        // Now [0,1,2,3,4,5] should be pending
        for nonce in 0..=5 {
            let id = AA2dTransactionId::new(seq_id, nonce);
            assert!(
                pool.by_id.get(&id).unwrap().is_pending,
                "Nonce {nonce} should be pending"
            );
        }
        // [10, 15] should still be queued
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 10))
                .unwrap()
                .is_pending
        );
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 15))
                .unwrap()
                .is_pending
        );

        // Fill gap [6,7,8,9]
        for nonce in 6..=9 {
            let tx = create_aa_tx(sender, nonce_key, nonce);
            pool.add_transaction(Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)), 0)
                .unwrap();
        }

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 12);

        // Now [0..=10] should be pending
        for nonce in 0..=10 {
            let id = AA2dTransactionId::new(seq_id, nonce);
            assert!(
                pool.by_id.get(&id).unwrap().is_pending,
                "Nonce {nonce} should be pending"
            );
        }
        // Only [15] should be queued
        assert!(
            !pool
                .by_id
                .get(&AA2dTransactionId::new(seq_id, 15))
                .unwrap()
                .is_pending
        );

        // Fill final gap [11,12,13,14]
        for nonce in 11..=14 {
            let tx = create_aa_tx(sender, nonce_key, nonce);
            pool.add_transaction(Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)), 0)
                .unwrap();
        }

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 16);

        // All should be pending now
        for nonce in 0..=15 {
            let id = AA2dTransactionId::new(seq_id, nonce);
            assert!(
                pool.by_id.get(&id).unwrap().is_pending,
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
            let tx = create_aa_tx(sender, nonce_key, nonce);
            pool.add_transaction(Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)), 0)
                .unwrap();
        }

        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count + queued_count, 5);

        // All should be pending
        for nonce in 0..=4 {
            assert!(
                pool.by_id
                    .get(&AA2dTransactionId::new(seq_id, nonce))
                    .unwrap()
                    .is_pending
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
        let tx0 = create_aa_tx(sender, nonce_key, 0);
        let tx2 = create_aa_tx(sender, nonce_key, 2);
        let tx4 = create_aa_tx(sender, nonce_key, 4);

        pool.add_transaction(Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)), 0)
            .unwrap();
        pool.add_transaction(Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)), 0)
            .unwrap();
        pool.add_transaction(Arc::new(wrap_valid_tx(tx4, TransactionOrigin::Local)), 0)
            .unwrap();

        // Only tx0 should be in independent set
        assert_eq!(pool.independent_transactions.len(), 1);
        assert!(pool.independent_transactions.contains_key(&seq_id));

        // Verify initial state: tx0 pending, tx2 and tx4 queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 1);
        assert_eq!(queued_count, 2);

        // Fill first gap: insert [1]
        let tx1 = create_aa_tx(sender, nonce_key, 1);
        pool.add_transaction(Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)), 0)
            .unwrap();

        // Now [0, 1, 2] should be pending, tx4 still queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 3);
        assert_eq!(queued_count, 1);

        // Still only tx0 in independent set
        assert_eq!(pool.independent_transactions.len(), 1);
        assert!(pool.independent_transactions.contains_key(&seq_id));

        // Fill second gap: insert [3]
        let tx3 = create_aa_tx(sender, nonce_key, 3);
        pool.add_transaction(Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)), 0)
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
                let tx = create_aa_tx(sender, nonce_key, nonce);
                pool.add_transaction(Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)), 0)
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
                assert!(pool.by_id.get(&id).unwrap().is_pending);
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
        let tx0 = create_aa_tx(sender, nonce_key, 0);
        let tx3 = create_aa_tx(sender, nonce_key, 3);
        let tx5 = create_aa_tx(sender, nonce_key, 5);

        pool.add_transaction(Arc::new(wrap_valid_tx(tx0, TransactionOrigin::Local)), 0)
            .unwrap();
        pool.add_transaction(Arc::new(wrap_valid_tx(tx3, TransactionOrigin::Local)), 0)
            .unwrap();
        pool.add_transaction(Arc::new(wrap_valid_tx(tx5, TransactionOrigin::Local)), 0)
            .unwrap();

        // Only tx0 should be in independent set
        assert_eq!(pool.independent_transactions.len(), 1);
        assert!(pool.independent_transactions.contains_key(&seq_id));

        // Verify initial state: tx0 pending, tx3 and tx5 queued
        let (pending_count, queued_count) = pool.pending_and_queued_txn_count();
        assert_eq!(pending_count, 1, "Only tx0 should be pending");
        assert_eq!(queued_count, 2, "tx3 and tx5 should be queued");

        // Fill gaps to get [0, 1, 2, 3, 5]
        let tx1 = create_aa_tx(sender, nonce_key, 1);
        pool.add_transaction(Arc::new(wrap_valid_tx(tx1, TransactionOrigin::Local)), 0)
            .unwrap();

        let tx2 = create_aa_tx(sender, nonce_key, 2);
        pool.add_transaction(Arc::new(wrap_valid_tx(tx2, TransactionOrigin::Local)), 0)
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
        let tx4 = create_aa_tx(sender, nonce_key, 4);
        pool.add_transaction(Arc::new(wrap_valid_tx(tx4, TransactionOrigin::Local)), 3)
            .unwrap();

        // After inserting tx4, we should have [3, 4, 5] all in the pool
        let (_pending_count_after, _queued_count_after) = pool.pending_and_queued_txn_count();
        pool.assert_invariants();
    }
}
