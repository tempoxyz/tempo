/// Basic 2D nonce pool for user nonces (nonce_key > 0) that are tracked on chain.
use crate::transaction::TempoPooledTransaction;
use alloy_primitives::{Address, B256, TxHash, U256};
use parking_lot::RwLock;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::{
    BestTransactions, CoinbaseTipOrdering, PoolResult, PoolTransaction, PriceBumpConfig, Priority,
    SubPool, SubPoolLimit, TransactionOrdering, TransactionOrigin, ValidPoolTransaction,
    error::{InvalidPoolTransactionError, PoolError, PoolErrorKind},
    pool::{AddedPendingTransaction, AddedTransaction, QueuedReason, pending::PendingTransaction},
};
use std::{
    collections::{
        BTreeMap, BTreeSet, Bound::Unbounded, HashMap, HashSet, btree_map::Entry, hash_map,
    },
    sync::Arc,
};
use tempo_chainspec::spec::TEMPO_BASE_FEE;

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
#[derive(Debug, Default)]
pub struct AA2dPool {
    /// Keeps track of transactions inserted in the pool.
    ///
    /// This way we can determine when transactions were submitted to the pool.
    submission_id: u64,
    /// independent, pending, executable transactions.
    independent: HashMap<AA2dTransactionId, PendingTransaction<Ordering>>,
    /// _All_ transactions that are currently inside the pool grouped by their unique identifier.
    by_id: BTreeMap<AA2dTransactionId, AA2dInternalTransaction>,
    /// _All_ transactions by hash.
    by_hash: HashMap<TxHash, Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    /// Keeps track of the known nonce key values per account.
    nonce_keys: AA2dNonceKeys,
    /// Settings for this sub-pool.
    config: AA2dPoolConfig,
}

impl AA2dPool {
    /// Creates a new instance with the givenconfig and nonce keys
    pub fn new(config: AA2dPoolConfig, nonce_keys: AA2dNonceKeys) -> Self {
        Self {
            submission_id: 0,
            independent: Default::default(),
            by_id: Default::default(),
            by_hash: Default::default(),
            nonce_keys,
            config,
        }
    }

    /// Entrypoint for adding a 2d AA transaction.
    ///
    /// ## Limitations
    /// * This currently assumes that the account's nonce key is already tracked in [`AA2dNonceKeys`], if not then this transaction is considered pending.
    pub(crate) fn add_transaction(
        &mut self,
        transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    ) -> PoolResult<AddedTransaction<TempoPooledTransaction>> {
        debug_assert!(
            transaction.transaction.is_aa_2d(),
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
            .expect("is AA transaction");

        let on_chain_nonce = self
            .nonce_keys
            .current_nonce(
                transaction.transaction.sender_ref(),
                &tx_id.sender.nonce_key,
            )
            .unwrap_or_default();

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
            self.by_hash.remove(replaced.inner.transaction.hash());
            self.independent.remove(&tx_id);
        }

        // insert transaction by hash
        self.by_hash
            .insert(*tx.inner.transaction.hash(), tx.inner.transaction.clone());

        let mut promoted = Vec::new();
        // now we need to scan the range and mark transactions as pending, if any
        let on_chain_id = AA2dTransactionId::new(tx_id.sender, on_chain_nonce);
        // track the next nonce we expect if the transactions are gapless
        let mut next_nonce = on_chain_id.nonce;

        // scan all the transactions with the same nonce key starting with the on chain nonce
        for (existing_id, existing_tx) in self.descendant_txs_mut(&on_chain_id) {
            let mut is_promoted = false;
            if existing_id.nonce == next_nonce {
                // if this was previously not pending we need to promote the transaction
                is_promoted = !std::mem::replace(&mut existing_tx.is_pending, true);
            } else {
                existing_tx.is_pending = false;
            }
            if existing_id.nonce == tx_id.nonce {
                // we found our transaction and keep track of whether it's pending
                inserted_as_pending = existing_tx.is_pending;
            } else if is_promoted {
                promoted.push(existing_tx.inner.transaction.clone());
            }

            next_nonce = existing_id.nonce.saturating_add(1);
        }

        if inserted_as_pending {
            // if this is the next nonce in line we can mark it as independent
            if tx_id.nonce == on_chain_nonce {
                self.independent.insert(tx_id, tx.inner);
            }

            return Ok(AddedTransaction::Pending(AddedPendingTransaction {
                transaction,
                replaced: replaced.map(|tx| tx.inner.transaction),
                promoted,
                discarded: Default::default(),
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
            independent: self.independent.values().cloned().collect(),
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
            .take_while(|(other, _)| id.sender == other.sender)
    }

    fn remove_transaction_by_id(
        &mut self,
        id: &AA2dTransactionId,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let tx = self.by_id.remove(id)?;
        self.independent.remove(id);
        self.by_hash.remove(tx.inner.transaction.hash());
        Some(tx.inner.transaction)
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
            if let Some(tx) = self.by_hash.remove(tx_hash) {
                txs.push(tx);
            }
        }
        txs
    }
    /// Removes the transaction by its hash from all internal sets.
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
        self.independent.remove(&id);
        Some(tx)
    }

    /// Updates the internal state based on the state changes of the `NonceManager` [`NONCE_PRECOMPILE_ADDRESS`](tempo_precompiles::NONCE_PRECOMPILE_ADDRESS).
    ///
    /// This takes a vec of changed [`AASenderId`] with their current on chain nonce.
    ///
    /// This will prune mined transactions and promote unblocked transactions if any, returns `(promoted, mined)`
    #[allow(clippy::type_complexity)]
    pub(crate) fn on_aa_2d_nonce_changes(
        &mut self,
        on_chain_ids: HashMap<AASenderId, u64>,
    ) -> (
        Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    ) {
        let mut promoted = Vec::new();
        let mut mined_ids = Vec::new();

        // we assume the set of changed senders is smaller than the individual accounts
        'changes: for (sender_id, on_chain_nonce) in on_chain_ids {
            let mut iter = self
                .by_id
                .range_mut((sender_id.start_bound(), Unbounded))
                .take_while(move |(other, _)| sender_id == other.sender)
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

            let mut next_nonce = on_chain_nonce;
            for (existing_id, existing_tx) in iter {
                if existing_id.nonce == next_nonce {
                    if std::mem::replace(&mut existing_tx.is_pending, true) {
                        promoted.push(existing_tx.inner.transaction.clone());
                    }

                    if existing_id.nonce == on_chain_nonce {
                        // if this is the on chain nonce we can mark it as the next independent transaction
                        self.independent
                            .insert(*existing_id, existing_tx.inner.clone());
                    }
                } else {
                    // can exit early
                    break;
                }

                next_nonce = next_nonce.saturating_add(1);
            }
        }

        // actually remove mined transactions
        let mut mined = Vec::with_capacity(mined_ids.len());
        for id in mined_ids {
            if let Some(removed) = self.remove_transaction_by_id(&id) {
                mined.push(removed);
            }
        }

        (promoted, mined)
    }

    /// Removes transactions if the pool is above capacity.
    fn discard(&mut self) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        Vec::new()
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

    /// Returns the shared instance of the [`AA2dNonceKeys`]
    pub(crate) fn aa_2d_nonce_keys(&self) -> &AA2dNonceKeys {
        &self.nonce_keys
    }

    const fn next_id(&mut self) -> u64 {
        let id = self.submission_id;
        self.submission_id = self.submission_id.wrapping_add(1);
        id
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

/// Keeps track of the account's nonce keys.
///
/// This tries to be in sync with the state
#[derive(Default, Debug, Clone)]
pub struct AA2dNonceKeys {
    inner: Arc<RwLock<AA2dNonceKeysInner>>,
}

impl AA2dNonceKeys {
    /// Inserts/Updates the latest account info
    pub fn insert(&self, address: Address, nonce_key: U256, nonce: u64, slot: U256) {
        self.inner.write().insert(address, nonce_key, nonce, slot)
    }

    /// Returns the tracked nonce for this address' nonce key.
    pub fn current_nonce(&self, address: &Address, nonce_key: &U256) -> Option<u64> {
        self.inner.read().current_nonce(address, nonce_key)
    }

    /// Update the tracked nonces for the slots and return the new on chain identifiers for the changed slots.]
    ///
    /// Note: This only updates existing, tracked slots.
    pub(crate) fn update_tracked(
        &self,
        changed_slots: impl IntoIterator<Item = (U256, U256)>,
    ) -> HashMap<AASenderId, u64> {
        self.inner.write().update_tracked(changed_slots)
    }
}

/// Keeps track of the account's nonce keys.
///
/// This tries to be in sync with the
#[derive(Default, Debug)]
struct AA2dNonceKeysInner {
    /// Keeps track of the on chain nonce for an account's nonce key.
    address_to_nonce_keys: HashMap<Address, HashMap<U256, u64>>,
    /// Reverse index for the storage slot of an account's nonce
    ///
    /// ```solidity
    ///  mapping(address => mapping(uint256 => uint64)) public nonces
    /// ```
    ///
    /// This identifies the account and nonce key based on the slot in the `NonceManager`.
    address_slots: HashMap<U256, (Address, U256)>,
}

impl AA2dNonceKeysInner {
    /// Inserts the nonce key info for the account's nonce key.
    fn insert(&mut self, address: Address, nonce_key: U256, nonce: u64, slot: U256) {
        self.address_to_nonce_keys
            .entry(address)
            .or_default()
            .insert(nonce_key, nonce);
        self.address_slots.insert(slot, (address, nonce_key));
    }

    fn current_nonce(&self, address: &Address, nonce_key: &U256) -> Option<u64> {
        self.address_to_nonce_keys
            .get(address)?
            .get(nonce_key)
            .copied()
    }

    fn update_tracked(
        &mut self,
        changed_slots: impl IntoIterator<Item = (U256, U256)>,
    ) -> HashMap<AASenderId, u64> {
        let mut ids = HashMap::new();
        for (accout_nonce_key_slot, nonce) in changed_slots {
            if let Some((address, nonce_key)) = self.address_slots.get(&accout_nonce_key_slot)
                && let Some(nonce_keys) = self.address_to_nonce_keys.get_mut(address)
            {
                match nonce_keys.entry(*nonce_key) {
                    hash_map::Entry::Occupied(mut entry) => {
                        let new_nonce = nonce.saturating_to();
                        entry.insert(new_nonce);
                        ids.insert(AASenderId::new(*address, *nonce_key), new_nonce);
                    }
                    hash_map::Entry::Vacant(_) => {
                        // we haven't tracked this key yet, so we ignore
                    }
                }
            }
        }
        ids
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
    pub(crate) invalid: HashSet<AASenderId>,
}

impl BestAA2dTransactions {
    /// Removes the best transaction from the set
    fn pop_best(&mut self) -> Option<(AA2dTransactionId, PendingTransaction<Ordering>)> {
        let tx = self.independent.pop_last()?;
        let id = tx.transaction.transaction.aa_transaction_id().unwrap();
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
            if self.invalid.contains(&id.sender) {
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
            self.invalid.insert(id.sender);
        }
    }

    fn no_updates(&mut self) {}

    fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
}

/// Key for identifying a unique sender in 2D nonce system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) struct AASenderId {
    pub(crate) address: Address,
    pub(crate) nonce_key: U256,
}

impl AASenderId {
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
    pub(crate) sender: AASenderId,
    pub(crate) nonce: u64,
}

impl AA2dTransactionId {
    /// Creates a new identifier.
    pub(crate) const fn new(sender: AASenderId, nonce: u64) -> Self {
        Self { sender, nonce }
    }

    /// Returns the next transaction in the sequence.
    pub(crate) fn unlocks(&self) -> Self {
        Self::new(self.sender, self.nonce.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn insert_pending() {}
}
