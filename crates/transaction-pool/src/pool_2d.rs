/// Basic 2D nonce pool for user nonces (nonce_key > 0) that are tracked on chain.
use crate::transaction::TempoPooledTransaction;
use alloy_primitives::{Address, B256, TxHash, U256};
use parking_lot::RwLock;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::{
    CoinbaseTipOrdering, PoolResult, PoolTransaction, TransactionOrdering, ValidPoolTransaction,
    error::{InvalidPoolTransactionError, PoolError, PoolErrorKind},
    pool::{AddedPendingTransaction, AddedTransaction, pending::PendingTransaction},
};
use std::{
    collections::{BTreeSet, HashMap, hash_map::Entry},
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
pub(super) struct Pool2D2 {
    /// Keeps track of transactions inserted in the pool.
    ///
    /// This way we can determine when transactions were submitted to the pool.
    submission_id: u64,
    /// pending, executable transactions sorted by their priority.
    pending: BTreeSet<PendingTransaction<Ordering>>,
    // TODO: separate by queued and pending
    /// _All_ transactions that are currently inside the pool grouped by their unique identifier.
    by_id: HashMap<AA2dTransactionId, PendingTransaction<Ordering>>,
    /// _All_ transactions by hash.
    by_hash: HashMap<TxHash, Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    /// Keeps track of the known nonce key values per account.
    nonce_keys: NonceKeys,
}

impl Pool2D2 {
    /// Entrypoint for adding a 2d AA transaction.
    ///
    /// ## Limitations
    /// * This currently assumes that the account's nonce key is already tracked in [`NonceKeys`], if not then this transaction is considered pending.
    pub fn add_transaction(
        &mut self,
        transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
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
            .expect("is AA transaction");

        // check if it's pending or queued
        let active_nonce = self
            .nonce_keys
            .current_nonce(
                transaction.transaction.sender_ref(),
                &tx_id.sender.nonce_key,
            )
            .unwrap_or_default();

        if transaction.nonce() < active_nonce {
            // outdated transaction
            return Err(PoolError::new(
                *transaction.hash(),
                PoolErrorKind::InvalidTransaction(InvalidPoolTransactionError::Consensus(
                    InvalidTransactionError::NonceNotConsistent {
                        tx: transaction.nonce(),
                        state: active_nonce,
                    },
                )),
            ));
        }

        let tx = PendingTransaction {
            submission_id: self.next_id(),
            priority: CoinbaseTipOrdering::default()
                .priority(&transaction.transaction, TEMPO_BASE_FEE),
            transaction: transaction.clone(),
        };

        // insert into the unique id set
        let replaced = match self.by_id.entry(tx_id) {
            Entry::Occupied(mut entry) => {
                // TODO: handle replacements, for now simply replace
                Some(entry.insert(tx.clone()))
            }
            Entry::Vacant(mut entry) => {
                entry.insert(tx.clone());
                None
            }
        };

        // insert transaction by hash
        self.by_hash
            .insert(*tx.transaction.hash(), tx.transaction.clone());

        // clean up replaced
        if let Some(replaced) = &replaced {
            self.by_hash.remove(replaced.transaction.hash());
            self.pending.remove(&replaced);
        }

        if active_nonce == tx.transaction.nonce() {
            // insert to pending
            self.pending.insert(tx);

            return Ok(AddedTransaction::Pending(AddedPendingTransaction {
                transaction,
                replaced: replaced.map(|tx| tx.transaction),
                promoted: Default::default(),
                discarded: Default::default(),
            }));

            // TODO: check if this promoted any transactions
        }

        // parked transaction if ancestor key does not exist

        todo!()
    }

    /// Returns the best, executable transactions for this sub-pool
    pub fn best(&self) -> BestAATransactions {
        BestAATransactions {
            pending: self.pending.clone(),
            by_id: self.by_id.clone(),
        }
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
        let tx = self.by_id.remove(&id)?;
        self.pending.remove(&tx);
        Some(tx.transaction)
    }

    /// Updates the internal state based on the state changes of the `NonceManager` [`NONCE_PRECOMPILE_ADDRESS`](tempo_precompiles::NONCE_PRECOMPILE_ADDRESS).
    ///
    /// This will prune mined transactions and promote unblocked transactions if any.
    pub fn on_state_change(&mut self) {}

    /// Removes transactions if the pool is above capacity.
    fn discard(&mut self) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let removed = Vec::new();

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
}

/// Keeps track of the account's nonce keys.
///
/// This tries to be in sync with the state
#[derive(Default, Debug, Clone)]
pub struct NonceKeys {
    inner: Arc<RwLock<NonceKeysInner>>,
}

impl NonceKeys {
    /// Inserts/Updates the latest account info
    pub fn insert(&self, address: Address, nonce_key: U256, nonce: u64, slot: U256) {
        self.inner.write().insert(address, nonce_key, nonce, slot)
    }

    /// Returns the tracked nonce for this address' nonce key.
    pub fn current_nonce(&self, address: &Address, nonce_key: &U256) -> Option<u64> {
        self.inner.read().current_nonce(address, nonce_key)
    }
}

/// Keeps track of the account's nonce keys.
///
/// This tries to be in sync with the
#[derive(Default, Debug)]
struct NonceKeysInner {
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

impl NonceKeysInner {
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
            .get(&nonce_key)
            .copied()
    }
}

/// A snapshot of the sub-pool containing all executable transactions.
#[derive(Debug)]
pub(crate) struct BestAATransactions {
    /// pending, executable transactions sorted by their priority.
    pending: BTreeSet<PendingTransaction<Ordering>>,
    /// _All_ transactions that are currently inside the pool grouped by their unique identifier.
    by_id: HashMap<AA2dTransactionId, PendingTransaction<Ordering>>,
}

impl BestAATransactions {}

/// Key for identifying a unique sender in 2D nonce system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct AASenderId {
    pub(crate) address: Address,
    pub(crate) nonce_key: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct AA2dTransactionId {
    pub(crate) sender: AASenderId,
    pub(crate) nonce: u64,
}

impl AA2dTransactionId {
    /// Returns the id of the ancestor transaction if any
    fn ancestor(&self) -> Option<AA2dTransactionId> {
        self.nonce.checked_sub(1).map(|nonce| AA2dTransactionId {
            sender: self.sender,
            nonce,
        })
    }
}
