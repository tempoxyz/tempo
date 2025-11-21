// Minimal 2D nonce pool for user nonces (nonce_key > 0)
// Follows Reth's pool patterns but simplified for 2D nonce use case

use crate::transaction::TempoPooledTransaction;
use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, U256};
use parking_lot::RwLock;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_provider::StateProviderFactory;
use reth_transaction_pool::{
    BestTransactions, PoolSize, PoolTransaction, TransactionOrigin, ValidPoolTransaction,
    error::{InvalidPoolTransactionError, PoolError, PoolErrorKind},
    identifier::{SenderId, TransactionId},
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::Instant,
};
use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, storage::slots::mapping_slot};

/// Key for identifying a unique sender in 2D nonce system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SenderKey {
    address: Address,
    nonce_key: U256,
}

/// Transactions for a specific (address, nonce_key) pair
#[derive(Debug)]
struct SenderTransactions {
    /// Transactions ordered by nonce
    transactions: BTreeMap<u64, Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    /// Current state nonce
    state_nonce: u64,
}

impl SenderTransactions {
    fn new(state_nonce: u64) -> Self {
        Self {
            transactions: BTreeMap::new(),
            state_nonce,
        }
    }

    /// Check if a nonce is ready (matches state nonce)
    fn is_ready(&self, nonce: u64) -> bool {
        nonce == self.state_nonce
    }

    /// Get next ready transaction
    fn next_ready(&self) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.transactions.get(&self.state_nonce).cloned()
    }

    /// Add transaction, potentially replacing existing
    fn add_transaction(
        &mut self,
        tx: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    ) -> Result<
        Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        InvalidPoolTransactionError,
    > {
        let nonce = tx.nonce();

        if nonce < self.state_nonce {
            return Err(InvalidPoolTransactionError::Consensus(
                InvalidTransactionError::NonceNotConsistent {
                    tx: nonce,
                    state: self.state_nonce,
                },
            ));
        }

        // Check for replacement (requires 10% gas price bump)
        if let Some(existing) = self.transactions.get(&nonce) {
            let existing_price = existing.max_fee_per_gas();
            let new_price = tx.max_fee_per_gas();

            if new_price <= existing_price * 110 / 100 {
                return Err(InvalidPoolTransactionError::Underpriced);
            }
        }

        Ok(self.transactions.insert(nonce, tx))
    }

    /// Remove transaction by nonce
    fn remove(&mut self, nonce: u64) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.transactions.remove(&nonce)
    }

    /// Update state nonce after execution
    #[allow(dead_code)]
    fn update_state_nonce(&mut self, new_nonce: u64) {
        self.state_nonce = new_nonce;
        // Remove executed transactions
        self.transactions = self.transactions.split_off(&new_nonce);
    }

    /// Remove all transactions with nonce >= given
    fn remove_descendants(
        &mut self,
        from_nonce: u64,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut removed = vec![];
        let to_remove = self.transactions.split_off(&from_nonce);
        for (_, tx) in to_remove {
            removed.push(tx);
        }
        removed
    }
}

/// Minimal 2D nonce pool
pub(super) struct Pool2D<S: StateProviderFactory> {
    /// State provider for nonce queries
    state: S,

    /// Transactions organized by (address, nonce_key)
    by_sender: Arc<RwLock<HashMap<SenderKey, SenderTransactions>>>,

    /// Index: hash -> transaction
    by_hash: Arc<RwLock<HashMap<B256, Arc<ValidPoolTransaction<TempoPooledTransaction>>>>>,

    /// Index: address -> list of nonce_keys
    address_to_keys: Arc<RwLock<HashMap<Address, HashSet<U256>>>>,

    /// Track transaction origin for metrics
    tx_origin: Arc<RwLock<HashMap<B256, TransactionOrigin>>>,
}

impl<S: StateProviderFactory> Pool2D<S> {
    pub(super) fn new(state: S) -> Self {
        Self {
            state,
            by_sender: Arc::new(RwLock::new(HashMap::new())),
            by_hash: Arc::new(RwLock::new(HashMap::new())),
            address_to_keys: Arc::new(RwLock::new(HashMap::new())),
            tx_origin: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the current nonce from state for (address, nonce_key)
    fn get_state_nonce(&self, address: Address, nonce_key: U256) -> Result<u64, PoolError> {
        // Query from NonceManager precompile
        let state = self.state.latest().map_err(|_e| PoolError {
            hash: B256::ZERO,
            kind: PoolErrorKind::InvalidTransaction(InvalidPoolTransactionError::Consensus(
                InvalidTransactionError::TxTypeNotSupported,
            )),
        })?;

        // Compute storage slot for 2D nonce
        // Based on: mapping(address => mapping(uint256 => uint64)) at slot 0
        let outer_slot = mapping_slot(address.as_slice(), U256::ZERO);
        let slot = mapping_slot(nonce_key.as_le_bytes(), outer_slot);

        let nonce_value = state
            .storage(NONCE_PRECOMPILE_ADDRESS, slot.into())
            .map_err(|_e| PoolError {
                hash: B256::ZERO,
                kind: PoolErrorKind::InvalidTransaction(InvalidPoolTransactionError::Consensus(
                    InvalidTransactionError::TxTypeNotSupported,
                )),
            })?;

        // Storage returns Option<U256>, unwrap to U256 then convert to u64
        Ok(nonce_value.unwrap_or_default().to::<u64>())
    }

    /// Add a transaction to the pool
    pub(super) async fn add_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: TempoPooledTransaction,
    ) -> Result<B256, PoolError> {
        self.add_transaction_sync(origin, transaction)
    }

    /// Synchronous version of add_transaction
    pub(super) fn add_transaction_sync(
        &self,
        origin: TransactionOrigin,
        transaction: TempoPooledTransaction,
    ) -> Result<B256, PoolError> {
        let hash = *transaction.hash();

        // Check if already exists
        if self.by_hash.read().contains_key(&hash) {
            return Err(PoolError {
                hash,
                kind: PoolErrorKind::AlreadyImported,
            });
        }

        // Extract nonce_key from AA transaction
        let nonce_key = transaction
            .inner()
            .as_aa()
            .map(|aa| aa.tx().nonce_key)
            .ok_or_else(|| PoolError {
                hash,
                kind: PoolErrorKind::InvalidTransaction(InvalidPoolTransactionError::Consensus(
                    InvalidTransactionError::TxTypeNotSupported,
                )),
            })?;

        if nonce_key.is_zero() {
            return Err(PoolError {
                hash,
                kind: PoolErrorKind::InvalidTransaction(InvalidPoolTransactionError::Consensus(
                    InvalidTransactionError::TxTypeNotSupported,
                )),
            });
        }

        let sender = transaction.sender();
        let nonce = transaction.nonce();
        let sender_key = SenderKey {
            address: sender,
            nonce_key,
        };

        // Get state nonce
        let state_nonce = self.get_state_nonce(sender, nonce_key)?;

        // Create valid pool transaction manually
        // We need to assign a SenderId - for 2D nonces, we'll use a simple hash-based approach
        let sender_hash = u64::from_le_bytes(sender.as_slice()[..8].try_into().unwrap());
        let nonce_key_hash = nonce_key.wrapping_to::<u64>();
        let sender_id = SenderId::from((sender_hash ^ nonce_key_hash).wrapping_add(nonce));

        let pooled = Arc::new(ValidPoolTransaction {
            transaction,
            transaction_id: TransactionId::new(sender_id, nonce),
            propagate: true,
            timestamp: Instant::now(),
            origin,
            authority_ids: None,
        });

        // Add to sender's queue
        {
            let mut by_sender = self.by_sender.write();
            let sender_txs = by_sender
                .entry(sender_key)
                .or_insert_with(|| SenderTransactions::new(state_nonce));

            // Always update to latest state nonce (fixes bug where cached nonce was stale)
            sender_txs.state_nonce = state_nonce;

            if let Some(replaced) =
                sender_txs
                    .add_transaction(pooled.clone())
                    .map_err(|e| PoolError {
                        hash,
                        kind: PoolErrorKind::InvalidTransaction(e),
                    })?
            {
                // Remove replaced from indices
                self.by_hash.write().remove(replaced.hash());
                self.tx_origin.write().remove(replaced.hash());
            }
        }

        // Update indices
        self.by_hash.write().insert(hash, pooled);
        self.tx_origin.write().insert(hash, origin);

        // Track nonce_key for this address
        self.address_to_keys
            .write()
            .entry(sender)
            .or_default()
            .insert(nonce_key);

        Ok(hash)
    }

    /// Remove a transaction
    pub(super) fn remove_transaction(
        &self,
        hash: &B256,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let tx = self.by_hash.write().remove(hash)?;
        self.tx_origin.write().remove(hash);

        // Extract info
        let sender = tx.sender();
        let nonce_key = tx
            .transaction
            .inner()
            .as_aa()
            .map(|aa| aa.tx().nonce_key)
            .unwrap_or(U256::ZERO);

        let sender_key = SenderKey {
            address: sender,
            nonce_key,
        };

        // Remove from sender's queue
        if let Some(sender_txs) = self.by_sender.write().get_mut(&sender_key) {
            sender_txs.remove(tx.nonce());
        }

        Some(tx)
    }

    /// Remove transaction and its descendants
    pub(super) fn remove_transaction_and_descendants(
        &self,
        hash: &B256,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut removed = vec![];

        if let Some(tx) = self.remove_transaction(hash) {
            let sender = tx.sender();
            let nonce = tx.nonce();
            let nonce_key = tx
                .transaction
                .inner()
                .as_aa()
                .map(|aa| aa.tx().nonce_key)
                .unwrap_or(U256::ZERO);

            removed.push(tx);

            let sender_key = SenderKey {
                address: sender,
                nonce_key,
            };

            // Remove descendants (higher nonces)
            if let Some(sender_txs) = self.by_sender.write().get_mut(&sender_key) {
                let descendants = sender_txs.remove_descendants(nonce + 1);
                for desc_tx in &descendants {
                    self.by_hash.write().remove(desc_tx.hash());
                    self.tx_origin.write().remove(desc_tx.hash());
                }
                removed.extend(descendants);
            }
        }

        removed
    }

    /// Get best transactions for block building
    pub(super) fn best_transactions(
        &self,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>> {
        let ready = self.ready_transactions();
        Box::new(BestTransactions2D::new(ready))
    }

    /// Get best transactions with base fee filter
    pub(super) fn best_transactions_with_base_fee(
        &self,
        base_fee: u64,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>> {
        let ready = self
            .ready_transactions()
            .into_iter()
            .filter(|tx| tx.max_fee_per_gas() >= base_fee as u128)
            .collect();
        Box::new(BestTransactions2D::new(ready))
    }

    /// Get all ready transactions (nonce matches state)
    fn ready_transactions(&self) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let by_sender = self.by_sender.read();
        let mut ready = vec![];

        for sender_txs in by_sender.values() {
            if let Some(tx) = sender_txs.next_ready() {
                ready.push(tx);
            }
        }

        // Sort by gas price descending
        ready.sort_by(|a, b| b.max_fee_per_gas().cmp(&a.max_fee_per_gas()));

        ready
    }

    /// Get pending transactions
    pub(super) fn pending_transactions(
        &self,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.ready_transactions()
    }

    /// Get queued transactions (with nonce gaps)
    pub(super) fn queued_transactions(
        &self,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let by_sender = self.by_sender.read();
        let mut queued = vec![];

        for sender_txs in by_sender.values() {
            for (nonce, tx) in &sender_txs.transactions {
                if !sender_txs.is_ready(*nonce) {
                    queued.push(tx.clone());
                }
            }
        }

        queued
    }

    /// Get all transactions
    pub(super) fn all_transactions(
        &self,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_hash.read().values().cloned().collect()
    }

    /// Get transaction by hash
    pub(super) fn get_transaction(
        &self,
        hash: &B256,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        self.by_hash.read().get(hash).cloned()
    }

    /// Get all transaction hashes
    pub(super) fn all_hashes(&self) -> Vec<B256> {
        self.by_hash.read().keys().copied().collect()
    }

    /// Pool size metrics
    pub(super) fn size(&self) -> PoolSize {
        let by_hash = self.by_hash.read();
        let total = by_hash.len();

        // Count pending vs queued
        let pending = self.ready_transactions().len();
        let queued = total - pending;

        PoolSize {
            pending,
            pending_size: pending, // Simplified: assume 1:1 for now
            basefee: 0,
            basefee_size: 0,
            queued,
            queued_size: queued,
            blob: 0,
            blob_size: 0,
            total,
        }
    }

    /// Remove all transactions for a sender
    pub(super) fn remove_all_for_sender(
        &self,
        address: &Address,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut removed = vec![];

        // Get all nonce_keys for this address
        let nonce_keys = self
            .address_to_keys
            .read()
            .get(address)
            .cloned()
            .unwrap_or_default();

        for nonce_key in nonce_keys {
            let sender_key = SenderKey {
                address: *address,
                nonce_key,
            };

            if let Some(sender_txs) = self.by_sender.write().remove(&sender_key) {
                for (_, tx) in sender_txs.transactions {
                    self.by_hash.write().remove(tx.hash());
                    self.tx_origin.write().remove(tx.hash());
                    removed.push(tx);
                }
            }
        }

        // Clean up address_to_keys
        self.address_to_keys.write().remove(address);

        removed
    }

    /// Get transactions by address
    pub(super) fn get_transactions_by_address(
        &self,
        address: &Address,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut txs = vec![];

        let nonce_keys = self
            .address_to_keys
            .read()
            .get(address)
            .cloned()
            .unwrap_or_default();

        let by_sender = self.by_sender.read();
        for nonce_key in nonce_keys {
            let sender_key = SenderKey {
                address: *address,
                nonce_key,
            };

            if let Some(sender_txs) = by_sender.get(&sender_key) {
                txs.extend(sender_txs.transactions.values().cloned());
            }
        }

        txs
    }

    /// Get pending transactions for address
    pub(super) fn get_pending_for_address(
        &self,
        address: &Address,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut pending = vec![];

        let nonce_keys = self
            .address_to_keys
            .read()
            .get(address)
            .cloned()
            .unwrap_or_default();

        let by_sender = self.by_sender.read();
        for nonce_key in nonce_keys {
            let sender_key = SenderKey {
                address: *address,
                nonce_key,
            };

            if let Some(sender_txs) = by_sender.get(&sender_key) {
                if let Some(tx) = sender_txs.next_ready() {
                    pending.push(tx);
                }
            }
        }

        pending
    }

    /// Get queued transactions for address
    pub(super) fn get_queued_for_address(
        &self,
        address: &Address,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut queued = vec![];

        let nonce_keys = self
            .address_to_keys
            .read()
            .get(address)
            .cloned()
            .unwrap_or_default();

        let by_sender = self.by_sender.read();
        for nonce_key in nonce_keys {
            let sender_key = SenderKey {
                address: *address,
                nonce_key,
            };

            if let Some(sender_txs) = by_sender.get(&sender_key) {
                for (nonce, tx) in &sender_txs.transactions {
                    if !sender_txs.is_ready(*nonce) {
                        queued.push(tx.clone());
                    }
                }
            }
        }

        queued
    }

    /// Get highest nonce transaction for address
    pub(super) fn get_highest_nonce_tx(
        &self,
        address: &Address,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let nonce_keys = self.address_to_keys.read().get(address).cloned()?;

        let by_sender = self.by_sender.read();
        let mut highest = None;
        let mut highest_nonce = 0;

        for nonce_key in nonce_keys {
            let sender_key = SenderKey {
                address: *address,
                nonce_key,
            };

            if let Some(sender_txs) = by_sender.get(&sender_key) {
                if let Some((&nonce, tx)) = sender_txs.transactions.last_key_value() {
                    if highest.is_none() || nonce > highest_nonce {
                        highest = Some(tx.clone());
                        highest_nonce = nonce;
                    }
                }
            }
        }

        highest
    }

    /// Get transaction by sender and nonce (any nonce_key)
    pub(super) fn get_by_sender_and_nonce(
        &self,
        address: &Address,
        nonce: u64,
    ) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let nonce_keys = self.address_to_keys.read().get(address).cloned()?;

        let by_sender = self.by_sender.read();
        for nonce_key in nonce_keys {
            let sender_key = SenderKey {
                address: *address,
                nonce_key,
            };

            if let Some(sender_txs) = by_sender.get(&sender_key) {
                if let Some(tx) = sender_txs.transactions.get(&nonce) {
                    return Some(tx.clone());
                }
            }
        }

        None
    }

    /// Get unique senders
    pub(super) fn unique_senders(&self) -> HashSet<Address> {
        self.address_to_keys.read().keys().copied().collect()
    }

    /// Get transactions by origin
    pub(super) fn get_transactions_by_origin(
        &self,
        origin: TransactionOrigin,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let tx_origin = self.tx_origin.read();
        let by_hash = self.by_hash.read();

        tx_origin
            .iter()
            .filter(|&(_, o)| *o == origin)
            .filter_map(|(hash, _)| by_hash.get(hash).cloned())
            .collect()
    }

    /// Retain only unknown transactions
    #[allow(dead_code)]
    pub(super) fn retain_unknown(&self, known: &HashSet<B256>) {
        let mut by_hash = self.by_hash.write();
        let mut tx_origin = self.tx_origin.write();
        let mut to_remove = vec![];

        for hash in by_hash.keys() {
            if known.contains(hash) {
                to_remove.push(*hash);
            }
        }

        for hash in to_remove {
            if let Some(tx) = by_hash.remove(&hash) {
                tx_origin.remove(&hash);

                // Remove from sender queue
                let sender = tx.sender();
                let nonce_key = tx
                    .transaction
                    .inner()
                    .as_aa()
                    .map(|aa| aa.tx().nonce_key)
                    .unwrap_or(U256::ZERO);

                let sender_key = SenderKey {
                    address: sender,
                    nonce_key,
                };

                if let Some(sender_txs) = self.by_sender.write().get_mut(&sender_key) {
                    sender_txs.remove(tx.nonce());
                }
            }
        }
    }
}

/// Simple best transactions iterator for 2D pool
struct BestTransactions2D {
    transactions: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    position: usize,
}

impl BestTransactions2D {
    fn new(transactions: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>) -> Self {
        // Already sorted by gas price in ready_transactions()
        Self {
            transactions,
            position: 0,
        }
    }
}

// First implement Iterator
impl Iterator for BestTransactions2D {
    type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position < self.transactions.len() {
            let tx = self.transactions[self.position].clone();
            self.position += 1;
            Some(tx)
        } else {
            None
        }
    }
}

// Then implement BestTransactions
impl BestTransactions for BestTransactions2D {
    fn mark_invalid(&mut self, _tx: &Self::Item, _error: InvalidPoolTransactionError) {
        // In a full implementation, would track invalid transactions
    }

    fn no_updates(&mut self) {
        // No new transactions available
    }

    fn skip_blobs(&mut self) {
        // 2D pool doesn't handle blob transactions
    }

    fn set_skip_blobs(&mut self, _skip: bool) {
        // 2D pool doesn't handle blob transactions
    }
}
