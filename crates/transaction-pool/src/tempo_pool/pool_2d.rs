// Minimal 2D nonce pool for user nonces (nonce_key > 0)
// Follows Reth's pool patterns but simplified for 2D nonce use case
//
// NONCE TRACKING STRATEGY:
// @mattse: Does this make sense? I am a bit shaky on if this is handles negative cases correctly
// This pool uses optimistic nonce tracking to handle the fact that StateProvider.latest()
// returns stale data for precompile storage (2D nonces).
//
// 1. Cached State Nonces:
//    - Each (address, nonce_key) pair has a cached `state_nonce` representing the expected next nonce
//    - Initialized from on-chain state when first transaction is added
//    - Protected from stale state queries by only updating when queried value is HIGHER
//
// 2. Optimistic Advancement:
//    - When the iterator returns a transaction via `next()`, it immediately advances the cached nonce
//    - This allows subsequent calls to return the next transaction in sequence
//    - Works because state queries are stale and can't be relied upon during block building
//
// 3. Rollback on Failure:
//    - If payload builder calls `mark_invalid()` on a transaction, we roll back the nonce
//    - This prevents losing valid transactions when execution fails
//
// 4. Dynamic Iterator (Gap Handling):
//    - Unlike snapshot-based iterators, BestTransactions2D queries ready state on EACH call to `next()`
//    - When a transaction is executed and nonce advances, queued transactions automatically promote
//    - Example: Have [0, 2], state_nonce=0
//      * First `next()` returns 0, advances to 1
//      * Second `next()` sees no tx at nonce=1, returns None
//      * User sends nonce=1
//      * Next `next()` returns 1, advances to 2
//      * Next `next()` returns 2 (was queued, now promoted!)
//
// Why this approach:
// - StateProvider.latest() returns stale data (doesn't immediately reflect newly mined blocks)
// - 2D nonces are stored in precompile storage which updates during execution but queries are cached
// - We don't have access to Reth's internal maintenance task that updates the protocol pool
// - Optimistic tracking works perfectly for sequential block building with successful transactions

use crate::{transaction::TempoPooledTransaction, validator::TempoTransactionValidator};
use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256, U256};
use parking_lot::RwLock;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_provider::StateProviderFactory;
use reth_transaction_pool::{
    BestTransactions, PoolSize, PoolTransaction, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidationTaskExecutor, TransactionValidator, ValidPoolTransaction,
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
pub(super) struct Pool2D<S>
where
    S: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + 'static,
{
    /// State provider for nonce queries
    state: S,

    /// Transaction validator
    validator: Arc<TransactionValidationTaskExecutor<TempoTransactionValidator<S>>>,

    /// Transactions organized by (address, nonce_key)
    by_sender: Arc<RwLock<HashMap<SenderKey, SenderTransactions>>>,

    /// Index: hash -> transaction
    by_hash: Arc<RwLock<HashMap<B256, Arc<ValidPoolTransaction<TempoPooledTransaction>>>>>,

    /// Index: address -> list of nonce_keys
    address_to_keys: Arc<RwLock<HashMap<Address, HashSet<U256>>>>,

    /// Track transaction origin for metrics
    tx_origin: Arc<RwLock<HashMap<B256, TransactionOrigin>>>,
}

impl<S> Pool2D<S>
where
    S: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + 'static,
{
    pub(super) fn new(
        state: S,
        validator: Arc<TransactionValidationTaskExecutor<TempoTransactionValidator<S>>>,
    ) -> Self {
        Self {
            state,
            validator,
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
        // Validate the transaction first
        let validation_result = self
            .validator
            .validate_transaction(origin, transaction)
            .await;

        match validation_result {
            TransactionValidationOutcome::Valid {
                balance: _,
                state_nonce: _,
                transaction: validated_tx,
                propagate: _,
                ..
            } => {
                // Extract the inner transaction from ValidTransaction
                let inner_tx = validated_tx.into_transaction();
                self.add_transaction_sync(origin, inner_tx)
            }
            TransactionValidationOutcome::Invalid(tx, err) => Err(PoolError {
                hash: *tx.hash(),
                kind: PoolErrorKind::InvalidTransaction(err),
            }),
            TransactionValidationOutcome::Error(hash, err) => Err(PoolError {
                hash,
                kind: PoolErrorKind::Other(err),
            }),
        }
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

            // Update state nonce, but only if the queried value is HIGHER than our cached value
            // Our cached value might be ahead if we've been tracking executions locally
            // @mattse: Does this look correct to you? Do we need some per block maintenance service,
            // which updates the optimistically cached nonces?
            if state_nonce > sender_txs.state_nonce {
                sender_txs.state_nonce = state_nonce;
            }

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
        Box::new(BestTransactions2D::new(Arc::clone(&self.by_sender), None))
    }

    /// Get best transactions with base fee filter
    pub(super) fn best_transactions_with_base_fee(
        &self,
        base_fee: u64,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>> {
        Box::new(BestTransactions2D::new(
            Arc::clone(&self.by_sender),
            Some(base_fee),
        ))
    }

    /// Get all ready transactions (nonce matches state)
    /// Returns transactions that are ready to be executed based on the current nonce state
    fn ready_transactions(&self) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut by_sender = self.by_sender.write();
        let mut ready = vec![];
        let mut to_remove_hashes = Vec::new();

        for (_sender_key, sender_txs) in by_sender.iter_mut() {
            // Remove any transactions with nonce < cached state_nonce (they were executed in previous blocks)
            let nonces_to_remove: Vec<u64> = sender_txs
                .transactions
                .keys()
                .filter(|&&n| n < sender_txs.state_nonce)
                .copied()
                .collect();

            for nonce in nonces_to_remove {
                if let Some(tx) = sender_txs.transactions.remove(&nonce) {
                    to_remove_hashes.push(*tx.hash());
                }
            }

            // Return the transaction only if its nonce matches the expected state_nonce
            // This ensures we don't execute transactions out of order (respecting nonce gaps)
            if let Some(tx) = sender_txs.transactions.get(&sender_txs.state_nonce) {
                ready.push(tx.clone());
            }
        }

        // Clean up removed transaction hashes from indices
        for hash in to_remove_hashes {
            self.by_hash.write().remove(&hash);
            self.tx_origin.write().remove(&hash);
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

        for (sender_key, sender_txs) in by_sender.iter() {
            // Fetch fresh state nonce to determine if transactions are queued
            if let Ok(current_state_nonce) =
                self.get_state_nonce(sender_key.address, sender_key.nonce_key)
            {
                for (nonce, tx) in &sender_txs.transactions {
                    if *nonce != current_state_nonce {
                        queued.push(tx.clone());
                    }
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

/// Best transactions iterator for 2D pool with proper state tracking
///
/// Unlike a simple snapshot-based iterator, this dynamically queries for ready transactions
/// as nonces advance, allowing queued transactions to automatically promote when gaps are filled.
/// This follows Reth's pattern of re-evaluating ready state after each transaction.
struct BestTransactions2D {
    /// Shared access to sender transactions for nonce tracking and querying
    by_sender: Arc<RwLock<HashMap<SenderKey, SenderTransactions>>>,
    /// Base fee filter
    base_fee: Option<u64>,
}

impl BestTransactions2D {
    fn new(
        by_sender: Arc<RwLock<HashMap<SenderKey, SenderTransactions>>>,
        base_fee: Option<u64>,
    ) -> Self {
        Self {
            by_sender,
            base_fee,
        }
    }

    /// Get the next ready transaction across all senders, sorted by gas price
    fn next_ready(&self) -> Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let by_sender = self.by_sender.read();
        let mut candidates = Vec::new();

        // Collect one ready transaction from each sender
        for sender_txs in by_sender.values() {
            if let Some(tx) = sender_txs.transactions.get(&sender_txs.state_nonce) {
                // Apply base fee filter if set
                if let Some(min_fee) = self.base_fee {
                    if tx.max_fee_per_gas() < min_fee as u128 {
                        continue;
                    }
                }
                candidates.push(tx.clone());
            }
        }

        // Return the one with highest gas price
        candidates.into_iter().max_by_key(|tx| tx.max_fee_per_gas())
    }
}

// First implement Iterator
impl Iterator for BestTransactions2D {
    type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Dynamically query for the next ready transaction
        let tx = self.next_ready()?;

        // Optimistically mark as executed to advance nonce tracking
        // This will be rolled back by mark_invalid if the transaction fails
        self.mark_executed_internal(&tx);

        Some(tx)
    }
}

// Then implement BestTransactions
impl BestTransactions for BestTransactions2D {
    fn mark_invalid(&mut self, tx: &Self::Item, _error: InvalidPoolTransactionError) {
        // Transaction failed - rollback the nonce advancement
        if let Some(aa) = tx.transaction.inner().as_aa() {
            let nonce_key = aa.tx().nonce_key;
            if !nonce_key.is_zero() {
                let sender_key = SenderKey {
                    address: tx.sender(),
                    nonce_key,
                };

                if let Some(sender_txs) = self.by_sender.write().get_mut(&sender_key) {
                    // Roll back the nonce to where this transaction should be
                    if sender_txs.state_nonce > tx.nonce() {
                        sender_txs.state_nonce = tx.nonce();
                    }
                }
            }
        }
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

impl BestTransactions2D {
    /// Mark a transaction as executed (advance nonce)
    fn mark_executed_internal(&self, tx: &ValidPoolTransaction<TempoPooledTransaction>) {
        if let Some(aa) = tx.transaction.inner().as_aa() {
            let nonce_key = aa.tx().nonce_key;
            if nonce_key.is_zero() {
                return; // Protocol nonces are handled by the protocol pool
            }

            let sender_key = SenderKey {
                address: tx.sender(),
                nonce_key,
            };

            if let Some(sender_txs) = self.by_sender.write().get_mut(&sender_key) {
                // Advance the expected nonce
                sender_txs.state_nonce = tx.nonce() + 1;
            }
        }
    }
}
