// Tempo transaction pool that implements Reth's TransactionPool trait
// Routes protocol nonces (nonce_key=0) to Reth pool
// Routes user nonces (nonce_key>0) to minimal 2D nonce pool

use crate::{
    pool_2d::{AA2dNonceKeys, AASenderId, Pool2D},
    transaction::TempoPooledTransaction,
    validator::TempoTransactionValidator,
};
use alloy_consensus::Transaction;
use alloy_primitives::{Address, B256};
use parking_lot::RwLock;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_eth_wire_types::HandleMempoolData;
use reth_provider::StateProviderFactory;
use reth_transaction_pool::{
    AddedTransactionOutcome, AllPoolTransactions, BestTransactions, BestTransactionsAttributes,
    BlockInfo, CoinbaseTipOrdering, GetPooledTransactionLimit, NewBlobSidecar, Pool, PoolResult,
    PoolSize, PoolTransaction, PropagatedTransactions, TransactionEvents, TransactionOrigin,
    TransactionPool, TransactionValidationOutcome, TransactionValidationTaskExecutor,
    TransactionValidator, ValidPoolTransaction, blobstore::DiskFileBlobStore,
    identifier::TransactionId,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Instant,
};

/// Tempo transaction pool that routes based on nonce_key
pub struct TempoTransactionPool<Client>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + 'static,
{
    /// Reth pool for protocol nonces (nonce_key = 0)
    protocol_pool: Pool<
        TransactionValidationTaskExecutor<TempoTransactionValidator<Client>>,
        CoinbaseTipOrdering<TempoPooledTransaction>,
        DiskFileBlobStore,
    >,

    /// Minimal pool for 2D nonces (nonce_key > 0)
    aa_2d_pool: Arc<RwLock<Pool2D>>,
}

impl<Client> TempoTransactionPool<Client>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + 'static,
{
    pub fn new(
        protocol_pool: Pool<
            TransactionValidationTaskExecutor<TempoTransactionValidator<Client>>,
            CoinbaseTipOrdering<TempoPooledTransaction>,
            DiskFileBlobStore,
        >,
    ) -> Self {
        Self {
            protocol_pool,
            aa_2d_pool: Arc::new(RwLock::new(Default::default())),
        }
    }

    /// Obtains a clone of the shared [`AA2dNonceKeys`].
    pub fn aa_2d_nonce_keys(&self) -> AA2dNonceKeys {
        self.aa_2d_pool.read().aa_2d_nonce_keys().clone()
    }

    /// Updates the 2d nonce pool with the given state changes.
    pub(crate) fn on_aa_2d_nonce_changes(&self, on_chain_ids: HashMap<AASenderId, u64>) {
        if on_chain_ids.is_empty() {
            return;
        }
        let (_promoted, _mined) = self.aa_2d_pool.write().on_aa_2d_nonce_changes(on_chain_ids);

        // TODO: notify in protocol pool
    }

    fn add_validated_transactions(
        &self,
        _origin: TransactionOrigin,
        _transaction: Vec<TransactionValidationOutcome<TempoPooledTransaction>>,
    ) -> Vec<PoolResult<AddedTransactionOutcome>> {
        // if transaction.iter().any(|outcome| outcome.) {
        //
        // }

        todo!()
    }

    fn add_validated_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: TransactionValidationOutcome<TempoPooledTransaction>,
    ) -> PoolResult<AddedTransactionOutcome> {
        match transaction {
            TransactionValidationOutcome::Valid {
                balance,
                state_nonce,
                bytecode_hash,
                transaction,
                propagate,
                authorities,
            } => {
                if transaction.transaction().is_aa_2d() {
                    let transaction = transaction.into_transaction();
                    let sender_id = self
                        .protocol_pool
                        .inner()
                        .get_sender_id(transaction.sender());
                    let transaction_id = TransactionId::new(sender_id, transaction.nonce());
                    let tx = ValidPoolTransaction {
                        transaction,
                        transaction_id,
                        propagate,
                        timestamp: Instant::now(),
                        origin,
                        authority_ids: authorities
                            .map(|auths| self.protocol_pool.inner().get_sender_ids(auths)),
                    };
                    let added = self.aa_2d_pool.write().add_transaction(Arc::new(tx))?;
                    let hash = *added.hash();
                    if let Some(pending) = added.as_pending() {
                        self.protocol_pool
                            .inner()
                            .on_new_pending_transaction(pending);
                    }

                    let state = added.transaction_state();
                    // notify regular event listeners from the protocol pool
                    self.protocol_pool.inner().notify_event_listeners(&added);
                    self.protocol_pool
                        .inner()
                        .on_new_transaction(added.into_new_transaction_event());

                    Ok(AddedTransactionOutcome { hash, state })
                } else {
                    self.protocol_pool
                        .inner()
                        .add_transactions(
                            origin,
                            std::iter::once(TransactionValidationOutcome::Valid {
                                balance,
                                state_nonce,
                                bytecode_hash,
                                transaction,
                                propagate,
                                authorities,
                            }),
                        )
                        .pop()
                        .unwrap()
                }
            }
            invalid => {
                // this forwards for event listener updates
                self.protocol_pool
                    .inner()
                    .add_transactions(origin, Some(invalid))
                    .pop()
                    .unwrap()
            }
        }
    }
}

// Manual Clone implementation
impl<Client> Clone for TempoTransactionPool<Client>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + 'static,
{
    fn clone(&self) -> Self {
        Self {
            protocol_pool: self.protocol_pool.clone(),
            aa_2d_pool: Arc::clone(&self.aa_2d_pool),
        }
    }
}

// Manual Debug implementation
impl<Client> std::fmt::Debug for TempoTransactionPool<Client>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempoTransactionPool")
            .field("protocol_pool", &"Pool<...>")
            .field("user_nonce_pool", &"Pool2D<...>")
            .finish()
    }
}

// Implement the TransactionPool trait
impl<Client> TransactionPool for TempoTransactionPool<Client>
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + Send
        + Sync
        + 'static,
    TempoPooledTransaction: reth_transaction_pool::EthPoolTransaction,
{
    type Transaction = TempoPooledTransaction;

    fn pool_size(&self) -> PoolSize {
        // TODO: update 2d size

        self.protocol_pool.pool_size()
    }

    fn block_info(&self) -> BlockInfo {
        self.protocol_pool.block_info()
    }

    async fn add_transaction_and_subscribe(
        &self,
        _origin: TransactionOrigin,
        _transaction: Self::Transaction,
    ) -> PoolResult<reth_transaction_pool::TransactionEvents> {
        // let tx = self
        //     .protocol_pool
        //     .validator()
        //     .validate(origin, transaction)
        //     .await;
        todo!()
    }

    async fn add_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> PoolResult<AddedTransactionOutcome> {
        let tx = self
            .protocol_pool
            .validator()
            .validate_transaction(origin, transaction)
            .await;
        self.add_validated_transaction(origin, tx)
    }

    async fn add_transactions(
        &self,
        origin: TransactionOrigin,
        transactions: Vec<Self::Transaction>,
    ) -> Vec<PoolResult<AddedTransactionOutcome>> {
        if transactions.is_empty() {
            return Vec::new();
        }
        let validated = self
            .protocol_pool
            .validator()
            .validate_transactions_with_origin(origin, transactions)
            .await;

        self.add_validated_transactions(origin, validated)
    }

    fn transaction_event_listener(&self, tx_hash: B256) -> Option<TransactionEvents> {
        self.protocol_pool.transaction_event_listener(tx_hash)
    }

    fn all_transactions_event_listener(
        &self,
    ) -> reth_transaction_pool::AllTransactionsEvents<Self::Transaction> {
        self.protocol_pool.all_transactions_event_listener()
    }

    fn pending_transactions_listener_for(
        &self,
        kind: reth_transaction_pool::TransactionListenerKind,
    ) -> tokio::sync::mpsc::Receiver<B256> {
        self.protocol_pool.pending_transactions_listener_for(kind)
    }

    fn blob_transaction_sidecars_listener(&self) -> tokio::sync::mpsc::Receiver<NewBlobSidecar> {
        self.protocol_pool.blob_transaction_sidecars_listener()
    }

    fn new_transactions_listener_for(
        &self,
        kind: reth_transaction_pool::TransactionListenerKind,
    ) -> tokio::sync::mpsc::Receiver<reth_transaction_pool::NewTransactionEvent<Self::Transaction>>
    {
        self.protocol_pool.new_transactions_listener_for(kind)
    }

    fn pooled_transaction_hashes(&self) -> Vec<B256> {
        let mut hashes = self.protocol_pool.pooled_transaction_hashes();
        hashes.extend(self.aa_2d_pool.read().pooled_transactions_hashes_iter());
        hashes
    }

    fn pooled_transaction_hashes_max(&self, max: usize) -> Vec<B256> {
        let protocol_hashes = self.protocol_pool.pooled_transaction_hashes_max(max);
        if protocol_hashes.len() >= max {
            return protocol_hashes;
        }
        // TODO: this should not starve the 2dpool
        let remaining = max - protocol_hashes.len();
        let mut hashes = protocol_hashes;
        hashes.extend(
            self.aa_2d_pool
                .read()
                .pooled_transactions_hashes_iter()
                .take(remaining),
        );
        hashes
    }

    fn pooled_transactions(&self) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.protocol_pool.pooled_transactions();
        txs.extend(self.aa_2d_pool.read().pooled_transactions_iter());
        txs
    }

    fn pooled_transactions_max(
        &self,
        max: usize,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let protocol_txs = self.protocol_pool.pooled_transactions_max(max);
        if protocol_txs.len() >= max {
            return protocol_txs;
        }

        let remaining = max - protocol_txs.len();
        let mut txs = protocol_txs;
        txs.extend(
            self.aa_2d_pool
                .read()
                .pooled_transactions_iter()
                .take(remaining),
        );
        txs
    }

    fn get_pooled_transaction_elements(
        &self,
        tx_hashes: Vec<B256>,
        limit: GetPooledTransactionLimit,
    ) -> Vec<<Self::Transaction as PoolTransaction>::Pooled> {
        // TODO: Check both pools
        self.protocol_pool
            .get_pooled_transaction_elements(tx_hashes, limit)
    }

    fn get_pooled_transaction_element(
        &self,
        tx_hash: B256,
    ) -> Option<reth_primitives_traits::Recovered<<Self::Transaction as PoolTransaction>::Pooled>>
    {
        // For now, delegate to protocol pool
        // TODO: Check both pools
        self.protocol_pool.get_pooled_transaction_element(tx_hash)
    }

    fn best_transactions(
        &self,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Self::Transaction>>>> {
        todo!()
    }

    fn best_transactions_with_attributes(
        &self,
        _attributes: BestTransactionsAttributes,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Self::Transaction>>>> {
        todo!()
    }

    fn pending_transactions(&self) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // TODO: Check both pools

        self.protocol_pool.pending_transactions()
    }

    fn pending_transactions_max(
        &self,
        _max: usize,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        todo!()
        // let protocol_txs = self.protocol_pool.pending_transactions_max(max);
        // if protocol_txs.len() >= max {
        //     return protocol_txs;
        // }
        //
        // let remaining = max - protocol_txs.len();
        // let mut txs = protocol_txs;
        // let user_txs = self.aa_2d_pool.pending_transactions();
        // txs.extend(user_txs.into_iter().take(remaining));
        // txs
    }

    fn queued_transactions(&self) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        todo!()
        // let mut txs = self.protocol_pool.queued_transactions();
        // txs.extend(self.aa_2d_pool.queued_transactions());
        // txs
    }

    fn pending_and_queued_txn_count(&self) -> (usize, usize) {
        todo!()
        // let (protocol_pending, protocol_queued) = self.protocol_pool.pending_and_queued_txn_count();
        // let user_size = self.aa_2d_pool.size();
        // (
        //     protocol_pending + user_size.pending,
        //     protocol_queued + user_size.queued,
        // )
    }

    fn all_transactions(&self) -> AllPoolTransactions<Self::Transaction> {
        todo!()
        // let protocol_all = self.protocol_pool.all_transactions();
        // let user_nonce_all = self.aa_2d_pool.all_transactions();
        //
        // AllPoolTransactions {
        //     pending: [protocol_all.pending, user_nonce_all].concat(),
        //     queued: [protocol_all.queued, vec![]].concat(), // 2D pool doesn't separate queued
        // }
    }

    fn all_transaction_hashes(&self) -> Vec<B256> {
        self.protocol_pool.all_transaction_hashes()
    }

    fn remove_transactions(
        &self,
        _hashes: Vec<B256>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let removed = vec![];

        removed
    }

    fn remove_transactions_and_descendants(
        &self,
        _hashes: Vec<B256>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let removed = vec![];

        removed
    }

    fn remove_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // removed.extend(self.aa_2d_pool.remove_all_for_sender(&sender));
        //
        // // Clean up tx_location
        // for tx in &removed {
        //     self.tx_location.write().remove(tx.hash());
        // }

        self.protocol_pool.remove_transactions_by_sender(sender)
    }

    fn retain_unknown<A: HandleMempoolData>(&self, _announcement: &mut A) {
        // self.protocol_pool.retain_unknown(announcement);
    }

    fn contains(&self, tx_hash: &B256) -> bool {
        self.protocol_pool.contains(tx_hash) || self.aa_2d_pool.read().contains(tx_hash)
    }

    fn get(&self, _tx_hash: &B256) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>> {
        todo!()
    }

    fn get_all(&self, txs: Vec<B256>) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut result = vec![];
        for hash in txs {
            if let Some(tx) = self.get(&hash) {
                result.push(tx);
            }
        }
        result
    }

    fn on_propagated(&self, txs: PropagatedTransactions) {
        // Only protocol pool needs propagation info
        self.protocol_pool.on_propagated(txs);
    }

    fn get_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // txs.extend(self.aa_2d_pool.get_transactions_by_address(&sender));
        self.protocol_pool.get_transactions_by_sender(sender)
    }

    fn get_pending_transactions_with_predicate(
        &self,
        predicate: impl FnMut(&ValidPoolTransaction<Self::Transaction>) -> bool,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // This is complex to merge - delegate to protocol pool for now
        self.protocol_pool
            .get_pending_transactions_with_predicate(predicate)
    }

    fn get_pending_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // txs.extend(self.aa_2d_pool.get_pending_for_address(&sender));
        self.protocol_pool
            .get_pending_transactions_by_sender(sender)
    }

    fn get_queued_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        self.protocol_pool.get_queued_transactions_by_sender(sender)
    }

    fn get_highest_transaction_by_sender(
        &self,
        sender: Address,
    ) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // With 2D nonces, there's no concept of a single "highest" nonce across all nonce_keys
        // Return the highest protocol nonce (nonce_key=0) only
        self.protocol_pool.get_highest_transaction_by_sender(sender)
    }

    fn get_highest_consecutive_transaction_by_sender(
        &self,
        sender: Address,
        on_chain_nonce: u64,
    ) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // This is complex with 2D nonces - delegate to protocol pool
        self.protocol_pool
            .get_highest_consecutive_transaction_by_sender(sender, on_chain_nonce)
    }

    fn get_transaction_by_sender_and_nonce(
        &self,
        sender: Address,
        nonce: u64,
    ) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // Only returns transactions from protocol pool (nonce_key=0)
        self.protocol_pool
            .get_transaction_by_sender_and_nonce(sender, nonce)
    }

    fn get_transactions_by_origin(
        &self,
        origin: TransactionOrigin,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // txs.extend(self.aa_2d_pool.get_transactions_by_origin(origin));
        self.protocol_pool.get_transactions_by_origin(origin)
    }

    fn get_pending_transactions_by_origin(
        &self,
        origin: TransactionOrigin,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        self.protocol_pool
            .get_pending_transactions_by_origin(origin)
    }

    fn unique_senders(&self) -> HashSet<Address> {
        // senders.extend(self.aa_2d_pool.unique_senders());
        self.protocol_pool.unique_senders()
    }

    fn get_blob(
        &self,
        tx_hash: B256,
    ) -> Result<
        Option<Arc<alloy_eips::eip7594::BlobTransactionSidecarVariant>>,
        reth_transaction_pool::blobstore::BlobStoreError,
    > {
        self.protocol_pool.get_blob(tx_hash)
    }

    fn get_all_blobs(
        &self,
        tx_hashes: Vec<B256>,
    ) -> Result<
        Vec<(
            B256,
            Arc<alloy_eips::eip7594::BlobTransactionSidecarVariant>,
        )>,
        reth_transaction_pool::blobstore::BlobStoreError,
    > {
        self.protocol_pool.get_all_blobs(tx_hashes)
    }

    fn get_all_blobs_exact(
        &self,
        tx_hashes: Vec<B256>,
    ) -> Result<
        Vec<Arc<alloy_eips::eip7594::BlobTransactionSidecarVariant>>,
        reth_transaction_pool::blobstore::BlobStoreError,
    > {
        self.protocol_pool.get_all_blobs_exact(tx_hashes)
    }

    fn get_blobs_for_versioned_hashes_v1(
        &self,
        versioned_hashes: &[B256],
    ) -> Result<
        Vec<Option<alloy_eips::eip4844::BlobAndProofV1>>,
        reth_transaction_pool::blobstore::BlobStoreError,
    > {
        self.protocol_pool
            .get_blobs_for_versioned_hashes_v1(versioned_hashes)
    }

    fn get_blobs_for_versioned_hashes_v2(
        &self,
        versioned_hashes: &[B256],
    ) -> Result<
        Option<Vec<alloy_eips::eip4844::BlobAndProofV2>>,
        reth_transaction_pool::blobstore::BlobStoreError,
    > {
        self.protocol_pool
            .get_blobs_for_versioned_hashes_v2(versioned_hashes)
    }
}
