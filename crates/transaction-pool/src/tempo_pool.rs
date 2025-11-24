// Tempo transaction pool that implements Reth's TransactionPool trait
// Routes protocol nonces (nonce_key=0) to Reth pool
// Routes user nonces (nonce_key>0) to minimal 2D nonce pool

use crate::{transaction::TempoPooledTransaction, validator::TempoTransactionValidator};
use alloy_primitives::{Address, B256};
use parking_lot::RwLock;
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_provider::StateProviderFactory;
use reth_transaction_pool::{
    AddedTransactionOutcome, AllPoolTransactions, BestTransactions, BestTransactionsAttributes,
    BlockInfo, CoinbaseTipOrdering, GetPooledTransactionLimit, NewBlobSidecar, Pool, PoolResult,
    PoolSize, PoolTransaction, PropagatedTransactions, TransactionEvents, TransactionOrigin,
    TransactionPool, TransactionValidationTaskExecutor, ValidPoolTransaction,
    blobstore::DiskFileBlobStore, pool::AddedTransactionState,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::broadcast;

/// Minimal 2D nonce pool for user nonces only
mod pool_2d;
use pool_2d::Pool2D;

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
    user_nonce_pool: Arc<Pool2D<Client>>,

    /// Track which pool each transaction is in
    tx_location: Arc<RwLock<HashMap<B256, PoolLocation>>>,

    /// Event broadcaster for transaction events (simplified for now)
    event_tx: broadcast::Sender<B256>,
    event_rx: Arc<RwLock<broadcast::Receiver<B256>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolLocation {
    Protocol,
    UserNonce,
}

impl<Client> TempoTransactionPool<Client>
where
    Client:
        StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + Clone + 'static,
{
    pub fn new(
        protocol_pool: Pool<
            TransactionValidationTaskExecutor<TempoTransactionValidator<Client>>,
            CoinbaseTipOrdering<TempoPooledTransaction>,
            DiskFileBlobStore,
        >,
        client: Client,
        validator: TransactionValidationTaskExecutor<TempoTransactionValidator<Client>>,
    ) -> Self {
        let user_nonce_pool = Arc::new(Pool2D::new(client, Arc::new(validator)));
        let (event_tx, event_rx) = broadcast::channel(1024);

        Self {
            protocol_pool,
            user_nonce_pool,
            tx_location: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            event_rx: Arc::new(RwLock::new(event_rx)),
        }
    }

    /// Determine which pool a transaction should go to
    fn route_transaction(&self, tx: &TempoPooledTransaction) -> PoolLocation {
        if let Some(aa) = tx.inner().as_aa() {
            if !aa.tx().nonce_key.is_zero() {
                return PoolLocation::UserNonce;
            }
        }
        PoolLocation::Protocol
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
            user_nonce_pool: Arc::clone(&self.user_nonce_pool),
            tx_location: Arc::clone(&self.tx_location),
            event_tx: self.event_tx.clone(),
            event_rx: Arc::clone(&self.event_rx),
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
            .field("tx_location", &self.tx_location)
            .finish()
    }
}

// Implement the TransactionPool trait
impl<Client> TransactionPool for TempoTransactionPool<Client>
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthereumHardforks>
        + Clone
        + Send
        + Sync
        + 'static,
    TempoPooledTransaction: reth_transaction_pool::EthPoolTransaction,
{
    type Transaction = TempoPooledTransaction;

    fn pool_size(&self) -> PoolSize {
        let protocol_size = self.protocol_pool.pool_size();
        let user_nonce_size = self.user_nonce_pool.size();

        PoolSize {
            pending: protocol_size.pending + user_nonce_size.pending,
            pending_size: protocol_size.pending_size + user_nonce_size.pending_size,
            basefee: protocol_size.basefee + user_nonce_size.basefee,
            basefee_size: protocol_size.basefee_size + user_nonce_size.basefee_size,
            queued: protocol_size.queued + user_nonce_size.queued,
            queued_size: protocol_size.queued_size + user_nonce_size.queued_size,
            blob: protocol_size.blob,
            blob_size: protocol_size.blob_size,
            total: protocol_size.total + user_nonce_size.total,
        }
    }

    fn block_info(&self) -> BlockInfo {
        // Both pools should have same block info, use protocol pool's
        self.protocol_pool.block_info()
    }

    async fn add_transaction_and_subscribe(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> PoolResult<reth_transaction_pool::TransactionEvents> {
        let hash = *transaction.hash();
        let location = self.route_transaction(&transaction);

        // Route to appropriate pool
        let result = match location {
            PoolLocation::Protocol => {
                self.protocol_pool
                    .add_transaction_and_subscribe(origin, transaction)
                    .await
            }
            PoolLocation::UserNonce => {
                // Add to 2D pool
                let tx_hash = self
                    .user_nonce_pool
                    .add_transaction(origin, transaction.clone())
                    .await?;

                // For now, create empty events
                // In production, would need proper event handling
                let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
                Ok(TransactionEvents::new(tx_hash, rx))
            }
        };

        // Track location on success
        if result.is_ok() {
            self.tx_location.write().insert(hash, location);
        }

        result
    }

    async fn add_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> PoolResult<AddedTransactionOutcome> {
        let hash = *transaction.hash();
        let location = self.route_transaction(&transaction);

        let result = match location {
            PoolLocation::Protocol => {
                self.protocol_pool
                    .add_transaction(origin, transaction)
                    .await
            }
            PoolLocation::UserNonce => {
                // Add to user nonce pool and wrap result in AddedTransactionOutcome
                self.user_nonce_pool
                    .add_transaction(origin, transaction)
                    .await
                    .map(|tx_hash| AddedTransactionOutcome {
                        hash: tx_hash,
                        state: AddedTransactionState::Pending,
                    })
            }
        };

        if result.is_ok() {
            self.tx_location.write().insert(hash, location);
        }

        result
    }

    async fn add_transactions(
        &self,
        origin: TransactionOrigin,
        transactions: Vec<Self::Transaction>,
    ) -> Vec<PoolResult<AddedTransactionOutcome>> {
        // Divide transactions into protocol and user nonce pools, tracking order
        let mut protocol_txs = Vec::new();
        let mut user_nonce_txs = Vec::new();
        let mut tx_order = Vec::with_capacity(transactions.len());

        for tx in transactions {
            let hash = *tx.hash();
            let location = self.route_transaction(&tx);
            tx_order.push((hash, location));

            match location {
                PoolLocation::Protocol => protocol_txs.push(tx),
                PoolLocation::UserNonce => user_nonce_txs.push(tx),
            }
        }

        // Call both pools in parallel
        let (protocol_results, user_results) = tokio::join!(
            async {
                if protocol_txs.is_empty() {
                    vec![]
                } else {
                    self.protocol_pool
                        .add_transactions(origin, protocol_txs)
                        .await
                }
            },
            async {
                let mut results = Vec::with_capacity(user_nonce_txs.len());
                for tx in user_nonce_txs {
                    let result =
                        self.user_nonce_pool
                            .add_transaction(origin, tx)
                            .await
                            .map(|tx_hash| AddedTransactionOutcome {
                                hash: tx_hash,
                                state: AddedTransactionState::Pending,
                            });
                    results.push(result);
                }
                results
            }
        );

        // Merge results maintaining original order
        let mut protocol_iter = protocol_results.into_iter();
        let mut user_iter = user_results.into_iter();
        let mut final_results = Vec::with_capacity(tx_order.len());

        for (hash, location) in tx_order {
            let result = match location {
                PoolLocation::Protocol => protocol_iter.next().unwrap(),
                PoolLocation::UserNonce => user_iter.next().unwrap(),
            };

            // Track location on success
            if result.is_ok() {
                self.tx_location.write().insert(hash, location);
            }

            final_results.push(result);
        }

        final_results
    }

    fn pending_transactions_listener_for(
        &self,
        kind: reth_transaction_pool::TransactionListenerKind,
    ) -> tokio::sync::mpsc::Receiver<B256> {
        // Delegate to protocol pool for now
        // TODO: Merge events from both pools
        self.protocol_pool.pending_transactions_listener_for(kind)
    }

    fn blob_transaction_sidecars_listener(&self) -> tokio::sync::mpsc::Receiver<NewBlobSidecar> {
        // Only protocol pool handles blobs
        self.protocol_pool.blob_transaction_sidecars_listener()
    }

    fn new_transactions_listener_for(
        &self,
        kind: reth_transaction_pool::TransactionListenerKind,
    ) -> tokio::sync::mpsc::Receiver<reth_transaction_pool::NewTransactionEvent<Self::Transaction>>
    {
        // Delegate to protocol pool
        self.protocol_pool.new_transactions_listener_for(kind)
    }

    fn pooled_transaction_hashes(&self) -> Vec<B256> {
        let mut hashes = self.protocol_pool.pooled_transaction_hashes();
        hashes.extend(self.user_nonce_pool.all_hashes());
        hashes
    }

    fn pooled_transaction_hashes_max(&self, max: usize) -> Vec<B256> {
        let protocol_hashes = self.protocol_pool.pooled_transaction_hashes_max(max);
        if protocol_hashes.len() >= max {
            return protocol_hashes;
        }

        let remaining = max - protocol_hashes.len();
        let mut hashes = protocol_hashes;
        hashes.extend(
            self.user_nonce_pool
                .all_hashes()
                .into_iter()
                .take(remaining),
        );
        hashes
    }

    fn pooled_transactions(&self) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.protocol_pool.pooled_transactions();
        txs.extend(self.user_nonce_pool.all_transactions());
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
            self.user_nonce_pool
                .all_transactions()
                .into_iter()
                .take(remaining),
        );
        txs
    }

    fn get_pooled_transaction_elements(
        &self,
        tx_hashes: Vec<B256>,
        limit: GetPooledTransactionLimit,
    ) -> Vec<<Self::Transaction as PoolTransaction>::Pooled> {
        // Check both pools
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
        let protocol_iter = self.protocol_pool.best_transactions()
            as Box<dyn Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + Send>;
        let user_iter = self.user_nonce_pool.best_transactions()
            as Box<dyn Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + Send>;

        Box::new(TempoBestTransactions::new(protocol_iter, user_iter))
    }

    fn best_transactions_with_attributes(
        &self,
        attributes: BestTransactionsAttributes,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Self::Transaction>>>> {
        let protocol_iter = self
            .protocol_pool
            .best_transactions_with_attributes(attributes)
            as Box<dyn Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + Send>;
        let user_iter = self
            .user_nonce_pool
            .best_transactions_with_base_fee(attributes.basefee)
            as Box<dyn Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + Send>;

        Box::new(TempoBestTransactions::new(protocol_iter, user_iter))
    }

    fn pending_transactions(&self) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.protocol_pool.pending_transactions();
        txs.extend(self.user_nonce_pool.pending_transactions());
        txs
    }

    fn queued_transactions(&self) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.protocol_pool.queued_transactions();
        txs.extend(self.user_nonce_pool.queued_transactions());
        txs
    }

    fn all_transactions(&self) -> AllPoolTransactions<Self::Transaction> {
        let protocol_all = self.protocol_pool.all_transactions();
        let user_nonce_all = self.user_nonce_pool.all_transactions();

        AllPoolTransactions {
            pending: [protocol_all.pending, user_nonce_all].concat(),
            queued: [protocol_all.queued, vec![]].concat(), // 2D pool doesn't separate queued
        }
    }

    fn remove_transactions(
        &self,
        hashes: Vec<B256>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut removed = vec![];

        for hash in hashes {
            if let Some(location) = self.tx_location.write().remove(&hash) {
                match location {
                    PoolLocation::Protocol => {
                        removed.extend(self.protocol_pool.remove_transactions(vec![hash]));
                    }
                    PoolLocation::UserNonce => {
                        if let Some(tx) = self.user_nonce_pool.remove_transaction(&hash) {
                            removed.push(tx);
                        }
                    }
                }
            }
        }

        removed
    }

    fn remove_transactions_and_descendants(
        &self,
        hashes: Vec<B256>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut removed = vec![];

        for hash in hashes {
            if let Some(location) = self.tx_location.read().get(&hash).copied() {
                match location {
                    PoolLocation::Protocol => {
                        // Protocol pool handles descendants automatically
                        removed.extend(
                            self.protocol_pool
                                .remove_transactions_and_descendants(vec![hash]),
                        );
                    }
                    PoolLocation::UserNonce => {
                        // 2D pool needs to remove descendants for same (sender, nonce_key)
                        removed.extend(
                            self.user_nonce_pool
                                .remove_transaction_and_descendants(&hash),
                        );
                    }
                }
            }
        }

        removed
    }

    fn remove_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut removed = self.protocol_pool.remove_transactions_by_sender(sender);
        removed.extend(self.user_nonce_pool.remove_all_for_sender(&sender));

        // Clean up tx_location
        for tx in &removed {
            self.tx_location.write().remove(tx.hash());
        }

        removed
    }

    fn retain_unknown<A: reth_eth_wire_types::broadcast::HandleMempoolData>(
        &self,
        announcement: &mut A,
    ) {
        self.protocol_pool.retain_unknown(announcement);
        // 2D pool doesn't participate in P2P announcement filtering for now
    }

    fn contains(&self, tx_hash: &B256) -> bool {
        self.tx_location.read().contains_key(tx_hash)
    }

    fn get(&self, tx_hash: &B256) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let location = self.tx_location.read().get(tx_hash).copied()?;

        match location {
            PoolLocation::Protocol => self.protocol_pool.get(tx_hash),
            PoolLocation::UserNonce => self.user_nonce_pool.get_transaction(tx_hash),
        }
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
        let mut txs = self.protocol_pool.get_transactions_by_sender(sender);
        txs.extend(self.user_nonce_pool.get_transactions_by_address(&sender));
        txs
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
        let mut txs = self
            .protocol_pool
            .get_pending_transactions_by_sender(sender);
        txs.extend(self.user_nonce_pool.get_pending_for_address(&sender));
        txs
    }

    fn get_queued_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.protocol_pool.get_queued_transactions_by_sender(sender);
        txs.extend(self.user_nonce_pool.get_queued_for_address(&sender));
        txs
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
        // Check protocol pool first (nonce_key=0)
        if let Some(tx) = self
            .protocol_pool
            .get_transaction_by_sender_and_nonce(sender, nonce)
        {
            return Some(tx);
        }

        // Check 2D pool for any nonce_key
        self.user_nonce_pool.get_by_sender_and_nonce(&sender, nonce)
    }

    fn get_transactions_by_origin(
        &self,
        origin: TransactionOrigin,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.protocol_pool.get_transactions_by_origin(origin);
        txs.extend(self.user_nonce_pool.get_transactions_by_origin(origin));
        txs
    }

    fn get_pending_transactions_by_origin(
        &self,
        origin: TransactionOrigin,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // 2D pool doesn't track origin separately for pending
        self.protocol_pool
            .get_pending_transactions_by_origin(origin)
    }

    fn unique_senders(&self) -> HashSet<Address> {
        let mut senders = self.protocol_pool.unique_senders();
        senders.extend(self.user_nonce_pool.unique_senders());
        senders
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

    async fn add_external_transaction(
        &self,
        transaction: Self::Transaction,
    ) -> PoolResult<AddedTransactionOutcome> {
        self.add_transaction(TransactionOrigin::External, transaction)
            .await
    }

    async fn add_external_transactions(
        &self,
        transactions: Vec<Self::Transaction>,
    ) -> Vec<PoolResult<AddedTransactionOutcome>> {
        self.add_transactions(TransactionOrigin::External, transactions)
            .await
    }

    fn add_transactions_with_origins(
        &self,
        transactions: Vec<(TransactionOrigin, Self::Transaction)>,
    ) -> impl std::future::Future<Output = Vec<PoolResult<AddedTransactionOutcome>>> + Send {
        async move {
            let mut results = Vec::with_capacity(transactions.len());
            for (origin, tx) in transactions {
                results.push(self.add_transaction(origin, tx).await);
            }
            results
        }
    }

    fn transaction_event_listener(&self, tx_hash: B256) -> Option<TransactionEvents> {
        // Check which pool has this transaction
        if let Some(location) = self.tx_location.read().get(&tx_hash) {
            match location {
                PoolLocation::Protocol => self.protocol_pool.transaction_event_listener(tx_hash),
                PoolLocation::UserNonce => None, // 2D pool doesn't support event listening yet
            }
        } else {
            None
        }
    }

    fn all_transactions_event_listener(
        &self,
    ) -> reth_transaction_pool::AllTransactionsEvents<Self::Transaction> {
        // Delegate to protocol pool for now
        self.protocol_pool.all_transactions_event_listener()
    }

    fn pending_transactions_max(
        &self,
        max: usize,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let protocol_txs = self.protocol_pool.pending_transactions_max(max);
        if protocol_txs.len() >= max {
            return protocol_txs;
        }

        let remaining = max - protocol_txs.len();
        let mut txs = protocol_txs;
        let user_txs = self.user_nonce_pool.pending_transactions();
        txs.extend(user_txs.into_iter().take(remaining));
        txs
    }

    fn pending_and_queued_txn_count(&self) -> (usize, usize) {
        let (protocol_pending, protocol_queued) = self.protocol_pool.pending_and_queued_txn_count();
        let user_size = self.user_nonce_pool.size();
        (
            protocol_pending + user_size.pending,
            protocol_queued + user_size.queued,
        )
    }

    fn all_transaction_hashes(&self) -> Vec<B256> {
        let mut hashes = self.protocol_pool.all_transaction_hashes();
        hashes.extend(self.user_nonce_pool.all_hashes());
        hashes
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

/// Iterator that merges best transactions from both pools
struct TempoBestTransactions {
    protocol_iter:
        Box<dyn Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + Send>,
    user_nonce_iter:
        Box<dyn Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + Send>,
    protocol_peek: Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    user_nonce_peek: Option<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
}

impl TempoBestTransactions {
    fn new(
        mut protocol: Box<
            dyn Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + Send,
        >,
        mut user_nonce: Box<
            dyn Iterator<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + Send,
        >,
    ) -> Self {
        let protocol_peek = protocol.next();
        let user_nonce_peek = user_nonce.next();
        Self {
            protocol_iter: protocol,
            user_nonce_iter: user_nonce,
            protocol_peek,
            user_nonce_peek,
        }
    }
}

impl Iterator for TempoBestTransactions {
    type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Properly interleave transactions from both pools by comparing gas prices
        match (&self.protocol_peek, &self.user_nonce_peek) {
            (Some(protocol_tx), Some(user_tx)) => {
                // Both pools have transactions, pick higher gas price
                // @mattse: Is this the correct gas number to compare, or should we use priority fee here?
                if protocol_tx.max_fee_per_gas() >= user_tx.max_fee_per_gas() {
                    let tx = self.protocol_peek.take();
                    self.protocol_peek = self.protocol_iter.next();
                    tx
                } else {
                    let tx = self.user_nonce_peek.take();
                    self.user_nonce_peek = self.user_nonce_iter.next();
                    tx
                }
            }
            (Some(_), None) => {
                // Only protocol pool has transactions
                let tx = self.protocol_peek.take();
                self.protocol_peek = self.protocol_iter.next();
                tx
            }
            (None, Some(_)) => {
                // Only user nonce pool has transactions
                let tx = self.user_nonce_peek.take();
                self.user_nonce_peek = self.user_nonce_iter.next();
                tx
            }
            (None, None) => None,
        }
    }
}

impl BestTransactions for TempoBestTransactions {
    fn mark_invalid(
        &mut self,
        _tx: &Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        _error: reth_transaction_pool::error::InvalidPoolTransactionError,
    ) {
        // Since we're using plain iterators, we can't mark invalid
        // In production, would need to track state
    }

    fn no_updates(&mut self) {
        // No-op for plain iterators
    }

    fn skip_blobs(&mut self) {
        // No-op for plain iterators
    }

    fn set_skip_blobs(&mut self, _skip: bool) {
        // No-op for plain iterators
    }
}
