// Tempo transaction pool that implements Reth's TransactionPool trait
// Routes protocol nonces (nonce_key=0) to Reth pool
// Routes user nonces (nonce_key>0) to minimal 2D nonce pool

use crate::{
    amm::AmmLiquidityCache,
    best::MergeBestTransactions,
    invalidation::{Invalidations, Reason, RecentBlocks, Verdict},
    ordering::TempoTipOrdering,
    transaction::TempoPooledTransaction,
    tt_2d_pool::AA2dPool,
    validator::{ConfigureTempoPoolEvm, TempoTransactionValidator},
};
use alloy_consensus::Transaction;
use alloy_primitives::{
    Address, B256, TxHash, U256,
    map::{AddressMap, AddressSet, HashMap},
};
use parking_lot::RwLock;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_eth_wire_types::HandleMempoolData;
use reth_provider::{ChangedAccount, StateProviderFactory};
use reth_transaction_pool::{
    AddedTransactionOutcome, AllPoolTransactions, BestTransactions, BestTransactionsAttributes,
    BlockInfo, CanonicalStateUpdate, GetPooledTransactionLimit, NewBlobSidecar, Pool, PoolResult,
    PoolSize, PoolTransaction, PropagatedTransactions, TransactionEvents, TransactionOrigin,
    TransactionPool, TransactionPoolExt, TransactionValidationOutcome,
    TransactionValidationTaskExecutor, TransactionValidator, ValidPoolTransaction,
    blobstore::InMemoryBlobStore,
    error::{PoolError, PoolErrorKind},
    identifier::TransactionId,
};
use reth_trie_common::bundle_state::BundleAccount;
use std::{sync::Arc, time::Instant};
use tempo_chainspec::hardfork::TempoHardforks;
use tempo_evm::TempoEvmConfig;
use tempo_primitives::{Block, TempoHeader};
use tracing::{debug, trace};

/// Transaction pool operations for Tempo nonce lanes.
pub trait TempoTransactionPoolExt: TransactionPool {
    /// Returns pending transactions in the address's sequential 2D nonce lane.
    fn get_pending_transactions_by_address_and_nonce_key(
        &self,
        address: Address,
        nonce_key: U256,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>>;
}

/// Tempo transaction pool that routes based on nonce_key
pub struct TempoTransactionPool<Client, EvmConfig = TempoEvmConfig> {
    /// Vanilla pool for all standard transactions and AA transactions with regular nonce.
    protocol_pool: Pool<
        TransactionValidationTaskExecutor<TempoTransactionValidator<Client, EvmConfig>>,
        TempoTipOrdering<TempoPooledTransaction>,
        InMemoryBlobStore,
    >,
    /// Minimal pool for 2D nonces (nonce_key > 0)
    aa_2d_pool: Arc<RwLock<AA2dPool>>,
    /// Changes of the most recent blocks, for payload builds that start before maintenance
    /// processes them.
    recent_blocks: Arc<RecentBlocks>,
}

impl<Client, EvmConfig> TempoTransactionPool<Client, EvmConfig>
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + 'static,
    EvmConfig: ConfigureTempoPoolEvm,
{
    pub fn new(
        protocol_pool: Pool<
            TransactionValidationTaskExecutor<TempoTransactionValidator<Client, EvmConfig>>,
            TempoTipOrdering<TempoPooledTransaction>,
            InMemoryBlobStore,
        >,
        mut aa_2d_pool: AA2dPool,
    ) -> Self {
        aa_2d_pool.set_base_fee(protocol_pool.inner().block_info().pending_basefee);
        Self {
            protocol_pool,
            aa_2d_pool: Arc::new(RwLock::new(aa_2d_pool)),
            recent_blocks: Arc::default(),
        }
    }
}
impl<Client, EvmConfig> TempoTransactionPool<Client, EvmConfig>
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + 'static,
    EvmConfig: ConfigureTempoPoolEvm,
{
    /// Obtains a clone of the shared [`AmmLiquidityCache`].
    pub fn amm_liquidity_cache(&self) -> AmmLiquidityCache {
        self.protocol_pool
            .validator()
            .validator()
            .amm_liquidity_cache()
    }

    /// Returns the configured client
    pub fn client(&self) -> &Client {
        self.protocol_pool.validator().validator().client()
    }

    /// Updates the 2d nonce pool with the given state changes.
    ///
    /// Returns mined AA transactions.
    pub(crate) fn notify_aa_pool_on_state_updates(
        &self,
        state: &AddressMap<BundleAccount>,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let (promoted, mined, discarded) = self.aa_2d_pool.write().on_state_updates(state);
        // Note: mined transactions are notified via the vanilla pool updates
        self.protocol_pool
            .inner()
            .notify_on_transaction_updates(promoted, discarded);
        mined
    }

    /// Returns the changes of the most recent blocks, which maintenance publishes before
    /// processing them.
    pub fn recent_blocks(&self) -> &RecentBlocks {
        &self.recent_blocks
    }

    /// Takes out the transactions that on-chain changes invalidated or may have invalidated.
    ///
    /// Runs `Invalidations::verdict` on every pooled transaction: those it finds invalid are
    /// evicted, and those it finds in need of revalidation are removed for the caller to validate
    /// and re-add.
    pub fn evict_invalidated_transactions(
        &self,
        invalidations: &Invalidations,
    ) -> InvalidatedTransactions {
        let all_txs = self.all_transactions();
        self.evict_invalidated_transactions_from(invalidations, all_txs.iter(), None)
    }

    /// See [`Self::evict_invalidated_transactions`]; also evicts transactions that expire by
    /// `expiry_cutoff`.
    pub(crate) fn evict_invalidated_transactions_from<'a>(
        &self,
        invalidations: &Invalidations,
        transactions: impl IntoIterator<Item = &'a Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        expiry_cutoff: Option<u64>,
    ) -> InvalidatedTransactions {
        // Re-check liquidity for all pooled txs when an active validator changes token or a
        // reserve decreased. Leverages the per-tx `has_enough_liquidity` check, which passes if
        // ANY validator pair has enough liquidity, matching admission and preventing
        // mass-eviction of valid txs.
        let amm_cache = self.amm_liquidity_cache();
        let has_active_validator_token_changes =
            !invalidations.events.validator_token_changes.is_empty() && {
                let active_new_tokens: Vec<_> = invalidations
                    .events
                    .validator_token_changes
                    .iter()
                    .filter(|(validator, _)| amm_cache.is_active_validator(validator))
                    .filter(|(_, new_token)| !amm_cache.is_active_validator_token(new_token))
                    .map(|(_, &new_token)| new_token)
                    .collect();
                amm_cache.track_tokens(&active_new_tokens)
            };

        // The cache follows reserves through the state diff; it reads state only for pairs it
        // has not seen, such as a new validator token's.
        let check_liquidity =
            has_active_validator_token_changes || invalidations.fee_liquidity_may_have_decreased();
        let provider = check_liquidity
            .then(|| self.client().latest().ok())
            .flatten();
        let mut has_fee_liquidity = |_: &TempoPooledTransaction, token, fee| {
            let Some(provider) = provider.as_ref() else {
                return true;
            };
            // Errors leave the transaction to execution.
            amm_cache
                .has_enough_liquidity(token, fee, provider)
                .unwrap_or(true)
        };

        let mut evict = Vec::new();
        let mut revalidate = Vec::new();
        let mut expired = 0usize;
        for tx in transactions {
            if expiry_cutoff.is_some_and(|cutoff| tx.transaction.is_expired_by(cutoff)) {
                evict.push(*tx.hash());
                expired += 1;
                continue;
            }
            // Reth's canonical update already handles protocol nonces.
            match invalidations.verdict(&tx.transaction, &mut has_fee_liquidity) {
                Verdict::Valid | Verdict::StaleNonce => {}
                Verdict::Invalid(reason) => {
                    trace!(target: "txpool", tx = %tx.hash(), reason = reason.as_str(), "Evicting invalidated transaction");
                    evict.push(*tx.hash());
                }
                Verdict::Revalidate(reason) => revalidate.push((*tx.hash(), reason)),
            }
        }

        if !evict.is_empty() || !revalidate.is_empty() {
            debug!(
                target: "txpool",
                evicted = evict.len(),
                expired,
                revalidate = revalidate.len(),
                "Taking out invalidated or expired transactions"
            );
        }
        let reasons: HashMap<TxHash, Reason> = revalidate.iter().copied().collect();
        InvalidatedTransactions {
            evicted: self.remove_transactions(evict),
            revalidate: self
                .remove_transactions(revalidate.into_iter().map(|(hash, _)| hash).collect())
                .into_iter()
                .map(|tx| {
                    let reason = reasons[tx.hash()];
                    (tx, reason)
                })
                .collect(),
        }
    }

    /// Adds a validated transaction to the subpool derived from its type and nonce key.
    ///
    /// [`TempoPooledTransaction::is_aa_2d`] routes AA transactions with non-zero
    /// nonce keys, including expiring nonces, to the 2D nonce pool. Everything else
    /// stays in the protocol pool.
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

                    // Get the active Tempo hardfork for expiring nonce handling
                    let hardfork = self.protocol_pool.validator().validator().active_hardfork();

                    let tx = Arc::new(tx);
                    let added =
                        self.aa_2d_pool
                            .write()
                            .add_transaction(tx, state_nonce, hardfork)?;
                    let hash = *added.hash();
                    if let Some(pending) = added.as_pending() {
                        if pending.discarded.iter().any(|tx| *tx.hash() == hash) {
                            return Err(PoolError::new(hash, PoolErrorKind::DiscardedOnInsert));
                        }
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
impl<Client, EvmConfig> Clone for TempoTransactionPool<Client, EvmConfig> {
    fn clone(&self) -> Self {
        Self {
            protocol_pool: self.protocol_pool.clone(),
            aa_2d_pool: Arc::clone(&self.aa_2d_pool),
            recent_blocks: Arc::clone(&self.recent_blocks),
        }
    }
}

// Manual Debug implementation
impl<Client, EvmConfig> std::fmt::Debug for TempoTransactionPool<Client, EvmConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempoTransactionPool")
            .field("protocol_pool", &"Pool<...>")
            .field("aa_2d_nonce_pool", &"AA2dPool<...>")
            .finish_non_exhaustive()
    }
}

// Implement the TransactionPool trait
impl<Client, EvmConfig> TransactionPool for TempoTransactionPool<Client, EvmConfig>
where
    EvmConfig: ConfigureTempoPoolEvm,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + 'static,
    TempoPooledTransaction: reth_transaction_pool::EthPoolTransaction,
{
    type Transaction = TempoPooledTransaction;

    fn pool_size(&self) -> PoolSize {
        let mut size = self.protocol_pool.pool_size();
        let aa_2d_pool = self.aa_2d_pool.read();
        let (pending, queued) = aa_2d_pool.pending_and_queued_txn_count();
        let (pending_size, queued_size) = aa_2d_pool.pending_and_queued_txn_size();
        size.pending += pending;
        size.pending_size += pending_size;
        size.queued += queued;
        size.queued_size += queued_size;
        size.total += pending + queued;
        size
    }

    fn block_info(&self) -> BlockInfo {
        self.protocol_pool.block_info()
    }

    async fn add_transaction_and_subscribe(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> PoolResult<TransactionEvents> {
        let res = self.add_transaction(origin, transaction).await?;
        self.transaction_event_listener(res.hash)
            .ok_or_else(|| PoolError::new(res.hash, PoolErrorKind::DiscardedOnInsert))
    }

    async fn add_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> PoolResult<AddedTransactionOutcome> {
        self.add_transactions_with_origins(vec![(origin, transaction)])
            .await
            .pop()
            .expect("one result per transaction")
    }

    async fn add_transactions(
        &self,
        origin: TransactionOrigin,
        transactions: Vec<Self::Transaction>,
    ) -> Vec<PoolResult<AddedTransactionOutcome>> {
        self.add_transactions_with_origins(
            transactions.into_iter().map(|tx| (origin, tx)).collect(),
        )
        .await
    }

    async fn add_transactions_with_origins(
        &self,
        transactions: Vec<(TransactionOrigin, Self::Transaction)>,
    ) -> Vec<PoolResult<AddedTransactionOutcome>> {
        if transactions.is_empty() {
            return Vec::new();
        }

        // Fully delegate to protocol pool for non-2D transactions
        if !transactions.iter().any(|(_, tx)| tx.is_aa_2d()) {
            return self
                .protocol_pool
                .add_transactions_with_origins(transactions)
                .await;
        }

        let origins = transactions
            .iter()
            .map(|(origin, _)| *origin)
            .collect::<Vec<_>>();

        self.protocol_pool
            .validator()
            .validate_transactions(transactions)
            .await
            .into_iter()
            .zip(origins)
            .map(|(outcome, origin)| self.add_validated_transaction(origin, outcome))
            .collect()
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
        let mut txs = self.protocol_pool.pooled_transactions_max(max);
        if txs.len() >= max {
            return txs;
        }

        let remaining = max - txs.len();
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
        let mut out = Vec::new();
        self.append_pooled_transaction_elements(&tx_hashes, limit, &mut out);
        out
    }

    fn append_pooled_transaction_elements(
        &self,
        tx_hashes: &[B256],
        limit: GetPooledTransactionLimit,
        out: &mut Vec<<Self::Transaction as PoolTransaction>::Pooled>,
    ) {
        let mut accumulated_size = 0;
        self.aa_2d_pool.read().append_pooled_transaction_elements(
            tx_hashes,
            limit,
            &mut accumulated_size,
            out,
        );

        // If the limit is already exceeded, don't query the protocol pool
        if limit.exceeds(accumulated_size) {
            return;
        }

        // Adjust the limit for the protocol pool based on what we've already collected
        let remaining_limit = match limit {
            GetPooledTransactionLimit::None => GetPooledTransactionLimit::None,
            GetPooledTransactionLimit::ResponseSizeSoftLimit(max) => {
                GetPooledTransactionLimit::ResponseSizeSoftLimit(
                    max.saturating_sub(accumulated_size),
                )
            }
        };

        self.protocol_pool
            .append_pooled_transaction_elements(tx_hashes, remaining_limit, out);
    }

    fn get_pooled_transaction_element(
        &self,
        tx_hash: B256,
    ) -> Option<reth_primitives_traits::Recovered<<Self::Transaction as PoolTransaction>::Pooled>>
    {
        self.protocol_pool
            .get_pooled_transaction_element(tx_hash)
            .or_else(|| {
                self.aa_2d_pool
                    .read()
                    .get(&tx_hash)
                    .and_then(|tx| tx.transaction.clone_into_pooled().ok())
            })
    }

    fn best_transactions(
        &self,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Self::Transaction>>>> {
        let protocol_pool = self.protocol_pool.inner();
        let base_fee = protocol_pool.block_info().pending_basefee;
        let left = protocol_pool.best_transactions();
        let right = self.aa_2d_pool.read().best_transactions();
        Box::new(MergeBestTransactions::new(Box::new(left), right, base_fee))
    }

    fn best_transactions_with_attributes(
        &self,
        attributes: BestTransactionsAttributes,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Self::Transaction>>>> {
        let left = self
            .protocol_pool
            .best_transactions_with_attributes(attributes);
        let right = self
            .aa_2d_pool
            .read()
            .best_transactions_with_base_fee(attributes.basefee);
        Box::new(MergeBestTransactions::new(left, right, attributes.basefee))
    }

    fn pending_transactions(&self) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut pending = self.protocol_pool.pending_transactions();
        pending.extend(self.aa_2d_pool.read().pending_transactions());
        pending
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
        txs.extend(
            self.aa_2d_pool
                .read()
                .pending_transactions()
                .take(remaining),
        );
        txs
    }

    fn queued_transactions(&self) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut queued = self.protocol_pool.queued_transactions();
        queued.extend(self.aa_2d_pool.read().queued_transactions());
        queued
    }

    fn pending_and_queued_txn_count(&self) -> (usize, usize) {
        let (protocol_pending, protocol_queued) = self.protocol_pool.pending_and_queued_txn_count();
        let (aa_pending, aa_queued) = self.aa_2d_pool.read().pending_and_queued_txn_count();
        (protocol_pending + aa_pending, protocol_queued + aa_queued)
    }

    fn all_transactions(&self) -> AllPoolTransactions<Self::Transaction> {
        let mut transactions = self.protocol_pool.all_transactions();
        self.aa_2d_pool
            .read()
            .append_all_transactions(&mut transactions);
        transactions
    }

    fn all_transactions_by_sender(
        &self,
        sender: Address,
    ) -> AllPoolTransactions<Self::Transaction> {
        let mut transactions = self.protocol_pool.all_transactions_by_sender(sender);
        self.aa_2d_pool
            .read()
            .append_all_transactions_by_sender(sender, &mut transactions);
        transactions
    }

    fn all_transaction_hashes(&self) -> Vec<B256> {
        let mut hashes = self.protocol_pool.all_transaction_hashes();
        hashes.extend(self.aa_2d_pool.read().all_transaction_hashes_iter());
        hashes
    }

    fn remove_transactions(
        &self,
        hashes: Vec<B256>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.aa_2d_pool.write().remove_transactions(hashes.iter());
        txs.extend(self.protocol_pool.remove_transactions(hashes));
        txs
    }

    fn remove_transactions_and_descendants(
        &self,
        hashes: Vec<B256>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self
            .aa_2d_pool
            .write()
            .remove_transactions_and_descendants(hashes.iter());
        txs.extend(
            self.protocol_pool
                .remove_transactions_and_descendants(hashes),
        );
        txs
    }

    fn remove_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self
            .aa_2d_pool
            .write()
            .remove_transactions_by_sender(sender);
        txs.extend(self.protocol_pool.remove_transactions_by_sender(sender));
        txs
    }

    fn prune_transactions(
        &self,
        hashes: Vec<TxHash>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.aa_2d_pool.write().remove_transactions(hashes.iter());
        txs.extend(self.protocol_pool.prune_transactions(hashes));
        txs
    }

    fn retain_unknown<A: HandleMempoolData>(&self, announcement: &mut A) {
        self.protocol_pool.retain_unknown(announcement);
        if announcement.is_empty() {
            return;
        }
        let aa_pool = self.aa_2d_pool.read();
        announcement.retain_by_hash(|tx| !aa_pool.contains(tx))
    }

    fn retain_contains<A>(&self, announcement: &mut A)
    where
        A: HandleMempoolData,
    {
        if announcement.is_empty() {
            return;
        }
        announcement.retain_by_hash(|tx| self.contains(tx))
    }

    fn contains(&self, tx_hash: &B256) -> bool {
        self.protocol_pool.contains(tx_hash) || self.aa_2d_pool.read().contains(tx_hash)
    }

    fn get(&self, tx_hash: &B256) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>> {
        self.protocol_pool
            .get(tx_hash)
            .or_else(|| self.aa_2d_pool.read().get(tx_hash))
    }

    fn get_all(&self, txs: Vec<B256>) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut result = self.aa_2d_pool.read().get_all(txs.iter());
        result.extend(self.protocol_pool.get_all(txs));
        result
    }

    fn on_propagated(&self, txs: PropagatedTransactions) {
        self.protocol_pool.on_propagated(txs);
    }

    fn get_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.protocol_pool.get_transactions_by_sender(sender);
        txs.extend(
            self.aa_2d_pool
                .read()
                .get_transactions_by_sender_iter(sender),
        );
        txs
    }

    fn get_pending_transactions_with_predicate(
        &self,
        mut predicate: impl FnMut(&ValidPoolTransaction<Self::Transaction>) -> bool,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self
            .protocol_pool
            .get_pending_transactions_with_predicate(&mut predicate);
        txs.extend(
            self.aa_2d_pool
                .read()
                .pending_transactions()
                .filter(|tx| predicate(tx)),
        );
        txs
    }

    fn get_pending_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self
            .protocol_pool
            .get_pending_transactions_by_sender(sender);
        txs.extend(
            self.aa_2d_pool
                .read()
                .pending_transactions()
                .filter(|tx| tx.sender() == sender),
        );

        txs
    }

    fn get_queued_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.protocol_pool.get_queued_transactions_by_sender(sender);
        txs.extend(
            self.aa_2d_pool
                .read()
                .queued_transactions()
                .filter(|tx| tx.sender() == sender),
        );

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
        // Only returns transactions from protocol pool (nonce_key=0)
        self.protocol_pool
            .get_transaction_by_sender_and_nonce(sender, nonce)
    }

    fn get_transactions_by_origin(
        &self,
        origin: TransactionOrigin,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.protocol_pool.get_transactions_by_origin(origin);
        txs.extend(
            self.aa_2d_pool
                .read()
                .get_transactions_by_origin_iter(origin),
        );
        txs
    }

    fn get_pending_transactions_by_origin(
        &self,
        origin: TransactionOrigin,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self
            .protocol_pool
            .get_pending_transactions_by_origin(origin);
        txs.extend(
            self.aa_2d_pool
                .read()
                .get_pending_transactions_by_origin_iter(origin),
        );
        txs
    }

    fn unique_senders(&self) -> AddressSet {
        let mut senders = self.protocol_pool.unique_senders();
        senders.extend(self.aa_2d_pool.read().senders_iter().copied());
        senders
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

    fn has_blobs_for_versioned_hashes(
        &self,
        versioned_hashes: &[B256],
    ) -> Result<Vec<bool>, reth_transaction_pool::blobstore::BlobStoreError> {
        self.protocol_pool
            .has_blobs_for_versioned_hashes(versioned_hashes)
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

    fn get_blobs_for_versioned_hashes_v3(
        &self,
        versioned_hashes: &[B256],
    ) -> Result<
        Vec<Option<alloy_eips::eip4844::BlobAndProofV2>>,
        reth_transaction_pool::blobstore::BlobStoreError,
    > {
        self.protocol_pool
            .get_blobs_for_versioned_hashes_v3(versioned_hashes)
    }

    fn get_blobs_for_versioned_hashes_v4(
        &self,
        versioned_hashes: &[B256],
        cell_mask: alloy_eips::eip7594::BlobCellMask,
    ) -> Result<
        Vec<Option<alloy_eips::eip4844::BlobCellsAndProofsV1>>,
        reth_transaction_pool::blobstore::BlobStoreError,
    > {
        self.protocol_pool
            .get_blobs_for_versioned_hashes_v4(versioned_hashes, cell_mask)
    }

    fn blob_store(&self) -> Box<dyn reth_transaction_pool::BlobStore> {
        TransactionPool::blob_store(&self.protocol_pool)
    }
}

impl<Client, EvmConfig> TempoTransactionPoolExt for TempoTransactionPool<Client, EvmConfig>
where
    EvmConfig: ConfigureTempoPoolEvm,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + 'static,
{
    fn get_pending_transactions_by_address_and_nonce_key(
        &self,
        address: Address,
        nonce_key: U256,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        self.aa_2d_pool
            .read()
            .get_pending_transactions_by_address_and_nonce_key(address, nonce_key)
            .collect()
    }
}

impl<Client, EvmConfig> TransactionPoolExt for TempoTransactionPool<Client, EvmConfig>
where
    EvmConfig: ConfigureTempoPoolEvm,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + 'static,
{
    type Block = Block;

    fn set_block_info(&self, info: BlockInfo) {
        self.protocol_pool.set_block_info(info);
        self.aa_2d_pool.write().set_base_fee(info.pending_basefee);
    }

    fn on_canonical_state_change(&self, update: CanonicalStateUpdate<'_, Self::Block>) {
        // Keep the AA 2D pool's base fee in sync with the protocol pool. Reth only calls
        // `set_block_info` at startup and after deep reorgs, so without this the 2D pool would
        // keep ordering its eviction sets against a stale base fee once the fee starts moving.
        let pending_basefee = update.pending_block_base_fee;
        self.protocol_pool.on_canonical_state_change(update);
        self.aa_2d_pool.write().set_base_fee(pending_basefee);
    }

    fn update_accounts(&self, accounts: Vec<ChangedAccount>) {
        self.protocol_pool.update_accounts(accounts)
    }

    fn delete_blob(&self, tx: B256) {
        self.protocol_pool.delete_blob(tx)
    }

    fn delete_blobs(&self, txs: Vec<B256>) {
        self.protocol_pool.delete_blobs(txs)
    }

    fn cleanup_blobs(&self) {
        self.protocol_pool.cleanup_blobs()
    }
}

/// Transactions [`TempoTransactionPool::evict_invalidated_transactions`] took out of the pool.
#[derive(Debug, Default)]
pub struct InvalidatedTransactions {
    /// Invalid or expired transactions, evicted for good.
    pub evicted: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    /// Transactions that may have become invalid, to validate and re-add.
    pub(crate) revalidate: Vec<(Arc<ValidPoolTransaction<TempoPooledTransaction>>, Reason)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Returns the hashes of the evicted transactions.
    fn tx_hashes(txs: &[Arc<ValidPoolTransaction<TempoPooledTransaction>>]) -> Vec<TxHash> {
        txs.iter().map(|tx| *tx.hash()).collect()
    }

    use crate::{
        preconditions::{Condition, Preconditions},
        test_utils::TxBuilder,
    };
    use alloy_consensus::Header;
    use alloy_primitives::{U256, address};

    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_transaction_pool::{
        PoolConfig, TransactionOrigin, TransactionPool, TransactionValidationTaskExecutor,
        blobstore::InMemoryBlobStore,
        validate::{EthTransactionValidatorBuilder, ValidTransaction},
    };
    use tempo_chainspec::{
        TempoChainSpec,
        hardfork::TempoHardfork,
        spec::{MODERATO, TEMPO_T1_TX_GAS_LIMIT_CAP},
    };

    use tempo_evm::{ResolvedFeeToken, TempoEvmConfig};
    use tempo_precompiles::PATH_USD_ADDRESS;
    use tempo_primitives::{Block, TempoHeader, TempoPrimitives};

    /// Adds an AA transaction of `sender` with `preconditions` to a fresh pool.
    fn pool_with(
        sender: Address,
        preconditions: Preconditions,
    ) -> (
        TempoTransactionPool<MockEthProvider<TempoPrimitives, TempoChainSpec>>,
        TempoPooledTransaction,
    ) {
        let pooled = TxBuilder::aa(sender).fee_token(PATH_USD_ADDRESS).build();
        pooled.set_preconditions(preconditions);
        let provider = create_provider_with_tip();
        provider.add_account(sender, ExtendedAccount::new(pooled.nonce(), *pooled.cost()));
        let pool = create_test_pool(provider);
        add_validated(&pool, pooled.clone());
        (pool, pooled)
    }

    #[tokio::test]
    async fn takes_out_transactions_of_changed_authority_for_revalidation() {
        let sender = Address::random();
        let (pool, pooled) = pool_with(sender, Preconditions::default());
        let mut invalidations = Invalidations::default();
        invalidations.changed_accounts.insert(sender);
        let taken = pool.evict_invalidated_transactions(&invalidations);
        assert!(taken.evicted.is_empty());
        assert_eq!(
            taken
                .revalidate
                .iter()
                .map(|(tx, reason)| (*tx.hash(), *reason))
                .collect::<Vec<_>>(),
            vec![(*pooled.hash(), Reason::Account)]
        );
        assert!(pool.get(pooled.hash()).is_none());
    }

    #[tokio::test]
    async fn takes_out_transactions_whose_precondition_a_block_broke() {
        let slot = U256::from(7);
        let (pool, pooled) = pool_with(
            Address::random(),
            Preconditions::from_conditions([(
                PATH_USD_ADDRESS,
                slot,
                Condition::Equals(U256::from(5)),
            )]),
        );
        let mut unchanged = Invalidations::default();
        unchanged.record_storage(PATH_USD_ADDRESS, slot, U256::from(4), U256::from(5));
        assert!(
            pool.evict_invalidated_transactions(&unchanged)
                .revalidate
                .is_empty()
        );

        let mut changed = Invalidations::default();
        changed.record_storage(PATH_USD_ADDRESS, slot, U256::from(5), U256::from(6));
        let taken = pool.evict_invalidated_transactions(&changed);
        assert_eq!(
            taken
                .revalidate
                .iter()
                .map(|(tx, reason)| (*tx.hash(), *reason))
                .collect::<Vec<_>>(),
            vec![(*pooled.hash(), Reason::Precondition)]
        );
    }

    fn create_test_pool(
        provider: MockEthProvider<TempoPrimitives, TempoChainSpec>,
    ) -> TempoTransactionPool<MockEthProvider<TempoPrimitives, TempoChainSpec>> {
        let inner =
            EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::mainnet())
                .disable_balance_check()
                .build(InMemoryBlobStore::default());
        let amm_cache =
            AmmLiquidityCache::new(provider).expect("failed to setup AmmLiquidityCache");
        let validator = TempoTransactionValidator::new(
            inner,
            crate::validator::DEFAULT_AA_VALID_AFTER_MAX_SECS,
            crate::validator::DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
            amm_cache,
        );

        let (executor, _task) = TransactionValidationTaskExecutor::new(validator);
        let protocol_pool = Pool::new(
            executor,
            TempoTipOrdering::default(),
            InMemoryBlobStore::default(),
            PoolConfig::default(),
        );
        TempoTransactionPool::new(protocol_pool, AA2dPool::new(Default::default()))
    }

    fn add_validated(
        pool: &TempoTransactionPool<MockEthProvider<TempoPrimitives, TempoChainSpec>>,
        pooled: TempoPooledTransaction,
    ) {
        let validated = TransactionValidationOutcome::Valid {
            balance: *pooled.cost(),
            state_nonce: pooled.nonce(),
            bytecode_hash: None,
            transaction: ValidTransaction::new(pooled, None),
            propagate: true,
            authorities: None,
        };
        pool.add_validated_transaction(TransactionOrigin::External, validated)
            .expect("transaction should be admitted");
    }

    fn create_provider_with_tip() -> MockEthProvider<TempoPrimitives, TempoChainSpec> {
        let provider = MockEthProvider::<TempoPrimitives>::new()
            .with_chain_spec(std::sync::Arc::unwrap_or_clone(MODERATO.clone()));
        provider.add_block(
            B256::random(),
            Block {
                header: TempoHeader {
                    inner: Header {
                        gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        provider
    }

    #[test]
    fn pending_transactions_by_address_and_nonce_key() {
        use crate::test_utils::{TxBuilder, wrap_valid_tx};

        let pool = create_test_pool(create_provider_with_tip());
        let sender = Address::random();
        let nonce_key = U256::from(7);
        let txs = [
            TxBuilder::aa(sender).nonce_key(nonce_key).build(),
            TxBuilder::aa(sender).nonce_key(nonce_key).nonce(1).build(),
            TxBuilder::aa(sender).nonce_key(nonce_key).nonce(3).build(),
            TxBuilder::aa(sender).nonce_key(U256::from(8)).build(),
            TxBuilder::aa(Address::random())
                .nonce_key(nonce_key)
                .build(),
            TxBuilder::aa(sender).nonce_key(U256::MAX).build(),
        ];
        let expected: Vec<_> = txs[..2].iter().map(|tx| *tx.hash()).collect();
        for tx in txs {
            pool.aa_2d_pool
                .write()
                .add_transaction(
                    Arc::new(wrap_valid_tx(tx, TransactionOrigin::Local)),
                    0,
                    TempoHardfork::T1,
                )
                .unwrap();
        }

        assert_eq!(
            tx_hashes(&pool.get_pending_transactions_by_address_and_nonce_key(sender, nonce_key)),
            expected
        );
        for (address, key) in [
            (Address::ZERO, nonce_key),
            (sender, U256::from(9)),
            (sender, U256::MAX),
        ] {
            assert!(
                pool.get_pending_transactions_by_address_and_nonce_key(address, key)
                    .is_empty()
            );
        }
    }

    #[test]
    fn canonical_state_change_refreshes_aa_2d_base_fee() {
        use reth_primitives_traits::SealedBlock;
        use reth_transaction_pool::PoolUpdateKind;

        let pool = create_test_pool(create_provider_with_tip());
        let initial_base_fee = pool.aa_2d_pool.read().base_fee();

        let new_tip = SealedBlock::seal_slow(Block {
            header: TempoHeader {
                inner: Header {
                    gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                    base_fee_per_gas: Some(initial_base_fee),
                    excess_blob_gas: Some(0),
                    ..Default::default()
                },
                ..Default::default()
            },
            body: Default::default(),
        });
        let pending_block_base_fee = initial_base_fee + 1_000;

        pool.on_canonical_state_change(CanonicalStateUpdate {
            new_tip: &new_tip,
            pending_block_base_fee,
            pending_block_blob_fee: None,
            changed_accounts: Vec::new(),
            mined_transactions: Vec::new(),
            update_kind: PoolUpdateKind::Commit,
        });

        assert_eq!(pool.aa_2d_pool.read().base_fee(), pending_block_base_fee);
        assert_eq!(
            pool.protocol_pool.block_info().pending_basefee,
            pending_block_base_fee
        );
    }

    #[test]
    fn pool_size_includes_aa_2d_transaction_counts_and_bytes() {
        let pool = create_test_pool(create_provider_with_tip());
        let tx = crate::test_utils::TxBuilder::aa(Address::random())
            .nonce_key(U256::ONE)
            .build();
        let tx_size = reth_primitives_traits::InMemorySize::size(&tx);

        add_validated(&pool, tx);

        let size = pool.pool_size();
        assert_eq!(size.pending, 1);
        assert_eq!(size.pending_size, tx_size);
        assert_eq!(size.queued, 0);
        assert_eq!(size.queued_size, 0);
        assert_eq!(size.total, 1);
    }

    #[test]
    fn by_sender_accessors_include_aa_2d_queued_transactions() {
        let pool = create_test_pool(create_provider_with_tip());
        let sender = Address::random();
        let other = Address::random();

        // Protocol lane (nonce_key = 0): nonce 0 is pending, nonce 2 is gapped and queued.
        let protocol_pending = crate::test_utils::TxBuilder::aa(sender).nonce(0).build();
        let protocol_queued = crate::test_utils::TxBuilder::aa(sender).nonce(2).build();
        // 2D lane (nonce_key = 1): same shape, lives only in the AA 2D pool.
        let aa_2d_pending = crate::test_utils::TxBuilder::aa(sender)
            .nonce_key(U256::ONE)
            .nonce(0)
            .build();
        let aa_2d_queued = crate::test_utils::TxBuilder::aa(sender)
            .nonce_key(U256::ONE)
            .nonce(2)
            .build();
        // Another sender's queued 2D transaction must not leak into `sender`'s results.
        let other_aa_2d_queued = crate::test_utils::TxBuilder::aa(other)
            .nonce_key(U256::ONE)
            .nonce(2)
            .build();

        let protocol_pending_hash = *protocol_pending.hash();
        let protocol_queued_hash = *protocol_queued.hash();
        let aa_2d_pending_hash = *aa_2d_pending.hash();
        let aa_2d_queued_hash = *aa_2d_queued.hash();
        let other_aa_2d_queued_hash = *other_aa_2d_queued.hash();

        for pooled in [
            protocol_pending,
            protocol_queued,
            aa_2d_pending,
            aa_2d_queued,
            other_aa_2d_queued,
        ] {
            let validated = TransactionValidationOutcome::Valid {
                balance: *pooled.cost(),
                state_nonce: 0,
                bytecode_hash: None,
                transaction: ValidTransaction::new(pooled, None),
                propagate: true,
                authorities: None,
            };
            pool.add_validated_transaction(TransactionOrigin::External, validated)
                .expect("transaction should be admitted");
        }

        assert_eq!(pool.pending_and_queued_txn_count(), (2, 3));

        let mut queued = tx_hashes(&pool.get_queued_transactions_by_sender(sender));
        queued.sort();
        let mut expected_queued = vec![protocol_queued_hash, aa_2d_queued_hash];
        expected_queued.sort();
        assert_eq!(queued, expected_queued);

        let mut pending = tx_hashes(&pool.get_pending_transactions_by_sender(sender));
        pending.sort();
        let mut expected_pending = vec![protocol_pending_hash, aa_2d_pending_hash];
        expected_pending.sort();
        assert_eq!(pending, expected_pending);

        assert_eq!(
            tx_hashes(&pool.get_queued_transactions_by_sender(other)),
            vec![other_aa_2d_queued_hash]
        );
        assert!(pool.get_pending_transactions_by_sender(other).is_empty());
    }

    #[tokio::test]
    async fn validator_token_change_uses_resolved_fee_token_for_liquidity_recheck() {
        let sender = Address::random();
        let validator_address = Address::random();
        let resolved_fee_token = address!("20C0000000000000000000000000000000000002");
        let pooled = crate::test_utils::TxBuilder::aa(sender).build();

        assert_eq!(pooled.inner().fee_token(), None);
        pooled.set_resolved_fee_token(ResolvedFeeToken::Selected(resolved_fee_token));

        let provider = MockEthProvider::<TempoPrimitives>::new()
            .with_chain_spec(std::sync::Arc::unwrap_or_clone(MODERATO.clone()));
        provider.add_account(sender, ExtendedAccount::new(pooled.nonce(), *pooled.cost()));
        provider.add_block(
            B256::random(),
            Block {
                header: TempoHeader {
                    inner: Header {
                        gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        let inner = EthTransactionValidatorBuilder::new(provider, TempoEvmConfig::mainnet())
            .disable_balance_check()
            .build(InMemoryBlobStore::default());
        let amm_cache = AmmLiquidityCache::with_unique_validators(vec![validator_address]);
        let validator = TempoTransactionValidator::new(
            inner,
            crate::validator::DEFAULT_AA_VALID_AFTER_MAX_SECS,
            crate::validator::DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
            amm_cache,
        );

        let (executor, _task) = TransactionValidationTaskExecutor::new(validator);
        let protocol_pool = Pool::new(
            executor,
            TempoTipOrdering::default(),
            InMemoryBlobStore::default(),
            PoolConfig::default(),
        );
        let pool = TempoTransactionPool::new(protocol_pool, AA2dPool::new(Default::default()));

        let validated = TransactionValidationOutcome::Valid {
            balance: *pooled.cost(),
            state_nonce: pooled.nonce(),
            bytecode_hash: None,
            transaction: ValidTransaction::new(pooled.clone(), None),
            propagate: true,
            authorities: None,
        };
        pool.add_validated_transaction(TransactionOrigin::External, validated)
            .expect("transaction should be admitted before validator token change");

        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates
            .validator_token_changes
            .insert(validator_address, resolved_fee_token);

        let evicted = pool.evict_invalidated_transactions(&updates.into()).evicted;
        assert!(evicted.is_empty());
        assert!(pool.get(pooled.hash()).is_some());
    }
}
