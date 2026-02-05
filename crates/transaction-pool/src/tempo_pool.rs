// Tempo transaction pool that implements Reth's TransactionPool trait
// Routes protocol nonces (nonce_key=0) to Reth pool
// Routes user nonces (nonce_key>0) to minimal 2D nonce pool

use crate::{
    amm::AmmLiquidityCache, best::MergeBestTransactions, transaction::TempoPooledTransaction,
    tt_2d_pool::AA2dPool, validator::TempoTransactionValidator,
};
use alloy_consensus::Transaction;
use alloy_primitives::{
    Address, B256, TxHash,
    map::{AddressMap, HashMap},
};
use parking_lot::RwLock;
use reth_chainspec::ChainSpecProvider;
use reth_eth_wire_types::HandleMempoolData;
use reth_primitives_traits::Block;
use reth_provider::{ChangedAccount, StateProviderFactory};
use reth_transaction_pool::{
    AddedTransactionOutcome, AllPoolTransactions, BestTransactions, BestTransactionsAttributes,
    BlockInfo, CanonicalStateUpdate, CoinbaseTipOrdering, GetPooledTransactionLimit,
    NewBlobSidecar, Pool, PoolResult, PoolSize, PoolTransaction, PropagatedTransactions,
    TransactionEvents, TransactionOrigin, TransactionPool, TransactionPoolExt,
    TransactionValidationOutcome, TransactionValidationTaskExecutor, TransactionValidator,
    ValidPoolTransaction,
    blobstore::InMemoryBlobStore,
    error::{PoolError, PoolErrorKind},
    identifier::TransactionId,
};
use revm::database::BundleAccount;
use std::{sync::Arc, time::Instant};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};

/// Tempo transaction pool that routes based on nonce_key
pub struct TempoTransactionPool<Client> {
    /// Vanilla pool for all standard transactions and AA transactions with regular nonce.
    protocol_pool: Pool<
        TransactionValidationTaskExecutor<TempoTransactionValidator<Client>>,
        CoinbaseTipOrdering<TempoPooledTransaction>,
        InMemoryBlobStore,
    >,
    /// Minimal pool for 2D nonces (nonce_key > 0)
    aa_2d_pool: Arc<RwLock<AA2dPool>>,
}

impl<Client> TempoTransactionPool<Client> {
    pub fn new(
        protocol_pool: Pool<
            TransactionValidationTaskExecutor<TempoTransactionValidator<Client>>,
            CoinbaseTipOrdering<TempoPooledTransaction>,
            InMemoryBlobStore,
        >,
        aa_2d_pool: AA2dPool,
    ) -> Self {
        Self {
            protocol_pool,
            aa_2d_pool: Arc::new(RwLock::new(aa_2d_pool)),
        }
    }
}
impl<Client> TempoTransactionPool<Client>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = TempoChainSpec> + 'static,
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
    pub(crate) fn notify_aa_pool_on_state_updates(&self, state: &HashMap<Address, BundleAccount>) {
        let (promoted, _mined) = self.aa_2d_pool.write().on_state_updates(state);
        // Note: mined transactions are notified via the vanilla pool updates
        self.protocol_pool
            .inner()
            .notify_on_transaction_updates(promoted, Vec::new());
    }

    /// Resets the nonce state for the given 2D nonce sequence IDs by reading from a specific
    /// block's state. Used during reorgs to correct the pool's nonce tracking for slots that
    /// were modified in the old chain but not in the new chain.
    pub(crate) fn reset_2d_nonces_from_state(
        &self,
        seq_ids: Vec<crate::tt_2d_pool::AASequenceId>,
        block_hash: B256,
    ) -> Result<(), reth_provider::ProviderError> {
        use reth_storage_api::StateProvider;
        use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, nonce::NonceManager};

        if seq_ids.is_empty() {
            return Ok(());
        }

        let state_provider = self.client().state_by_block_hash(block_hash)?;
        let mut nonce_changes = HashMap::default();

        for seq_id in seq_ids {
            // Read the current on-chain nonce for this sequence ID
            let slot = NonceManager::new().nonces[seq_id.address][seq_id.nonce_key].slot();
            let current_nonce: u64 = state_provider
                .storage(NONCE_PRECOMPILE_ADDRESS, slot.into())?
                .unwrap_or_default()
                .saturating_to();

            nonce_changes.insert(seq_id, current_nonce);
        }

        // Apply the nonce changes to the 2D pool
        let (promoted, _mined) = self.aa_2d_pool.write().on_nonce_changes(nonce_changes);
        if !promoted.is_empty() {
            self.protocol_pool
                .inner()
                .notify_on_transaction_updates(promoted, Vec::new());
        }

        Ok(())
    }

    /// Removes expiring nonce transactions that were included in a block.
    ///
    /// This is called with the transaction hashes from mined blocks to clean up
    /// expiring nonce transactions on inclusion, rather than waiting for expiry.
    pub(crate) fn remove_included_expiring_nonce_txs<'a>(
        &self,
        tx_hashes: impl Iterator<Item = &'a TxHash>,
    ) {
        self.aa_2d_pool
            .write()
            .remove_included_expiring_nonce_txs(tx_hashes);
    }

    /// Evicts transactions that are no longer valid due to on-chain events.
    ///
    /// This performs a single scan of all pooled transactions and checks for:
    /// 1. **Revoked keychain keys**: AA transactions signed with keys that have been revoked
    /// 2. **Spending limit updates**: AA transactions signed with keys whose spending limit
    ///    changed for a token matching the transaction's fee token
    /// 3. **Validator token changes**: Transactions that would fail due to insufficient
    ///    liquidity in the new (user_token, validator_token) AMM pool
    ///
    /// All checks are combined into one scan to avoid iterating the pool multiple times
    /// per block.
    pub fn evict_invalidated_transactions(
        &self,
        updates: &crate::maintain::TempoPoolUpdates,
    ) -> usize {
        use reth_storage_api::StateProvider;
        use tempo_precompiles::{
            TIP_FEE_MANAGER_ADDRESS,
            tip_fee_manager::amm::{Pool, PoolKey, compute_amount_out},
            tip20::slots as tip20_slots,
        };

        if !updates.has_invalidation_events() {
            return 0;
        }

        // Only fetch state provider if we need to check liquidity, blacklists, or whitelists.
        // Don't let a provider error skip revoked/spending-limit eviction.
        let state_provider = if !updates.validator_token_changes.is_empty()
            || !updates.blacklist_additions.is_empty()
            || !updates.whitelist_removals.is_empty()
        {
            self.client().latest().ok()
        } else {
            None
        };

        // Cache policy lookups per fee token to avoid redundant storage reads
        let mut policy_cache: AddressMap<u64> = AddressMap::default();

        // Filter validator token changes to only those from active validators.
        // This prevents DoS via permissionless setValidatorToken: we only process
        // token changes from validators who have actually produced recent blocks.
        let amm_cache = self.amm_liquidity_cache();
        let active_validator_token_changes: Vec<Address> = updates
            .validator_token_changes
            .iter()
            .filter_map(|&(validator, new_token)| {
                amm_cache
                    .is_active_validator(&validator)
                    .then_some(new_token)
            })
            .collect();

        let mut to_remove = Vec::new();
        let mut revoked_count = 0;
        let mut spending_limit_count = 0;
        let mut liquidity_count = 0;
        let mut user_token_count = 0;
        let mut blacklisted_count = 0;
        let mut unwhitelisted_count = 0;

        let all_txs = self.all_transactions();
        for tx in all_txs.pending.iter().chain(all_txs.queued.iter()) {
            // Extract keychain subject once per transaction (if applicable)
            let keychain_subject = tx.transaction.keychain_subject();

            // Check 1: Revoked keychain keys
            if !updates.revoked_keys.is_empty()
                && let Some(ref subject) = keychain_subject
                && subject.matches_revoked(&updates.revoked_keys)
            {
                to_remove.push(*tx.hash());
                revoked_count += 1;
                continue;
            }

            // Check 2: Spending limit updates
            // Only evict if the transaction's fee token matches the token whose limit changed.
            if !updates.spending_limit_changes.is_empty()
                && let Some(ref subject) = keychain_subject
                && subject.matches_spending_limit_update(&updates.spending_limit_changes)
            {
                to_remove.push(*tx.hash());
                spending_limit_count += 1;
                continue;
            }

            // Check 3: Validator token changes (check liquidity for all transactions)
            // NOTE: Only process changes from validators whose new token is already in use
            // by actual block producers. This prevents permissionless setValidatorToken calls
            // from triggering mass eviction.
            if let Some(ref provider) = state_provider
                && !active_validator_token_changes.is_empty()
            {
                let user_token = tx
                    .transaction
                    .inner()
                    .fee_token()
                    .unwrap_or(tempo_precompiles::DEFAULT_FEE_TOKEN);
                let cost = tx.transaction.fee_token_cost();

                let amount_out = match compute_amount_out(cost) {
                    Ok(amount) => amount,
                    Err(_) => continue,
                };

                for &new_validator_token in &active_validator_token_changes {
                    if user_token == new_validator_token {
                        continue;
                    }

                    let pool_key = PoolKey::new(user_token, new_validator_token).get_id();
                    let slot = tempo_precompiles::tip_fee_manager::TipFeeManager::new().pools
                        [pool_key]
                        .base_slot();

                    let pool_value = match provider.storage(TIP_FEE_MANAGER_ADDRESS, slot.into()) {
                        Ok(Some(value)) => value,
                        Ok(None) => {
                            to_remove.push(*tx.hash());
                            liquidity_count += 1;
                            break;
                        }
                        Err(_) => continue,
                    };

                    let reserve = alloy_primitives::U256::from(
                        Pool::decode_from_slot(pool_value).reserve_validator_token,
                    );

                    if reserve < amount_out {
                        to_remove.push(*tx.hash());
                        liquidity_count += 1;
                        break;
                    }
                }
            }

            // Check 4: Blacklisted fee payers
            // Only check AA transactions with a fee token (non-AA transactions don't have
            // a fee payer that can be blacklisted via TIP403)
            if !updates.blacklist_additions.is_empty()
                && let Some(ref provider) = state_provider
                && let Some(fee_token) = tx.transaction.inner().fee_token()
            {
                let fee_payer = tx
                    .transaction
                    .inner()
                    .fee_payer(tx.transaction.sender())
                    .unwrap_or(tx.transaction.sender());

                // Check if any blacklist addition applies to this transaction
                for &(blacklist_policy_id, blacklisted_account) in &updates.blacklist_additions {
                    if fee_payer != blacklisted_account {
                        continue;
                    }

                    // Get the token's transfer policy ID from cache or storage
                    let token_policy = if let Some(&cached) = policy_cache.get(&fee_token) {
                        Some(cached)
                    } else {
                        provider
                            .storage(fee_token, tip20_slots::TRANSFER_POLICY_ID.into())
                            .ok()
                            .flatten()
                            .map(|packed| {
                                let policy_id: u64 =
                                    (packed >> tip20_slots::TRANSFER_POLICY_ID_OFFSET).to();
                                policy_cache.insert(fee_token, policy_id);
                                policy_id
                            })
                    };

                    // If the token's policy matches the blacklist policy, evict the transaction
                    if token_policy == Some(blacklist_policy_id) {
                        to_remove.push(*tx.hash());
                        blacklisted_count += 1;
                        break;
                    }
                }
            }

            // Check 5: Un-whitelisted fee payers
            // When a fee payer is removed from a whitelist, their pending transactions
            // will fail validation at execution time.
            if !updates.whitelist_removals.is_empty()
                && let Some(ref provider) = state_provider
                && let Some(fee_token) = tx.transaction.inner().fee_token()
            {
                let fee_payer = tx
                    .transaction
                    .inner()
                    .fee_payer(tx.transaction.sender())
                    .unwrap_or(tx.transaction.sender());

                for &(whitelist_policy_id, unwhitelisted_account) in &updates.whitelist_removals {
                    if fee_payer != unwhitelisted_account {
                        continue;
                    }

                    // Get the token's transfer policy ID from cache or storage
                    let token_policy = if let Some(&cached) = policy_cache.get(&fee_token) {
                        Some(cached)
                    } else {
                        provider
                            .storage(fee_token, tip20_slots::TRANSFER_POLICY_ID.into())
                            .ok()
                            .flatten()
                            .map(|packed| {
                                let policy_id: u64 =
                                    (packed >> tip20_slots::TRANSFER_POLICY_ID_OFFSET).to();
                                policy_cache.insert(fee_token, policy_id);
                                policy_id
                            })
                    };

                    // If the token's policy matches the whitelist policy, evict the transaction
                    if token_policy == Some(whitelist_policy_id) {
                        to_remove.push(*tx.hash());
                        unwhitelisted_count += 1;
                        break;
                    }
                }
            }

            // Check 6: User fee token preference changes
            // When a user changes their fee token preference via setUserToken(), transactions
            // from that user that don't have an explicit fee_token set may now resolve to a
            // different token at execution time, causing fee payment failures.
            // Only evict transactions WITHOUT an explicit fee_token (those that rely on storage).
            if !updates.user_token_changes.is_empty()
                && tx.transaction.inner().fee_token().is_none()
                && updates
                    .user_token_changes
                    .contains(&tx.transaction.sender())
            {
                to_remove.push(*tx.hash());
                user_token_count += 1;
            }
        }

        let evicted_count = to_remove.len();
        if evicted_count > 0 {
            tracing::debug!(
                target: "txpool",
                total = evicted_count,
                revoked_count,
                spending_limit_count,
                liquidity_count,
                user_token_count,
                blacklisted_count,
                unwhitelisted_count,
                "Evicting invalidated transactions"
            );
            self.remove_transactions(to_remove);
        }
        evicted_count
    }

    fn add_validated_transactions(
        &self,
        origin: TransactionOrigin,
        transactions: Vec<TransactionValidationOutcome<TempoPooledTransaction>>,
    ) -> Vec<PoolResult<AddedTransactionOutcome>> {
        if transactions.iter().any(|outcome| {
            outcome
                .as_valid_transaction()
                .map(|tx| tx.transaction().is_aa_2d())
                .unwrap_or(false)
        }) {
            // mixed or 2d only
            let mut results = Vec::with_capacity(transactions.len());
            for tx in transactions {
                results.push(self.add_validated_transaction(origin, tx));
            }
            return results;
        }

        self.protocol_pool
            .inner()
            .add_transactions(origin, transactions)
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

                    // Get the active Tempo hardfork for expiring nonce handling
                    let tip_timestamp = self
                        .protocol_pool
                        .validator()
                        .validator()
                        .inner
                        .fork_tracker()
                        .tip_timestamp();
                    let hardfork = self.client().chain_spec().tempo_hardfork_at(tip_timestamp);

                    let added = self.aa_2d_pool.write().add_transaction(
                        Arc::new(tx),
                        state_nonce,
                        hardfork,
                    )?;
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
impl<Client> Clone for TempoTransactionPool<Client> {
    fn clone(&self) -> Self {
        Self {
            protocol_pool: self.protocol_pool.clone(),
            aa_2d_pool: Arc::clone(&self.aa_2d_pool),
        }
    }
}

// Manual Debug implementation
impl<Client> std::fmt::Debug for TempoTransactionPool<Client> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempoTransactionPool")
            .field("protocol_pool", &"Pool<...>")
            .field("aa_2d_nonce_pool", &"AA2dPool<...>")
            .field("paused_fee_token_pool", &"PausedFeeTokenPool<...>")
            .finish_non_exhaustive()
    }
}

// Implement the TransactionPool trait
impl<Client> TransactionPool for TempoTransactionPool<Client>
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + Send
        + Sync
        + 'static,
    TempoPooledTransaction: reth_transaction_pool::EthPoolTransaction,
{
    type Transaction = TempoPooledTransaction;

    fn pool_size(&self) -> PoolSize {
        let mut size = self.protocol_pool.pool_size();
        let (pending, queued) = self.aa_2d_pool.read().pending_and_queued_txn_count();
        size.pending += pending;
        size.queued += queued;
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
        let tx = self
            .protocol_pool
            .validator()
            .validate_transaction(origin, transaction)
            .await;
        let res = self.add_validated_transaction(origin, tx)?;
        self.transaction_event_listener(res.hash)
            .ok_or_else(|| PoolError::new(res.hash, PoolErrorKind::DiscardedOnInsert))
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
        let left = self.protocol_pool.inner().best_transactions();
        let right = self.aa_2d_pool.read().best_transactions();
        Box::new(MergeBestTransactions::new(left, right))
    }

    fn best_transactions_with_attributes(
        &self,
        _attributes: BestTransactionsAttributes,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Self::Transaction>>>> {
        self.best_transactions()
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
        {
            let aa_2d_pool = self.aa_2d_pool.read();
            transactions
                .pending
                .extend(aa_2d_pool.pending_transactions());
            transactions.queued.extend(aa_2d_pool.queued_transactions());
        }
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

    fn retain_unknown<A: HandleMempoolData>(&self, announcement: &mut A) {
        self.protocol_pool.retain_unknown(announcement);
        let aa_pool = self.aa_2d_pool.read();
        announcement.retain_by_hash(|tx| !aa_pool.contains(tx))
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
        predicate: impl FnMut(&ValidPoolTransaction<Self::Transaction>) -> bool,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // TODO: support 2d pool
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

    fn unique_senders(&self) -> std::collections::HashSet<Address> {
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
}

impl<Client> TransactionPoolExt for TempoTransactionPool<Client>
where
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = TempoChainSpec> + 'static,
{
    fn set_block_info(&self, info: BlockInfo) {
        self.protocol_pool.set_block_info(info)
    }

    fn on_canonical_state_change<B>(&self, update: CanonicalStateUpdate<'_, B>)
    where
        B: Block,
    {
        self.protocol_pool.on_canonical_state_change(update)
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
