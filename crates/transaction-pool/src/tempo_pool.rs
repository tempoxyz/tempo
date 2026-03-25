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
    map::{AddressMap, AddressSet, HashMap},
};
use parking_lot::RwLock;
use reth_chainspec::ChainSpecProvider;
use reth_eth_wire_types::HandleMempoolData;
use reth_provider::{ChangedAccount, StateProviderFactory};
use reth_storage_api::StateProvider;
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
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    error::Result as TempoPrecompileResult,
    nonce::NonceManager,
    storage::Handler,
    tip20::TIP20Token,
    tip403_registry::{REJECT_ALL_POLICY_ID, TIP403Registry},
};
use tempo_primitives::Block;
use tempo_revm::TempoStateAccess;

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
    pub(crate) fn notify_aa_pool_on_state_updates(&self, state: &AddressMap<BundleAccount>) {
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
        if seq_ids.is_empty() {
            return Ok(());
        }

        // Spec doesn't affect raw storage reads (sload), so default is safe here.
        let spec = TempoHardfork::default();
        let mut state_provider = self.client().state_by_block_hash(block_hash)?;

        let nonce_changes = state_provider
            .with_read_only_storage_ctx(spec, || -> TempoPrecompileResult<_> {
                let mut changes = HashMap::default();
                // Read the current on-chain nonce for this sequence ID
                for id in &seq_ids {
                    let current_nonce =
                        NonceManager::new().nonces[id.address][id.nonce_key].read()?;
                    changes.insert(*id, current_nonce);
                }
                Ok(changes)
            })
            .map_err(reth_provider::ProviderError::other)?;

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
    ///    2b. **Spending limit spends**: AA transactions whose remaining spending limit (re-read
    ///    from state) is now insufficient after included keychain txs decremented it
    /// 3. **Validator token changes**: Transactions that would fail due to insufficient
    ///    liquidity in the new (user_token, validator_token) AMM pool
    ///
    /// All checks are combined into one scan to avoid iterating the pool multiple times
    /// per block.
    pub fn evict_invalidated_transactions(
        &self,
        updates: &crate::maintain::TempoPoolUpdates,
    ) -> Vec<TxHash> {
        if !updates.has_invalidation_events() {
            return Vec::new();
        }

        // Fetch state provider if any check needs on-chain reads:
        // - validator token changes (liquidity check)
        // - blacklist/whitelist (policy check)
        // - spending limit spends (remaining limit check)
        let mut state_provider = if !updates.validator_token_changes.is_empty()
            || !updates.blacklist_additions.is_empty()
            || !updates.whitelist_removals.is_empty()
            || !updates.spending_limit_spends.is_empty()
        {
            self.client().latest().ok()
        } else {
            None
        };

        // Resolve the active hardfork for storage context.
        let tip_timestamp = self
            .protocol_pool
            .validator()
            .validator()
            .inner
            .fork_tracker()
            .tip_timestamp();
        let spec = self.client().chain_spec().tempo_hardfork_at(tip_timestamp);

        // Cache policy lookups per fee token to avoid redundant storage reads.
        // For compound policies (TIP-1015), the cache stores all sub-policy IDs
        // so eviction matches events emitted with sub-policy IDs.
        let mut policy_cache: AddressMap<Vec<u64>> = AddressMap::default();

        // Pre-collect policy IDs where TIP_FEE_MANAGER_ADDRESS (the fee recipient) was
        // blacklisted or un-whitelisted. This is constant across all txs so we compute
        // it once instead of re-scanning the updates list per transaction.
        let fee_manager_blacklisted: Vec<u64> = updates
            .blacklist_additions
            .iter()
            .filter(|(_, account)| *account == TIP_FEE_MANAGER_ADDRESS)
            .map(|(policy_id, _)| *policy_id)
            .collect();
        let fee_manager_unwhitelisted: Vec<u64> = updates
            .whitelist_removals
            .iter()
            .filter(|(_, account)| *account == TIP_FEE_MANAGER_ADDRESS)
            .map(|(policy_id, _)| *policy_id)
            .collect();

        // Re-check liquidity for all pooled txs when an active validator changes token.
        // Leverages the per-tx `has_enough_liquidity` check, which passes if ANY validator pair has
        // enough liquidity, matching admission and preventing mass-eviction of valid txs.
        let amm_cache = self.amm_liquidity_cache();
        let has_active_validator_token_changes = !updates.validator_token_changes.is_empty() && {
            let active_new_tokens: Vec<_> = updates
                .validator_token_changes
                .iter()
                .filter(|(validator, _)| amm_cache.is_active_validator(validator))
                .filter(|(_, new_token)| !amm_cache.is_active_validator_token(new_token))
                .map(|(_, &new_token)| new_token)
                .collect();
            amm_cache.track_tokens(&active_new_tokens)
        };

        let mut to_remove = Vec::new();
        let mut revoked_count = 0;
        let mut spending_limit_count = 0;
        let mut spending_limit_spend_count = 0;
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

            // Check 2b: Spending limit spends
            // When a keychain tx is included, verify_and_update_spending() decrements the
            // remaining limit but emits no event. We re-read the current remaining limit
            // from state for affected (account, key_id, fee_token) combos and evict if
            // the pending tx's fee cost now exceeds the remaining limit.
            if !updates.spending_limit_spends.is_empty()
                && let Some(ref subject) = keychain_subject
                && subject.matches_spending_limit_update(&updates.spending_limit_spends)
                && let Some(ref mut provider) = state_provider
                && exceeds_spending_limit(provider, subject, tx.transaction.fee_token_cost())
            {
                to_remove.push(*tx.hash());
                spending_limit_spend_count += 1;
                continue;
            }

            // Check 3: Validator token changes (re-check liquidity for all transactions)
            // Prevents mass eviction because it only:
            // - evicts when NO validator token has enough liquidity
            // - considers active validators (protects from permissionless `setValidatorToken`)
            if has_active_validator_token_changes && let Some(ref provider) = state_provider {
                let user_token = tx
                    .transaction
                    .inner()
                    .fee_token()
                    .unwrap_or(tempo_precompiles::DEFAULT_FEE_TOKEN);
                let cost = tx.transaction.fee_token_cost();

                match amm_cache.has_enough_liquidity(user_token, cost, &**provider) {
                    Ok(true) => {}
                    Ok(false) => {
                        to_remove.push(*tx.hash());
                        liquidity_count += 1;
                        continue;
                    }
                    Err(_) => continue,
                }
            }

            // Check 4: Blacklisted fee payers
            // Only check AA transactions with a fee token (non-AA transactions don't have
            // a fee payer that can be blacklisted via TIP403)
            if !updates.blacklist_additions.is_empty()
                && let Some(ref mut provider) = state_provider
                && let Some(fee_token) = tx.transaction.inner().fee_token()
            {
                let fee_payer = tx
                    .transaction
                    .inner()
                    .fee_payer(tx.transaction.sender())
                    .unwrap_or(tx.transaction.sender());

                // Check if any blacklist addition applies to this transaction's fee payer
                let mut sender_evicted = false;
                for &(blacklist_policy_id, blacklisted_account) in &updates.blacklist_additions {
                    if fee_payer != blacklisted_account {
                        continue;
                    }

                    let token_policies =
                        get_sender_policy_ids(provider, fee_token, spec, &mut policy_cache);

                    if token_policies
                        .as_ref()
                        .is_some_and(|ids| ids.contains(&blacklist_policy_id))
                    {
                        sender_evicted = true;
                        break;
                    }
                }

                // Check if the fee manager (recipient) was blacklisted on this token's
                // recipient policy — the tx would fail at execution since the fee
                // transfer to TIP_FEE_MANAGER_ADDRESS would be rejected.
                let recipient_evicted = !sender_evicted
                    && !fee_manager_blacklisted.is_empty()
                    && get_recipient_policy_ids(provider, fee_token, spec)
                        .is_some_and(|ids| fee_manager_blacklisted.iter().any(|p| ids.contains(p)));

                if sender_evicted || recipient_evicted {
                    to_remove.push(*tx.hash());
                    blacklisted_count += 1;
                }
            }

            // Check 5: Un-whitelisted fee payers
            // When a fee payer is removed from a whitelist, their pending transactions
            // will fail validation at execution time.
            if !updates.whitelist_removals.is_empty()
                && let Some(ref mut provider) = state_provider
                && let Some(fee_token) = tx.transaction.inner().fee_token()
            {
                let fee_payer = tx
                    .transaction
                    .inner()
                    .fee_payer(tx.transaction.sender())
                    .unwrap_or(tx.transaction.sender());

                let mut sender_evicted = false;
                for &(whitelist_policy_id, unwhitelisted_account) in &updates.whitelist_removals {
                    if fee_payer != unwhitelisted_account {
                        continue;
                    }

                    let token_policies =
                        get_sender_policy_ids(provider, fee_token, spec, &mut policy_cache);

                    if token_policies
                        .as_ref()
                        .is_some_and(|ids| ids.contains(&whitelist_policy_id))
                    {
                        sender_evicted = true;
                        break;
                    }
                }

                // Check if the fee manager (recipient) was un-whitelisted on this
                // token's recipient policy.
                let recipient_evicted = !sender_evicted
                    && !fee_manager_unwhitelisted.is_empty()
                    && get_recipient_policy_ids(provider, fee_token, spec).is_some_and(|ids| {
                        fee_manager_unwhitelisted.iter().any(|p| ids.contains(p))
                    });

                if sender_evicted || recipient_evicted {
                    to_remove.push(*tx.hash());
                    unwhitelisted_count += 1;
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

        if !to_remove.is_empty() {
            tracing::debug!(
                target: "txpool",
                total = to_remove.len(),
                revoked_count,
                spending_limit_count,
                spending_limit_spend_count,
                liquidity_count,
                user_token_count,
                blacklisted_count,
                unwhitelisted_count,
                "Evicting invalidated transactions"
            );
            self.remove_transactions(to_remove.clone());
        }
        to_remove
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

        // Fully delegate to protocol pool for non-2D transactions
        if !transactions.iter().any(|tx| tx.is_aa_2d()) {
            return self
                .protocol_pool
                .add_transactions(origin, transactions)
                .await;
        }

        self.protocol_pool
            .validator()
            .validate_transactions_with_origin(origin, transactions)
            .await
            .into_iter()
            .map(|outcome| self.add_validated_transaction(origin, outcome))
            .collect()
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
    type Block = Block;

    fn set_block_info(&self, info: BlockInfo) {
        self.protocol_pool.set_block_info(info)
    }

    fn on_canonical_state_change(&self, update: CanonicalStateUpdate<'_, Self::Block>) {
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

/// Checks whether a pending keychain tx exceeds its remaining spending limit.
///
/// Re-reads the current remaining limit from state for the tx's (account, key_id,
/// fee_token) combo. Returns true if the tx's fee cost exceeds the remaining limit,
/// meaning it should be evicted.
pub(crate) fn exceeds_spending_limit(
    provider: &mut impl StateProvider,
    subject: &crate::transaction::KeychainSubject,
    fee_token_cost: alloy_primitives::U256,
) -> bool {
    // Spec doesn't affect raw storage reads (sload), so default is safe here.
    let spec = TempoHardfork::default();
    let limit_key = AccountKeychain::spending_limit_key(subject.account, subject.key_id);

    provider
        .with_read_only_storage_ctx(spec, || -> TempoPrecompileResult<bool> {
            let keychain = AccountKeychain::new();
            if !keychain.keys[subject.account][subject.key_id]
                .read()?
                .enforce_limits
            {
                return Ok(false);
            }

            let remaining = keychain.spending_limits[limit_key][subject.fee_token].read()?;
            Ok(fee_token_cost > remaining)
        })
        .unwrap_or_default()
}

/// Returns the set of policy IDs that can affect fee_payer authorization for a token.
///
/// For simple policies the set contains just the policy ID. For compound policies
/// (TIP-1015) it contains both the compound root and the sender sub-policy, since
/// fee transfer authorization checks `fee_payer` via `AuthRole::Sender`.
/// `recipient_policy_id` and `mint_recipient_policy_id` are excluded — they govern
/// other roles and cannot invalidate a fee_payer's transactions.
fn get_sender_policy_ids(
    provider: &mut impl StateProvider,
    fee_token: Address,
    spec: TempoHardfork,
    cache: &mut AddressMap<Vec<u64>>,
) -> Option<Vec<u64>> {
    if let Some(cached) = cache.get(&fee_token) {
        return Some(cached.clone());
    }

    provider.with_read_only_storage_ctx(spec, || {
        let policy_id = TIP20Token::from_address(fee_token)
            .and_then(|t| t.transfer_policy_id())
            .ok()
            .filter(|&id| id != REJECT_ALL_POLICY_ID)?;

        let mut ids = vec![policy_id];

        // For compound policies, include only the sender sub-policy ID.
        let registry = TIP403Registry::new();
        if let Ok(data) = registry.policy_records[policy_id].base.read()
            && data.is_compound()
            && let Ok(compound) = registry.policy_records[policy_id].compound.read()
            && compound.sender_policy_id != REJECT_ALL_POLICY_ID
        {
            ids.push(compound.sender_policy_id);
        }

        // Cache even though compound sub-policy references are immutable: avoids
        // redundant SLOADs when multiple transactions share the same fee token.
        cache.insert(fee_token, ids.clone());
        Some(ids)
    })
}

/// Returns the set of policy IDs that can affect recipient authorization for a token.
///
/// For simple (non-compound) policies, the transfer policy applies symmetrically to both
/// sender and recipient, so the set contains just the policy ID. For compound policies
/// (TIP-1015) it contains both the compound root and the recipient sub-policy, since
/// fee transfer authorization checks the fee manager via `AuthRole::Recipient`.
///
/// Unlike `get_sender_policy_ids` this is uncached — it's only called on the rare path
/// where the fee manager itself is blacklisted or un-whitelisted.
fn get_recipient_policy_ids(
    provider: &mut impl StateProvider,
    fee_token: Address,
    spec: TempoHardfork,
) -> Option<Vec<u64>> {
    provider.with_read_only_storage_ctx(spec, || {
        let policy_id = TIP20Token::from_address(fee_token)
            .and_then(|t| t.transfer_policy_id())
            .ok()
            .filter(|&id| id != REJECT_ALL_POLICY_ID)?;

        let mut ids = vec![policy_id];

        let registry = TIP403Registry::new();
        if let Ok(data) = registry.policy_records[policy_id].base.read()
            && data.is_compound()
            && let Ok(compound) = registry.policy_records[policy_id].compound.read()
            && compound.recipient_policy_id != REJECT_ALL_POLICY_ID
        {
            ids.push(compound.recipient_policy_id);
        }

        Some(ids)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::KeychainSubject;
    use alloy_primitives::{U256, address};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_storage_api::StateProviderFactory;
    use tempo_contracts::precompiles::ITIP403Registry;
    use tempo_precompiles::{
        ACCOUNT_KEYCHAIN_ADDRESS, TIP403_REGISTRY_ADDRESS,
        account_keychain::{AccountKeychain, AuthorizedKey},
        tip20::slots as tip20_slots,
        tip403_registry::PolicyData,
    };

    fn provider_with_spending_limit(
        account: Address,
        key_id: Address,
        fee_token: Address,
        remaining_limit: alloy_primitives::U256,
    ) -> Box<dyn reth_storage_api::StateProvider> {
        let provider = MockEthProvider::default().with_chain_spec(std::sync::Arc::unwrap_or_clone(
            tempo_chainspec::spec::MODERATO.clone(),
        ));

        let keychain = AccountKeychain::new();

        // Write AuthorizedKey with enforce_limits=true
        let key_slot = keychain.keys[account][key_id].base_slot();
        let authorized_key = AuthorizedKey {
            signature_type: 0,
            expiry: u64::MAX,
            enforce_limits: true,
            is_revoked: false,
        }
        .encode_to_slot();

        let limit_key = AccountKeychain::spending_limit_key(account, key_id);
        let limit_slot = keychain.spending_limits[limit_key][fee_token].slot();

        provider.add_account(
            ACCOUNT_KEYCHAIN_ADDRESS,
            ExtendedAccount::new(0, alloy_primitives::U256::ZERO).extend_storage([
                (key_slot.into(), authorized_key),
                (limit_slot.into(), remaining_limit),
            ]),
        );

        provider.latest().unwrap()
    }

    /// Eviction must match sub-policy IDs against compound policies.
    /// When a token uses a compound policy, and a sub-policy event fires,
    /// the eviction comparison must detect the match.
    #[test]
    fn compound_policy_sub_policy_matches_eviction_check() {
        let fee_token = address!("20C0000000000000000000000000000000000001");
        let compound_policy_id: u64 = 5;
        let sender_sub_policy: u64 = 3;
        let recipient_sub_policy: u64 = 4;

        let provider = MockEthProvider::default().with_chain_spec(std::sync::Arc::unwrap_or_clone(
            tempo_chainspec::spec::MODERATO.clone(),
        ));

        // Set up TIP20 token with transfer_policy_id = compound_policy_id
        let transfer_policy_id_packed =
            U256::from(compound_policy_id) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8);
        provider.add_account(
            fee_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([(
                tip20_slots::TRANSFER_POLICY_ID.into(),
                transfer_policy_id_packed,
            )]),
        );

        // Set up TIP403 registry with compound policy pointing to sub-policies
        let registry = TIP403Registry::new();
        let policy_data = PolicyData {
            policy_type: ITIP403Registry::PolicyType::COMPOUND as u8,
            admin: Address::ZERO,
        };
        let base_slot = registry.policy_records[compound_policy_id].base.base_slot();
        let compound_slot = registry.policy_records[compound_policy_id]
            .compound
            .base_slot();
        // CompoundPolicyData: 3 u64s packed into one slot
        let compound_encoded =
            U256::from(sender_sub_policy) | (U256::from(recipient_sub_policy) << 64);

        provider.add_account(
            TIP403_REGISTRY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (base_slot.into(), policy_data.encode_to_slot()),
                (compound_slot.into(), compound_encoded),
            ]),
        );

        let mut state = provider.latest().unwrap();
        let mut cache: AddressMap<Vec<u64>> = AddressMap::default();

        let ids =
            get_sender_policy_ids(&mut state, fee_token, TempoHardfork::default(), &mut cache)
                .expect("should resolve policy IDs");

        assert!(
            ids.contains(&compound_policy_id),
            "should contain compound policy ID"
        );
        assert!(
            ids.contains(&sender_sub_policy),
            "should contain sender sub-policy"
        );
    }

    /// fee_payer is only checked against sender sub-policy at execution time,
    /// so sender_policy_ids must NOT contain recipient_sub_policy.
    #[test]
    fn compound_policy_sender_ids_exclude_recipient_sub_policy() {
        let fee_token = address!("20C0000000000000000000000000000000000001");
        let compound_policy_id: u64 = 5;
        let sender_sub_policy: u64 = 3;
        let recipient_sub_policy: u64 = 4;

        let provider = MockEthProvider::default().with_chain_spec(std::sync::Arc::unwrap_or_clone(
            tempo_chainspec::spec::MODERATO.clone(),
        ));

        let transfer_policy_id_packed =
            U256::from(compound_policy_id) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8);
        provider.add_account(
            fee_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([(
                tip20_slots::TRANSFER_POLICY_ID.into(),
                transfer_policy_id_packed,
            )]),
        );

        let registry = TIP403Registry::new();
        let policy_data = PolicyData {
            policy_type: ITIP403Registry::PolicyType::COMPOUND as u8,
            admin: Address::ZERO,
        };
        let base_slot = registry.policy_records[compound_policy_id].base.base_slot();
        let compound_slot = registry.policy_records[compound_policy_id]
            .compound
            .base_slot();
        let compound_encoded =
            U256::from(sender_sub_policy) | (U256::from(recipient_sub_policy) << 64);

        provider.add_account(
            TIP403_REGISTRY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (base_slot.into(), policy_data.encode_to_slot()),
                (compound_slot.into(), compound_encoded),
            ]),
        );

        let mut state = provider.latest().unwrap();
        let mut cache: AddressMap<Vec<u64>> = AddressMap::default();

        let ids =
            get_sender_policy_ids(&mut state, fee_token, TempoHardfork::default(), &mut cache)
                .expect("should resolve policy IDs");

        assert!(ids.contains(&compound_policy_id));
        assert!(ids.contains(&sender_sub_policy));
        assert!(
            !ids.contains(&recipient_sub_policy),
            "sender policy IDs should not contain recipient_sub_policy"
        );
    }

    /// mint_recipient_policy_id is never consulted for fee transfers,
    /// so it must be excluded from sender policy IDs.
    #[test]
    fn compound_policy_excludes_mint_recipient() {
        let fee_token = address!("20C0000000000000000000000000000000000001");
        let compound_policy_id: u64 = 5;
        let sender_sub: u64 = 3;
        let recipient_sub: u64 = 4;
        let mint_recipient_sub: u64 = 6;

        let provider = MockEthProvider::default().with_chain_spec(std::sync::Arc::unwrap_or_clone(
            tempo_chainspec::spec::MODERATO.clone(),
        ));

        let transfer_policy_id_packed =
            U256::from(compound_policy_id) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8);
        provider.add_account(
            fee_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([(
                tip20_slots::TRANSFER_POLICY_ID.into(),
                transfer_policy_id_packed,
            )]),
        );

        let registry = TIP403Registry::new();
        let policy_data = PolicyData {
            policy_type: ITIP403Registry::PolicyType::COMPOUND as u8,
            admin: Address::ZERO,
        };
        let base_slot = registry.policy_records[compound_policy_id].base.base_slot();
        let compound_slot = registry.policy_records[compound_policy_id]
            .compound
            .base_slot();
        let compound_encoded = U256::from(sender_sub)
            | (U256::from(recipient_sub) << 64)
            | (U256::from(mint_recipient_sub) << 128);

        provider.add_account(
            TIP403_REGISTRY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (base_slot.into(), policy_data.encode_to_slot()),
                (compound_slot.into(), compound_encoded),
            ]),
        );

        let mut state = provider.latest().unwrap();
        let mut cache: AddressMap<Vec<u64>> = AddressMap::default();

        let ids =
            get_sender_policy_ids(&mut state, fee_token, TempoHardfork::default(), &mut cache)
                .expect("should resolve policy IDs");

        assert!(
            !ids.contains(&mint_recipient_sub),
            "mint_recipient must be excluded from sender policy IDs"
        );
    }

    /// `get_recipient_policy_ids` returns the compound root and recipient sub-policy.
    #[test]
    fn recipient_policy_ids_includes_recipient_sub_policy() {
        let fee_token = address!("20C0000000000000000000000000000000000001");
        let compound_policy_id: u64 = 5;
        let sender_sub: u64 = 3;
        let recipient_sub: u64 = 4;

        let provider = MockEthProvider::default().with_chain_spec(std::sync::Arc::unwrap_or_clone(
            tempo_chainspec::spec::MODERATO.clone(),
        ));

        let transfer_policy_id_packed =
            U256::from(compound_policy_id) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8);
        provider.add_account(
            fee_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([(
                tip20_slots::TRANSFER_POLICY_ID.into(),
                transfer_policy_id_packed,
            )]),
        );

        let registry = TIP403Registry::new();
        let policy_data = PolicyData {
            policy_type: ITIP403Registry::PolicyType::COMPOUND as u8,
            admin: Address::ZERO,
        };
        let base_slot = registry.policy_records[compound_policy_id].base.base_slot();
        let compound_slot = registry.policy_records[compound_policy_id]
            .compound
            .base_slot();
        let compound_encoded = U256::from(sender_sub) | (U256::from(recipient_sub) << 64);

        provider.add_account(
            TIP403_REGISTRY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (base_slot.into(), policy_data.encode_to_slot()),
                (compound_slot.into(), compound_encoded),
            ]),
        );

        let mut state = provider.latest().unwrap();
        let ids = get_recipient_policy_ids(&mut state, fee_token, TempoHardfork::default())
            .expect("should resolve policy IDs");

        assert!(
            ids.contains(&compound_policy_id),
            "should contain compound policy ID"
        );
        assert!(
            ids.contains(&recipient_sub),
            "should contain recipient sub-policy"
        );
        assert!(
            !ids.contains(&sender_sub),
            "recipient policy IDs should not contain sender sub-policy"
        );
    }

    /// For simple (non-compound) policies, `get_recipient_policy_ids` returns just the root.
    #[test]
    fn recipient_policy_ids_simple_policy() {
        let fee_token = address!("20C0000000000000000000000000000000000001");
        let simple_policy_id: u64 = 7;

        let provider = MockEthProvider::default().with_chain_spec(std::sync::Arc::unwrap_or_clone(
            tempo_chainspec::spec::MODERATO.clone(),
        ));

        let transfer_policy_id_packed =
            U256::from(simple_policy_id) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8);
        provider.add_account(
            fee_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([(
                tip20_slots::TRANSFER_POLICY_ID.into(),
                transfer_policy_id_packed,
            )]),
        );

        let registry = TIP403Registry::new();
        let policy_data = PolicyData {
            policy_type: ITIP403Registry::PolicyType::BLACKLIST as u8,
            admin: Address::ZERO,
        };
        let base_slot = registry.policy_records[simple_policy_id].base.base_slot();

        provider.add_account(
            TIP403_REGISTRY_ADDRESS,
            ExtendedAccount::new(0, U256::ZERO)
                .extend_storage([(base_slot.into(), policy_data.encode_to_slot())]),
        );

        let mut state = provider.latest().unwrap();
        let ids = get_recipient_policy_ids(&mut state, fee_token, TempoHardfork::default())
            .expect("should resolve policy IDs");

        assert_eq!(ids, vec![simple_policy_id]);
    }

    #[test]
    fn exceeds_spending_limit_returns_true_when_cost_exceeds_remaining() {
        let account = Address::random();
        let key_id = Address::random();
        let fee_token = Address::random();
        let subject = KeychainSubject {
            account,
            key_id,
            fee_token,
        };

        let mut state = provider_with_spending_limit(
            account,
            key_id,
            fee_token,
            alloy_primitives::U256::from(100),
        );

        assert!(exceeds_spending_limit(
            &mut state,
            &subject,
            alloy_primitives::U256::from(200)
        ));
    }

    #[test]
    fn exceeds_spending_limit_returns_false_when_cost_within_limit() {
        let account = Address::random();
        let key_id = Address::random();
        let fee_token = Address::random();
        let subject = KeychainSubject {
            account,
            key_id,
            fee_token,
        };

        let mut state = provider_with_spending_limit(
            account,
            key_id,
            fee_token,
            alloy_primitives::U256::from(500),
        );

        assert!(!exceeds_spending_limit(
            &mut state,
            &subject,
            alloy_primitives::U256::from(200)
        ));
    }

    #[test]
    fn exceeds_spending_limit_returns_true_when_no_limit_set() {
        let account = Address::random();
        let key_id = Address::random();
        let fee_token = Address::random();
        let subject = KeychainSubject {
            account,
            key_id,
            fee_token,
        };

        // Provider with AuthorizedKey (enforce_limits=true) but no spending limit slot
        let provider = MockEthProvider::default().with_chain_spec(std::sync::Arc::unwrap_or_clone(
            tempo_chainspec::spec::MODERATO.clone(),
        ));
        let key_slot = AccountKeychain::new().keys[account][key_id].base_slot();
        let authorized_key = AuthorizedKey {
            signature_type: 0,
            expiry: u64::MAX,
            enforce_limits: true,
            is_revoked: false,
        }
        .encode_to_slot();
        provider.add_account(
            ACCOUNT_KEYCHAIN_ADDRESS,
            ExtendedAccount::new(0, alloy_primitives::U256::ZERO)
                .extend_storage([(key_slot.into(), authorized_key)]),
        );
        let mut state = provider.latest().unwrap();

        assert!(exceeds_spending_limit(
            &mut state,
            &subject,
            alloy_primitives::U256::from(1)
        ));
    }

    #[test]
    fn exceeds_spending_limit_returns_false_when_limits_not_enforced() {
        let account = Address::random();
        let key_id = Address::random();
        let fee_token = Address::random();
        let subject = KeychainSubject {
            account,
            key_id,
            fee_token,
        };

        // Provider with AuthorizedKey (enforce_limits=false)
        let provider = MockEthProvider::default().with_chain_spec(std::sync::Arc::unwrap_or_clone(
            tempo_chainspec::spec::MODERATO.clone(),
        ));
        let key_slot = AccountKeychain::new().keys[account][key_id].base_slot();
        let authorized_key = AuthorizedKey {
            signature_type: 0,
            expiry: u64::MAX,
            enforce_limits: false,
            is_revoked: false,
        }
        .encode_to_slot();
        provider.add_account(
            ACCOUNT_KEYCHAIN_ADDRESS,
            ExtendedAccount::new(0, alloy_primitives::U256::ZERO)
                .extend_storage([(key_slot.into(), authorized_key)]),
        );
        let mut state = provider.latest().unwrap();

        assert!(!exceeds_spending_limit(
            &mut state,
            &subject,
            alloy_primitives::U256::from(1)
        ));
    }
}
