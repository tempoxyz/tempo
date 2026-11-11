// Tempo transaction pool that implements Reth's TransactionPool trait
// Routes protocol nonces (nonce_key=0) to Reth pool
// Routes user nonces (nonce_key>0) to minimal 2D nonce pool

use crate::{
    amm::AmmLiquidityCache,
    best::MergeBestTransactions,
    delayed_pool::DelayedPool,
    ordering::TempoTipOrdering,
    transaction::TempoPooledTransaction,
    tt_2d_pool::AA2dPool,
    validator::{ConfigureTempoPoolEvm, TempoTransactionValidator},
};
use alloy_consensus::Transaction;
use alloy_primitives::{
    Address, B256, TxHash, U256,
    map::{AddressMap, AddressSet, B256Set, Entry, HashMap},
};
use parking_lot::RwLock;
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_eth_wire_types::HandleMempoolData;
use reth_provider::{ChangedAccount, StateProviderFactory};
use reth_storage_api::StateProvider;
use reth_transaction_pool::{
    AddedTransactionOutcome, AllPoolTransactions, BestTransactions, BestTransactionsAttributes,
    BlockInfo, CanonicalStateUpdate, GetPooledTransactionLimit, NewBlobSidecar, Pool, PoolResult,
    PoolSize, PoolTransaction, PropagatedTransactions, SubPool, TransactionEvents,
    TransactionOrigin, TransactionPool, TransactionPoolExt, TransactionValidationOutcome,
    TransactionValidationTaskExecutor, TransactionValidator, ValidPoolTransaction,
    blobstore::InMemoryBlobStore,
    error::{PoolError, PoolErrorKind},
    identifier::TransactionId,
    pool::{AddedPendingTransaction, AddedTransaction, AddedTransactionState, QueuedReason},
};
use reth_trie_common::bundle_state::BundleAccount;
use std::{sync::Arc, time::Instant};
use tempo_chainspec::hardfork::{TempoHardfork, TempoHardforks};
use tempo_evm::{TempoEvmConfig, TempoStateAccess};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    error::Result as TempoPrecompileResult,
    storage::{Handler, StorageActions},
    tip20::TIP20Token,
    tip403_registry::{REJECT_ALL_POLICY_ID, TIP403Registry},
};
use tempo_primitives::{Block, TempoHeader};

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
    /// Minimal pool for 2D nonces (nonce_key > 0), including the held expiring nonce
    /// transactions that are not valid yet.
    aa_2d_pool: Arc<RwLock<AA2dPool>>,
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
        delayed_pool: DelayedPool,
    ) -> Self {
        aa_2d_pool.set_base_fee(protocol_pool.inner().block_info().pending_basefee);
        aa_2d_pool.set_delayed(delayed_pool);
        Self {
            protocol_pool,
            aa_2d_pool: Arc::new(RwLock::new(aa_2d_pool)),
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

    /// Returns the best transactions whose time bounds and keychain key expiry permit inclusion
    /// at `timestamp`.
    ///
    /// AA transactions outside their validity window or signed with a keychain key that has
    /// expired by `timestamp`, and their nonce-dependent successors, are skipped for this
    /// iterator only. Future-valid transactions remain in the pool for later blocks. Apply this
    /// filter before prewarming so skipped transactions are never prewarmed.
    pub fn best_transactions_for_block(
        &self,
        attributes: BestTransactionsAttributes,
        timestamp: u64,
    ) -> impl BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>
    + use<Client, EvmConfig> {
        self.best_transactions_with_attributes(attributes)
            .filter_transactions(move |tx| tx.transaction.is_includable_at(timestamp))
    }

    /// Returns the configured client
    pub fn client(&self) -> &Client {
        self.protocol_pool.validator().validator().client()
    }

    /// Returns the timestamp of the tip the validator last saw.
    fn tip_timestamp(&self) -> u64 {
        self.protocol_pool
            .validator()
            .validator()
            .inner
            .fork_tracker()
            .tip_timestamp()
    }

    /// Moves held transactions whose `valid_after` is within the lead time of `tip_timestamp`
    /// into the live sub-pools.
    ///
    /// Each one is revalidated against current state with validation caches discarded and
    /// inserted with the live pool's limits and replacement rules applied. It is dropped, with a
    /// discarded event, if it fails revalidation or the live pool rejects it. Called by pool
    /// maintenance on each new block.
    pub(crate) async fn release_delayed_transactions(&self, tip_timestamp: u64) {
        let due = self
            .aa_2d_pool
            .write()
            .delayed_mut()
            .take_due(tip_timestamp);
        if due.is_empty() {
            return;
        }

        let outcomes = self
            .protocol_pool
            .validator()
            .validate_transactions(
                due.iter()
                    .map(|tx| (tx.origin, tx.transaction.with_discarded_caches()))
                    .collect::<Vec<_>>(),
            )
            .await;

        let mut released = 0;
        let mut discarded = Vec::new();
        for (held, outcome) in due.into_iter().zip(outcomes) {
            let hash = *held.hash();
            if !outcome.is_valid() {
                // Skipped if it was removed, for example by eviction, while it was revalidated.
                if self
                    .aa_2d_pool
                    .write()
                    .delayed_mut()
                    .remove(&hash)
                    .is_some()
                {
                    discarded.push(held);
                }
                continue;
            }

            match self.insert_validated_transaction(held.origin, outcome, Some(hash)) {
                Ok(Some(_)) => released += 1,
                // Removed while it was revalidated.
                Ok(None) => {}
                // Listeners were notified by the insert.
                Err(err) if matches!(err.kind, PoolErrorKind::DiscardedOnInsert) => {}
                Err(_) => discarded.push(held),
            }
        }

        {
            let aa_2d_pool = self.aa_2d_pool.read();
            let metrics = aa_2d_pool.delayed().metrics();
            metrics.released_transactions.increment(released);
            metrics
                .discarded_on_release
                .increment(discarded.len() as u64);
        }

        if !discarded.is_empty() {
            self.protocol_pool
                .inner()
                .notify_on_transaction_updates(Vec::new(), discarded);
        }
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

    /// Evicts transactions that are no longer valid due to on-chain events.
    ///
    /// This performs a single scan of all pooled transactions and checks for:
    /// 1. **Revoked keychain keys**: AA transactions signed with keys that have been revoked
    /// 2. **Spending limit updates**: AA transactions signed with keys whose spending limit
    ///    changed for a token matching the transaction's fee token
    ///    2b. **Spending limit spends**: AA transactions whose remaining spending limit (re-read
    ///    from state) is now insufficient after included keychain txs decremented it
    ///    2c. **Key-authorization witness burns**: AA transactions with a witness-bearing
    ///    inline key authorization whose `(account, witness)` has been manually burned
    /// 3. **Validator token changes**: Transactions that would fail due to insufficient
    ///    liquidity in the new (user_token, validator_token) AMM pool
    /// 4. **Fee payer balance changes**: Transactions whose fee payer no longer has enough
    ///    balance in the resolved fee token after a TIP20 transfer
    /// 5. **Fee token pauses**: Transactions using a token paused in the committed block
    ///
    /// All checks are combined into one scan to avoid iterating the pool multiple times
    /// per block.
    pub fn evict_invalidated_transactions(
        &self,
        updates: &crate::maintain::TempoPoolUpdates,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        if !updates.has_invalidation_events() {
            return Vec::new();
        }

        let all_txs = self.all_transactions();
        self.evict_invalidated_transactions_from(updates, all_txs.iter(), None)
    }

    /// See [`Self::evict_invalidated_transactions`]; returns the removed transactions so
    /// the caller controls when they are dropped.
    pub(crate) fn evict_invalidated_transactions_from<'a>(
        &self,
        updates: &crate::maintain::TempoPoolUpdates,
        transactions: impl IntoIterator<Item = &'a Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        expiry_cutoff: Option<u64>,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        if !updates.has_invalidation_events() && expiry_cutoff.is_none() {
            return Vec::new();
        }

        // Fetch state provider if any check needs on-chain reads:
        // - validator token changes (liquidity check)
        // - blacklist/whitelist (policy check)
        // - fee payer balance changes (balance check)
        // - spending limit spends (remaining limit check)
        let mut state_provider = if !updates.validator_token_changes.is_empty()
            || !updates.blacklist_additions.is_empty()
            || !updates.whitelist_removals.is_empty()
            || !updates.fee_balance_changes.is_empty()
            || !updates.spending_limit_spends.is_empty()
        {
            self.client().latest().ok()
        } else {
            None
        };

        // Resolve the active hardfork for storage context.
        let tip_timestamp = self.tip_timestamp();
        let spec = self.protocol_pool.validator().validator().active_hardfork();

        // Cache policy lookups per fee token to avoid redundant storage reads.
        // For compound policies (TIP-1015), the cache stores all sub-policy IDs
        // so eviction matches events emitted with sub-policy IDs.
        let mut policy_cache: AddressMap<Vec<u64>> = AddressMap::default();

        // Pre-T8 fee collection checked TIP_FEE_MANAGER_ADDRESS as the fee-token recipient.
        // TIP-1042 exempts that recipient side, so T8+ invalidation only tracks fee-payer sender
        // authorization.
        let is_t8 = spec.is_t8();
        // NOTE: We can remove this logic after T8 activation
        let (fee_manager_blacklisted, fee_manager_unwhitelisted): (Vec<u64>, Vec<u64>) = if !is_t8 {
            (
                updates
                    .blacklist_additions
                    .iter()
                    .filter(|(_, account)| *account == TIP_FEE_MANAGER_ADDRESS)
                    .map(|(policy_id, _)| *policy_id)
                    .collect(),
                updates
                    .whitelist_removals
                    .iter()
                    .filter(|(_, account)| *account == TIP_FEE_MANAGER_ADDRESS)
                    .map(|(policy_id, _)| *policy_id)
                    .collect(),
            )
        } else {
            (Vec::new(), Vec::new())
        };

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
        let mut key_authorization_target_count = 0;
        let mut spending_limit_count = 0;
        let mut spending_limit_spend_count = 0;
        let mut key_authorization_witness_count = 0;
        let mut liquidity_count = 0;
        let mut user_token_count = 0;
        let mut blacklisted_count = 0;
        let mut unwhitelisted_count = 0;
        let mut insolvent_fee_payer_count = 0;
        let mut paused_token_count = 0;
        let has_paused_tokens = !updates.paused_tokens.is_empty();
        let has_keychain_subject_updates = updates.has_keychain_subject_updates();
        let has_key_authorization_target_updates =
            !updates.key_authorization_target_changes.is_empty();
        let mut fee_balance_cache: HashMap<(Address, Address), U256> = HashMap::default();

        for tx in transactions {
            if expiry_cutoff.is_some_and(|cutoff| tx.transaction.is_expired_by(cutoff)) {
                #[cfg(feature = "fuzz")]
                antithesis_sdk::assert_reachable!(
                    "Pool maintenance evicts a transaction past its valid_before or key expiry"
                );
                to_remove.push(*tx.hash());
                continue;
            }

            if has_paused_tokens
                && updates
                    .paused_tokens
                    .contains(&tx.transaction.effective_fee_token())
            {
                to_remove.push(*tx.hash());
                paused_token_count += 1;
                continue;
            }

            // Avoid recovering key ids unless a keychain invalidation can use them.
            if has_keychain_subject_updates || has_key_authorization_target_updates {
                let keychain_subject = has_keychain_subject_updates
                    .then(|| tx.transaction.keychain_subject())
                    .flatten();
                let key_authorization_subject = (!updates.revoked_keys.is_empty())
                    .then(|| tx.transaction.key_authorization_signer_subject())
                    .flatten();
                let key_authorization_target = has_key_authorization_target_updates
                    .then(|| tx.transaction.key_authorization_target_subject())
                    .flatten();

                // Check 1: Revoked keychain keys
                if !updates.revoked_keys.is_empty()
                    && (keychain_subject
                        .as_ref()
                        .is_some_and(|subject| subject.matches_revoked(&updates.revoked_keys))
                        || key_authorization_subject
                            .as_ref()
                            .is_some_and(|subject| subject.matches_revoked(&updates.revoked_keys)))
                {
                    to_remove.push(*tx.hash());
                    revoked_count += 1;
                    continue;
                }

                // Check 1b: Inline key authorization target status changes
                if !updates.key_authorization_target_changes.is_empty()
                    && key_authorization_target.as_ref().is_some_and(|subject| {
                        subject.matches_key_update(&updates.key_authorization_target_changes)
                    })
                {
                    to_remove.push(*tx.hash());
                    key_authorization_target_count += 1;
                    continue;
                }

                // Check 2: Spending limit updates
                // Only evict if the transaction's fee token matches the token whose limit changed.
                if !updates.spending_limit_changes.is_empty()
                    && let Some(ref subject) = keychain_subject
                    && subject.matches_spending_limit_update(&updates.spending_limit_changes)
                    && tx.transaction.is_sender_paid_fee()
                {
                    to_remove.push(*tx.hash());
                    spending_limit_count += 1;
                    continue;
                }

                // Check 2b: Spending limit spends
                // AccessKeySpend receipt logs identify the exact (account, key_id, token)
                // triples whose remaining limit changed during execution. We re-read the
                // current remaining limit from state for matching pending txs and evict if
                // the tx's fee cost now exceeds that remaining limit.
                if !updates.spending_limit_spends.is_empty()
                    && let Some(ref subject) = keychain_subject
                    && subject.matches_spending_limit_update(&updates.spending_limit_spends)
                    && tx.transaction.is_sender_paid_fee()
                    && let Some(ref mut provider) = state_provider
                    && exceeds_spending_limit(
                        provider,
                        subject,
                        tx.transaction.fee_token_cost(),
                        tip_timestamp,
                        spec,
                    )
                {
                    to_remove.push(*tx.hash());
                    spending_limit_spend_count += 1;
                    continue;
                }
            }

            // Check 2c: TIP-1053 key-authorization witness burns
            if !updates.key_authorization_witness_burns.is_empty()
                && let Some(subject) = tx.transaction.key_authorization_witness_subject()
                && updates
                    .key_authorization_witness_burns
                    .get(&subject.account)
                    .is_some_and(|witnesses| witnesses.contains(&subject.witness))
            {
                to_remove.push(*tx.hash());
                key_authorization_witness_count += 1;
                continue;
            }

            // Check 3: Validator token changes (re-check liquidity for all transactions)
            // Prevents mass eviction because it only:
            // - evicts when NO validator token has enough liquidity
            // - considers active validators (protects from permissionless `setValidatorToken`)
            if has_active_validator_token_changes && let Some(ref provider) = state_provider {
                let user_token = tx.transaction.effective_fee_token();
                let cost = tx.transaction.fee_token_cost();

                match amm_cache.has_enough_liquidity(user_token, cost, provider) {
                    Ok(true) => {}
                    Ok(false) => {
                        to_remove.push(*tx.hash());
                        liquidity_count += 1;
                        continue;
                    }
                    Err(_) => continue,
                }
            }

            // Check 3b: Fee payer balance changes.
            // When a TIP20 transfer changes a fee payer's balance, pending transactions for that
            // (fee_token, fee_payer) pair may no longer be executable.
            if !updates.fee_balance_changes.is_empty()
                && let Some(ref mut provider) = state_provider
            {
                let fee_token = tx.transaction.effective_fee_token();
                // only resolve the fee payer if the fee token saw balance changes
                if let Some(accounts) = updates.fee_balance_changes.get(&fee_token) {
                    let Ok(fee_payer) = tx.transaction.fee_payer() else {
                        continue;
                    };

                    if accounts.contains(&fee_payer) {
                        let balance = match fee_balance_cache.entry((fee_token, fee_payer)) {
                            Entry::Occupied(entry) => *entry.get(),
                            Entry::Vacant(entry) => {
                                let Ok(balance) = provider.get_token_balance(
                                    fee_token,
                                    fee_payer,
                                    spec,
                                    StorageActions::disabled(),
                                ) else {
                                    continue;
                                };
                                *entry.insert(balance)
                            }
                        };

                        if balance < tx.transaction.fee_token_cost() {
                            to_remove.push(*tx.hash());
                            insolvent_fee_payer_count += 1;
                            continue;
                        }
                    }
                }
            }

            // Check 4: Blacklisted fee payers.
            // AA transactions use their recovered fee payer; non-AA transactions use their sender.
            if !updates.blacklist_additions.is_empty()
                && let Some(ref mut provider) = state_provider
            {
                let fee_token = tx.transaction.effective_fee_token();
                let fee_payer = tx
                    .transaction
                    .fee_payer()
                    .unwrap_or_else(|_| tx.transaction.sender());

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

            // Check 5: Un-whitelisted fee payers.
            // When a fee payer or sender is removed from a whitelist, their pending
            // transactions will fail validation at execution time.
            if !updates.whitelist_removals.is_empty()
                && let Some(ref mut provider) = state_provider
            {
                let fee_token = tx.transaction.effective_fee_token();
                let fee_payer = tx
                    .transaction
                    .fee_payer()
                    .unwrap_or_else(|_| tx.transaction.sender());

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
            // When a fee payer changes their fee token preference via setUserToken(),
            // transactions paid by that account that don't have an explicit fee_token set may
            // now resolve to a different token at execution time, causing fee payment failures.
            // Only evict transactions WITHOUT an explicit fee_token (those that rely on storage).
            if !updates.user_token_changes.is_empty()
                && tx.transaction.inner().fee_token().is_none()
                && tx
                    .transaction
                    .fee_payer()
                    .is_ok_and(|fee_payer| updates.user_token_changes.contains(&fee_payer))
            {
                to_remove.push(*tx.hash());
                user_token_count += 1;
            }
        }

        if to_remove.is_empty() {
            return Vec::new();
        }

        tracing::debug!(
            target: "txpool",
            total = to_remove.len(),
            revoked_count,
            key_authorization_target_count,
            spending_limit_count,
            spending_limit_spend_count,
            key_authorization_witness_count,
            liquidity_count,
            user_token_count,
            blacklisted_count,
            unwhitelisted_count,
            insolvent_fee_payer_count,
            paused_token_count,
            "Evicting invalidated or expired transactions"
        );
        self.remove_transactions(to_remove)
    }

    /// Removes held transactions whose expiring nonce the committed `state` marks as seen and
    /// returns them. The live 2D pool drops such transactions in the same block.
    ///
    /// Listeners see the ones in `mined`, the block's transaction hashes, as mined through
    /// reth's canonical update, so only the others are notified as discarded.
    pub(crate) fn remove_consumed_delayed_transactions(
        &self,
        state: &AddressMap<BundleAccount>,
        mined: &B256Set,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut removed = Vec::new();
        let (included, discarded) = self
            .aa_2d_pool
            .write()
            .delayed_mut()
            .remove_consumed(state)
            .into_iter()
            .partition(|tx| mined.contains(tx.hash()));
        self.notify_held_removed(&mut removed, discarded);
        removed.extend(included);
        removed
    }

    /// Holds a validated expiring nonce transaction in the delayed sub-pool until `valid_after`.
    ///
    /// Event listeners see it as queued. It still fires the pending transaction notification, which
    /// is how reth's network learns to announce it to peers, so pending hash subscribers see it
    /// before its `valid_after`.
    fn hold_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: TempoPooledTransaction,
        propagate: bool,
        authorities: Option<Vec<Address>>,
        valid_after: u64,
    ) -> PoolResult<AddedTransactionOutcome> {
        let hash = *transaction.hash();
        if self.protocol_pool.contains(&hash) {
            return Err(PoolError::new(hash, PoolErrorKind::AlreadyImported));
        }

        let protocol_pool = self.protocol_pool.inner();
        let transaction_id = TransactionId::new(
            protocol_pool.get_sender_id(transaction.sender()),
            transaction.nonce(),
        );
        let tx = Arc::new(ValidPoolTransaction {
            transaction,
            transaction_id,
            propagate,
            timestamp: Instant::now(),
            origin,
            authority_ids: authorities
                .as_ref()
                .map(|auths| protocol_pool.get_sender_ids(auths.iter().copied())),
        });
        let evicted = self
            .aa_2d_pool
            .write()
            .hold_transaction(Arc::clone(&tx), valid_after)?;

        protocol_pool.on_new_pending_transaction(&AddedPendingTransaction {
            transaction: Arc::clone(&tx),
            replaced: None,
            promoted: Vec::new(),
            discarded: Vec::new(),
        });
        let added = AddedTransaction::Parked {
            transaction: tx,
            replaced: None,
            subpool: SubPool::Queued,
            queued_reason: None,
            promoted: Vec::new(),
        };
        protocol_pool.notify_event_listeners(&added);
        protocol_pool.on_new_transaction(added.into_new_transaction_event());
        if !evicted.is_empty() {
            protocol_pool.notify_on_transaction_updates(Vec::new(), evicted);
        }

        // Reth has no queued reason for a transaction that is not valid yet.
        Ok(AddedTransactionOutcome {
            hash,
            state: AddedTransactionState::Queued(QueuedReason::ParkedAncestors),
        })
    }

    /// Notifies listeners that the held transactions were removed and appends them to `removed`.
    fn notify_held_removed(
        &self,
        removed: &mut Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        held: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    ) {
        if held.is_empty() {
            return;
        }
        self.protocol_pool
            .inner()
            .notify_on_transaction_updates(Vec::new(), held.clone());
        removed.extend(held);
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
        self.insert_validated_transaction(origin, transaction, None)
            .map(|added| added.expect("only a release skips the insert"))
    }

    /// Adds a validated transaction like [`Self::add_validated_transaction`], first taking
    /// the held transaction `release` out of the delayed sub-pool, if given.
    ///
    /// A released 2D transaction leaves the held set under the same lock that adds it live, so no
    /// other admission can take its hash or expiring nonce in between. Returns `None` without
    /// inserting if `release` is no longer held.
    fn insert_validated_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: TransactionValidationOutcome<TempoPooledTransaction>,
        release: Option<TxHash>,
    ) -> PoolResult<Option<AddedTransactionOutcome>> {
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
                    let (added, mut discarded) = {
                        let mut aa_2d_pool = self.aa_2d_pool.write();
                        if let Some(held) = release
                            && aa_2d_pool.delayed_mut().remove(&held).is_none()
                        {
                            return Ok(None);
                        }
                        let mut added = aa_2d_pool.add_transaction(tx, state_nonce, hardfork)?;
                        // Taken so `notify_event_listeners` doesn't report them a second time.
                        let discarded = match &mut added {
                            AddedTransaction::Pending(pending) => {
                                std::mem::take(&mut pending.discarded)
                            }
                            AddedTransaction::Parked { .. } => aa_2d_pool.discard(),
                        };
                        (added, discarded)
                    };
                    let hash = *added.hash();
                    if discarded.iter().any(|tx| *tx.hash() == hash) {
                        // The insert's own events are skipped, so the transaction it replaced is
                        // reported as discarded instead.
                        discarded.extend(added.replaced().cloned());
                        self.protocol_pool
                            .inner()
                            .notify_on_transaction_updates(Vec::new(), discarded);
                        return Err(PoolError::new(hash, PoolErrorKind::DiscardedOnInsert));
                    }
                    if let Some(pending) = added.as_pending() {
                        self.protocol_pool
                            .inner()
                            .on_new_pending_transaction(pending);
                    }

                    let state = added.transaction_state();
                    // notify regular event listeners from the protocol pool
                    self.protocol_pool.inner().notify_event_listeners(&added);
                    // Sent after the insert's events so a promoted transaction that was evicted
                    // again ends as discarded.
                    if !discarded.is_empty() {
                        self.protocol_pool
                            .inner()
                            .notify_on_transaction_updates(Vec::new(), discarded);
                    }
                    self.protocol_pool
                        .inner()
                        .on_new_transaction(added.into_new_transaction_event());

                    Ok(Some(AddedTransactionOutcome { hash, state }))
                } else {
                    if let Some(held) = release
                        && self
                            .aa_2d_pool
                            .write()
                            .delayed_mut()
                            .remove(&held)
                            .is_none()
                    {
                        return Ok(None);
                    }
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
                        .map(Some)
                }
            }
            invalid => {
                // this forwards for event listener updates
                self.protocol_pool
                    .inner()
                    .add_transactions(origin, Some(invalid))
                    .pop()
                    .unwrap()
                    .map(Some)
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
        let delayed_pool = aa_2d_pool.delayed();
        size.queued += delayed_pool.len();
        size.queued_size += delayed_pool.size();
        size.total += delayed_pool.len();
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

        // Fully delegate to the protocol pool unless a transaction is 2D, which includes every
        // transaction that may be held.
        if !transactions.iter().any(|(_, tx)| tx.is_aa_2d()) {
            return self
                .protocol_pool
                .add_transactions_with_origins(transactions)
                .await;
        }

        // Held transactions are validated again like live ones, so a resubmitted one that is no
        // longer valid reports why instead of being known already.
        let origins = transactions
            .iter()
            .map(|(origin, _)| *origin)
            .collect::<Vec<_>>();
        let outcomes = self
            .protocol_pool
            .validator()
            .validate_transactions(transactions)
            .await;
        let tip_timestamp = self.tip_timestamp();

        outcomes
            .into_iter()
            .zip(origins)
            .map(|(outcome, origin)| {
                let valid_after = match &outcome {
                    TransactionValidationOutcome::Valid { transaction, .. } => self
                        .aa_2d_pool
                        .read()
                        .delayed()
                        .hold_until(transaction.transaction(), tip_timestamp),
                    _ => None,
                };
                match (outcome, valid_after) {
                    (
                        TransactionValidationOutcome::Valid {
                            transaction,
                            propagate,
                            authorities,
                            ..
                        },
                        Some(valid_after),
                    ) => self.hold_transaction(
                        origin,
                        transaction.into_transaction(),
                        propagate,
                        authorities,
                        valid_after,
                    ),
                    // The 2D pool rejects a transaction that is held already.
                    (outcome, _) => self.add_validated_transaction(origin, outcome),
                }
            })
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
        hashes.extend(
            self.aa_2d_pool
                .read()
                .delayed()
                .pooled_transactions()
                .map(|tx| *tx.hash()),
        );
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
        let remaining = max - hashes.len();
        hashes.extend(
            self.aa_2d_pool
                .read()
                .delayed()
                .pooled_transactions()
                .map(|tx| *tx.hash())
                .take(remaining),
        );
        hashes
    }

    fn pooled_transactions(&self) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self.protocol_pool.pooled_transactions();
        txs.extend(self.aa_2d_pool.read().pooled_transactions_iter());
        txs.extend(
            self.aa_2d_pool
                .read()
                .delayed()
                .pooled_transactions()
                .cloned(),
        );
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
        let remaining = max - txs.len();
        txs.extend(
            self.aa_2d_pool
                .read()
                .delayed()
                .pooled_transactions()
                .take(remaining)
                .cloned(),
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
        if !limit.exceeds(accumulated_size) {
            self.aa_2d_pool
                .read()
                .delayed()
                .append_pooled_transaction_elements(tx_hashes, limit, &mut accumulated_size, out);
        }

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
            .or_else(|| {
                self.aa_2d_pool
                    .read()
                    .delayed()
                    .get(&tx_hash)
                    .filter(|tx| tx.propagate)
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
        // Held transactions are left out: reth's maintenance evicts external queued transactions
        // older than its queued lifetime, which a held transaction can reach before release.
        queued.extend(self.aa_2d_pool.read().queued_transactions());
        queued
    }

    fn pending_and_queued_txn_count(&self) -> (usize, usize) {
        let (protocol_pending, protocol_queued) = self.protocol_pool.pending_and_queued_txn_count();
        let (aa_pending, aa_queued) = self.aa_2d_pool.read().pending_and_queued_txn_count();
        let delayed = self.aa_2d_pool.read().delayed().len();
        (
            protocol_pending + aa_pending,
            protocol_queued + aa_queued + delayed,
        )
    }

    fn all_transactions(&self) -> AllPoolTransactions<Self::Transaction> {
        let mut transactions = self.protocol_pool.all_transactions();
        self.aa_2d_pool
            .read()
            .append_all_transactions(&mut transactions);
        transactions
            .queued
            .extend(self.aa_2d_pool.read().delayed().transactions().cloned());
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
        transactions.queued.extend(
            self.aa_2d_pool
                .read()
                .delayed()
                .transactions()
                .filter(|tx| tx.sender() == sender)
                .cloned(),
        );
        transactions
    }

    fn all_transaction_hashes(&self) -> Vec<B256> {
        let mut hashes = self.protocol_pool.all_transaction_hashes();
        hashes.extend(self.aa_2d_pool.read().all_transaction_hashes_iter());
        hashes.extend(
            self.aa_2d_pool
                .read()
                .delayed()
                .transactions()
                .map(|tx| *tx.hash()),
        );
        hashes
    }

    fn remove_transactions(
        &self,
        hashes: Vec<B256>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let held = self
            .aa_2d_pool
            .write()
            .delayed_mut()
            .remove_transactions(hashes.iter());
        let mut txs = self.aa_2d_pool.write().remove_transactions(hashes.iter());
        txs.extend(self.protocol_pool.remove_transactions(hashes));
        self.notify_held_removed(&mut txs, held);
        txs
    }

    fn remove_transactions_and_descendants(
        &self,
        hashes: Vec<B256>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        // Held transactions use expiring nonces, so none descends from another transaction.
        let held = self
            .aa_2d_pool
            .write()
            .delayed_mut()
            .remove_transactions(hashes.iter());
        let mut txs = self
            .aa_2d_pool
            .write()
            .remove_transactions_and_descendants(hashes.iter());
        txs.extend(
            self.protocol_pool
                .remove_transactions_and_descendants(hashes),
        );
        self.notify_held_removed(&mut txs, held);
        txs
    }

    fn remove_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let held = self
            .aa_2d_pool
            .write()
            .delayed_mut()
            .remove_transactions_by_sender(sender);
        let mut txs = self
            .aa_2d_pool
            .write()
            .remove_transactions_by_sender(sender);
        txs.extend(self.protocol_pool.remove_transactions_by_sender(sender));
        self.notify_held_removed(&mut txs, held);
        txs
    }

    fn prune_transactions(
        &self,
        hashes: Vec<TxHash>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut txs = self
            .aa_2d_pool
            .write()
            .delayed_mut()
            .remove_transactions(hashes.iter());
        txs.extend(self.aa_2d_pool.write().remove_transactions(hashes.iter()));
        txs.extend(self.protocol_pool.prune_transactions(hashes));
        txs
    }

    fn retain_unknown<A: HandleMempoolData>(&self, announcement: &mut A) {
        self.protocol_pool.retain_unknown(announcement);
        if announcement.is_empty() {
            return;
        }
        let aa_pool = self.aa_2d_pool.read();
        let delayed_pool = aa_pool.delayed();
        announcement.retain_by_hash(|tx| !aa_pool.contains(tx) && !delayed_pool.contains(tx))
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
        self.protocol_pool.contains(tx_hash)
            || self.aa_2d_pool.read().contains(tx_hash)
            || self.aa_2d_pool.read().delayed().contains(tx_hash)
    }

    fn get(&self, tx_hash: &B256) -> Option<Arc<ValidPoolTransaction<Self::Transaction>>> {
        self.protocol_pool
            .get(tx_hash)
            .or_else(|| self.aa_2d_pool.read().get(tx_hash))
            .or_else(|| self.aa_2d_pool.read().delayed().get(tx_hash))
    }

    fn get_all(&self, txs: Vec<B256>) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        let mut result = {
            let aa_2d_pool = self.aa_2d_pool.read();
            let delayed_pool = aa_2d_pool.delayed();
            let mut result = aa_2d_pool.get_all(txs.iter());
            result.extend(txs.iter().filter_map(|hash| delayed_pool.get(hash)));
            result
        };
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
        txs.extend(
            self.aa_2d_pool
                .read()
                .delayed()
                .transactions()
                .filter(|tx| tx.sender() == sender)
                .cloned(),
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
        txs.extend(
            self.aa_2d_pool
                .read()
                .delayed()
                .transactions()
                .filter(|tx| tx.sender() == sender)
                .cloned(),
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
        txs.extend(
            self.aa_2d_pool
                .read()
                .delayed()
                .transactions()
                .filter(|tx| tx.origin == origin)
                .cloned(),
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
        senders.extend(
            self.aa_2d_pool
                .read()
                .delayed()
                .transactions()
                .map(|tx| tx.sender()),
        );
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

/// Checks whether a pending keychain tx exceeds its effective remaining spending limit.
///
/// Re-reads the current limit from state for the tx's `(account, key_id, fee_token)` combo,
/// including any T3 periodic-limit rollover at `current_timestamp`. Returns true if the tx's
/// fee cost exceeds the effective remaining limit, meaning it should be evicted.
pub(crate) fn exceeds_spending_limit(
    provider: &mut impl StateProvider,
    subject: &crate::transaction::KeychainSubject,
    fee_token_cost: alloy_primitives::U256,
    current_timestamp: u64,
    spec: TempoHardfork,
) -> bool {
    provider
        .with_read_only_storage_ctx(
            spec,
            StorageActions::disabled(),
            || -> TempoPrecompileResult<bool> {
                let keychain = AccountKeychain::new();
                let key = keychain.keys[subject.account][subject.key_id].read()?;
                if !key.enforce_limits {
                    return Ok(false);
                }

                let remaining = keychain.effective_remaining_limit_with_key(
                    subject.account,
                    subject.key_id,
                    subject.fee_token,
                    current_timestamp,
                    &key,
                )?;
                Ok(fee_token_cost > remaining)
            },
        )
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

    provider.with_read_only_storage_ctx(spec, StorageActions::disabled(), || {
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
/// pre-T8 fee transfer authorization checks the fee manager via `AuthRole::Recipient`.
/// T8+ fee collection exempts the FeeManager recipient side, so this returns `None`.
///
/// Unlike `get_sender_policy_ids` this is uncached — it's only called on the rare path
/// where the fee manager itself is blacklisted or un-whitelisted.
fn get_recipient_policy_ids(
    provider: &mut impl StateProvider,
    fee_token: Address,
    spec: TempoHardfork,
) -> Option<Vec<u64>> {
    if spec.is_t8() {
        return None;
    }

    provider.with_read_only_storage_ctx(spec, StorageActions::disabled(), || {
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
    /// Returns the hashes of the evicted transactions.
    fn tx_hashes(txs: &[Arc<ValidPoolTransaction<TempoPooledTransaction>>]) -> Vec<TxHash> {
        txs.iter().map(|tx| *tx.hash()).collect()
    }

    use crate::{
        test_utils::{MockProviderStorageExt, TxBuilder, wrap_valid_tx},
        transaction::KeychainSubject,
        tt_2d_pool::AA2dPoolConfig,
    };
    use alloy_consensus::Header;
    use alloy_primitives::{Signature, TxKind, U256, address, uint};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use futures::{FutureExt, StreamExt};
    use reth_primitives_traits::{InMemorySize, Recovered, SealedBlock};
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_storage_api::StateProviderFactory;
    use reth_transaction_pool::{
        AllTransactionsEvents, FullTransactionEvent, PoolConfig, PoolUpdateKind, SubPoolLimit,
        TransactionOrigin, TransactionPool, TransactionValidationTaskExecutor,
        blobstore::InMemoryBlobStore,
        validate::{EthTransactionValidatorBuilder, ValidTransaction},
    };
    use tempo_chainspec::{
        TempoChainSpec,
        hardfork::TempoHardfork,
        spec::{DEV, MODERATO, TEMPO_T1_TX_GAS_LIMIT_CAP},
    };
    use tempo_contracts::precompiles::ITIP403Registry;
    use tempo_evm::{ResolvedFeeToken, TempoEvmConfig};
    use tempo_precompiles::{
        PATH_USD_ADDRESS,
        account_keychain::{
            AccountKeychain, AuthorizedKey, SpendingLimitState, StoredSignatureType,
        },
        tip20::slots as tip20_slots,
        tip403_registry::{CompoundPolicyData, PolicyData, TIP403Registry},
    };
    use tempo_primitives::{
        Block, TempoHeader, TempoPrimitives, TempoTxEnvelope,
        transaction::{
            KeyAuthorization, PrimitiveSignature, SignatureType, tempo_transaction::Call,
        },
    };

    use crate::delayed_pool;
    use reth_transaction_pool::TransactionListenerKind;
    use reth_trie_common::bundle_state::{AccountStatus, StorageSlot};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
    use tempo_primitives::TempoTxType;

    fn provider_with_spending_limit(
        account: Address,
        key_id: Address,
        fee_token: Address,
        remaining_limit: alloy_primitives::U256,
    ) -> Box<dyn reth_storage_api::StateProvider> {
        provider_with_spending_limit_state(
            account,
            key_id,
            fee_token,
            SpendingLimitState {
                remaining: remaining_limit,
                ..Default::default()
            },
            TempoHardfork::default(),
        )
    }

    fn provider_with_spending_limit_state(
        account: Address,
        key_id: Address,
        fee_token: Address,
        limit_state: SpendingLimitState,
        setup_spec: TempoHardfork,
    ) -> Box<dyn reth_storage_api::StateProvider> {
        let provider = MockEthProvider::default().with_chain_spec(std::sync::Arc::unwrap_or_clone(
            tempo_chainspec::spec::MODERATO.clone(),
        ));

        // Write AuthorizedKey with enforce_limits=true
        provider
            .setup_storage(setup_spec, || {
                let mut keychain = AccountKeychain::new();
                keychain.keys[account][key_id].write(AuthorizedKey {
                    signature_type: StoredSignatureType::Secp256k1,
                    expiry: u64::MAX,
                    enforce_limits: true,
                    is_revoked: false,
                    is_admin: false,
                })?;
                let limit_key = AccountKeychain::spending_limit_key(account, key_id);
                keychain.spending_limits[limit_key][fee_token].write(limit_state)?;
                Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
            })
            .unwrap();

        provider.latest().unwrap()
    }

    fn set_fee_token_balance(
        provider: &MockEthProvider<TempoPrimitives, TempoChainSpec>,
        fee_token: Address,
        account: Address,
        balance: U256,
    ) {
        let usd_currency_value =
            uint!(0x5553440000000000000000000000000000000000000000000000000000000006_U256);
        let transfer_policy_id_packed =
            uint!(0x0000000000000000000000010000000000000000000000000000000000000000_U256);
        let balance_slot = TIP20Token::from_address(fee_token)
            .expect("fee token must be a valid TIP20 token")
            .balances[account]
            .slot();

        provider.add_account(
            fee_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([
                (tip20_slots::CURRENCY.into(), usd_currency_value),
                (
                    tip20_slots::TRANSFER_POLICY_ID.into(),
                    transfer_policy_id_packed,
                ),
                (balance_slot.into(), balance),
            ]),
        );
    }

    fn set_transfer_policy(
        provider: &MockEthProvider<TempoPrimitives, TempoChainSpec>,
        fee_token: Address,
        policy_id: u64,
    ) {
        let transfer_policy_id_packed =
            U256::from(policy_id) << (tip20_slots::TRANSFER_POLICY_ID_OFFSET * 8);

        provider.add_account(
            fee_token,
            ExtendedAccount::new(0, U256::ZERO).extend_storage([(
                tip20_slots::TRANSFER_POLICY_ID.into(),
                transfer_policy_id_packed,
            )]),
        );
    }

    fn set_keychain_spending_limit(
        provider: &MockEthProvider<TempoPrimitives, TempoChainSpec>,
        account: Address,
        key_id: Address,
        fee_token: Address,
        remaining: U256,
    ) {
        provider
            .setup_storage(TempoHardfork::default(), || {
                let mut keychain = AccountKeychain::new();
                keychain.keys[account][key_id].write(AuthorizedKey {
                    signature_type: StoredSignatureType::Secp256k1,
                    expiry: u64::MAX,
                    enforce_limits: true,
                    is_revoked: false,
                    is_admin: false,
                })?;
                let limit_key = AccountKeychain::spending_limit_key(account, key_id);
                keychain.spending_limits[limit_key][fee_token].write(SpendingLimitState {
                    remaining,
                    ..Default::default()
                })?;
                Ok::<(), tempo_precompiles::error::TempoPrecompileError>(())
            })
            .unwrap();
    }

    fn create_test_pool(
        provider: MockEthProvider<TempoPrimitives, TempoChainSpec>,
    ) -> TempoTransactionPool<MockEthProvider<TempoPrimitives, TempoChainSpec>> {
        let inner = EthTransactionValidatorBuilder::new(
            provider.clone(),
            TempoEvmConfig::new(provider.chain_spec()),
        )
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
        TempoTransactionPool::new(
            protocol_pool,
            AA2dPool::new(Default::default()),
            DelayedPool::default(),
        )
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

    #[test_case::test_case(U256::ZERO; "protocol")]
    #[test_case::test_case(U256::ONE; "2d")]
    #[test_case::test_case(U256::MAX; "expiring")]
    fn best_transactions_for_block_validity_boundaries(nonce_key: U256) {
        let pool = create_test_pool(
            create_provider_with_tip().with_chain_spec(Arc::unwrap_or_clone(DEV.clone())),
        );
        let tx = TxBuilder::aa(Address::random())
            .nonce_key(nonce_key)
            .valid_after(50)
            .valid_before(100)
            .build();
        let hash = *tx.hash();
        add_validated(&pool, tx);

        for (timestamp, eligible) in [
            (49, false),
            (50, true),
            (99, true),
            (100, false),
            (101, false),
        ] {
            let hashes: Vec<_> = pool
                .best_transactions_for_block(BestTransactionsAttributes::base_fee(0), timestamp)
                .without_updates()
                .map(|tx| *tx.hash())
                .collect();
            assert_eq!(
                hashes,
                if eligible { vec![hash] } else { vec![] },
                "timestamp {timestamp}"
            );
            assert!(
                pool.get(&hash).is_some(),
                "filtering must not evict transactions"
            );
        }
    }

    #[test_case::test_case(U256::ZERO; "protocol")]
    #[test_case::test_case(U256::ONE; "2d")]
    #[test_case::test_case(U256::MAX; "expiring")]
    fn best_transactions_for_block_key_expiry_boundary(nonce_key: U256) {
        let pool = create_test_pool(
            create_provider_with_tip().with_chain_spec(Arc::unwrap_or_clone(DEV.clone())),
        );
        let tx = TxBuilder::aa(Address::random())
            .nonce_key(nonce_key)
            .valid_before(200)
            .build();
        tx.set_key_expiry(Some(100));
        let hash = *tx.hash();
        add_validated(&pool, tx);

        for (timestamp, eligible) in [(99, true), (100, false), (101, false)] {
            let hashes: Vec<_> = pool
                .best_transactions_for_block(BestTransactionsAttributes::base_fee(0), timestamp)
                .without_updates()
                .map(|tx| *tx.hash())
                .collect();
            assert_eq!(
                hashes,
                if eligible { vec![hash] } else { vec![] },
                "timestamp {timestamp}"
            );
            assert!(
                pool.get(&hash).is_some(),
                "filtering must not evict transactions"
            );
        }
    }

    #[test_case::test_case(U256::ZERO; "protocol")]
    #[test_case::test_case(U256::ONE; "2d")]
    fn best_transactions_for_block_missing_bounds(nonce_key: U256) {
        let pool = create_test_pool(create_provider_with_tip());
        let unbounded = TxBuilder::aa(Address::random())
            .nonce_key(nonce_key)
            .build();
        let future = TxBuilder::aa(Address::random())
            .nonce_key(nonce_key)
            .valid_after(50)
            .build();
        let expiring = TxBuilder::aa(Address::random())
            .nonce_key(nonce_key)
            .valid_before(100)
            .build();
        let eip1559 = TxBuilder::eip1559(Address::random()).build_eip1559();
        let unbounded_hash = *unbounded.hash();
        let future_hash = *future.hash();
        let expiring_hash = *expiring.hash();
        let eip1559_hash = *eip1559.hash();
        for tx in [unbounded, future, expiring, eip1559] {
            add_validated(&pool, tx);
        }

        for (timestamp, expected) in [
            (0, vec![unbounded_hash, expiring_hash, eip1559_hash]),
            (
                50,
                vec![unbounded_hash, future_hash, expiring_hash, eip1559_hash],
            ),
            (100, vec![unbounded_hash, future_hash, eip1559_hash]),
            (u64::MAX, vec![unbounded_hash, future_hash, eip1559_hash]),
        ] {
            let mut hashes: Vec<_> = pool
                .best_transactions_for_block(BestTransactionsAttributes::base_fee(0), timestamp)
                .without_updates()
                .map(|tx| *tx.hash())
                .collect();
            let mut expected = expected;
            hashes.sort();
            expected.sort();
            assert_eq!(hashes, expected, "timestamp {timestamp}");
        }
    }

    #[test_case::test_case(U256::ZERO, 0, false; "future_protocol_head")]
    #[test_case::test_case(U256::ZERO, 1, false; "future_protocol_successor")]
    #[test_case::test_case(U256::ONE, 0, false; "future_2d_head")]
    #[test_case::test_case(U256::ONE, 1, false; "future_2d_successor")]
    #[test_case::test_case(U256::ZERO, 0, true; "expired_protocol_head")]
    #[test_case::test_case(U256::ZERO, 1, true; "expired_protocol_successor")]
    #[test_case::test_case(U256::ONE, 0, true; "expired_2d_head")]
    #[test_case::test_case(U256::ONE, 1, true; "expired_2d_successor")]
    fn best_transactions_for_block_preserves_dependencies(
        nonce_key: U256,
        ineligible_nonce: u64,
        expired: bool,
    ) {
        let pool = create_test_pool(create_provider_with_tip());
        let sender = Address::random();
        let mut sequence = Vec::new();
        for nonce in 0..3 {
            let mut tx = TxBuilder::aa(sender)
                .nonce_key(nonce_key)
                .nonce(nonce)
                .max_priority_fee(10 + u128::from(nonce));
            if nonce == ineligible_nonce {
                tx = if expired {
                    tx.valid_before(50)
                } else {
                    tx.valid_after(50)
                };
            }
            sequence.push(tx.build());
        }
        // These share either the sender or the nonce key, but none depend on the skipped tx.
        let other_sender = TxBuilder::aa(Address::random())
            .nonce_key(nonce_key)
            .max_priority_fee(3)
            .build();
        let other_lane = TxBuilder::aa(sender)
            .nonce_key(U256::from(2))
            .max_priority_fee(2)
            .build();
        let other_pool = TxBuilder::aa(sender)
            .nonce_key(if nonce_key.is_zero() {
                U256::ONE
            } else {
                U256::ZERO
            })
            .max_priority_fee(1)
            .build();
        let mut expected: Vec<_> = sequence
            .iter()
            .take(usize::try_from(ineligible_nonce).unwrap())
            .map(|tx| *tx.hash())
            .collect();
        expected.extend([*other_sender.hash(), *other_lane.hash(), *other_pool.hash()]);
        let all_hashes: Vec<_> = sequence
            .iter()
            .map(|tx| *tx.hash())
            .chain([*other_sender.hash(), *other_lane.hash(), *other_pool.hash()])
            .collect();
        for tx in sequence
            .into_iter()
            .chain([other_sender, other_lane, other_pool])
        {
            let validated = TransactionValidationOutcome::Valid {
                balance: U256::MAX,
                state_nonce: 0,
                bytecode_hash: None,
                transaction: ValidTransaction::new(tx, None),
                propagate: true,
                authorities: None,
            };
            pool.add_validated_transaction(TransactionOrigin::External, validated)
                .unwrap();
        }
        let timestamp = if expired { 50 } else { 49 };
        let hashes: Vec<_> = pool
            .best_transactions_for_block(BestTransactionsAttributes::base_fee(0), timestamp)
            .without_updates()
            .map(|tx| *tx.hash())
            .collect();
        assert_eq!(hashes, expected);
        assert_eq!(pool.pool_size().total, all_hashes.len());

        // A new block iterator can select the whole sequence when the time bound permits it.
        let timestamp = if expired { 49 } else { 50 };
        let hashes: Vec<_> = pool
            .best_transactions_for_block(BestTransactionsAttributes::base_fee(0), timestamp)
            .without_updates()
            .map(|tx| *tx.hash())
            .collect();
        assert_eq!(hashes, all_hashes);
    }

    #[test_case::test_case(U256::ZERO; "protocol")]
    #[test_case::test_case(U256::ONE; "2d")]
    fn best_transactions_for_block_filters_live_updates(nonce_key: U256) {
        let pool = create_test_pool(create_provider_with_tip());
        let mut best =
            pool.best_transactions_for_block(BestTransactionsAttributes::base_fee(0), 49);
        let future = TxBuilder::aa(Address::random())
            .nonce_key(nonce_key)
            .valid_after(50)
            .max_priority_fee(2)
            .build();
        let eligible = TxBuilder::aa(Address::random())
            .nonce_key(nonce_key)
            .max_priority_fee(1)
            .build();
        let hash = *eligible.hash();
        for tx in [future, eligible] {
            add_validated(&pool, tx);
        }
        assert_eq!(best.next().map(|tx| *tx.hash()), Some(hash));
        assert!(best.next().is_none());
        assert_eq!(pool.pool_size().total, 2);
    }

    #[test]
    fn best_transactions_for_block_expiring_nonces_are_independent() {
        let pool = create_test_pool(
            create_provider_with_tip().with_chain_spec(Arc::unwrap_or_clone(DEV.clone())),
        );
        let sender = Address::random();
        let future = TxBuilder::aa(sender)
            .nonce_key(U256::MAX)
            .valid_after(50)
            .valid_before(100)
            .max_priority_fee(3)
            .build();
        let expired = TxBuilder::aa(sender)
            .nonce_key(U256::MAX)
            .valid_before(49)
            .max_priority_fee(2)
            .build();
        let eligible = TxBuilder::aa(sender)
            .nonce_key(U256::MAX)
            .valid_before(100)
            .max_priority_fee(1)
            .build();
        let hash = *eligible.hash();
        for tx in [future, expired, eligible] {
            add_validated(&pool, tx);
        }
        let hashes: Vec<_> = pool
            .best_transactions_for_block(BestTransactionsAttributes::base_fee(0), 49)
            .without_updates()
            .map(|tx| *tx.hash())
            .collect();
        assert_eq!(hashes, vec![hash]);
        assert_eq!(pool.pool_size().total, 3);
    }

    #[test]
    fn pending_transactions_by_address_and_nonce_key() {
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

    fn sponsored_keychain_transaction(
        sender: Address,
        fee_token: Address,
    ) -> (TempoPooledTransaction, Address) {
        let access_key_signer = PrivateKeySigner::random();
        let key_id = access_key_signer.address();
        let envelope = crate::test_utils::TxBuilder::aa(sender)
            .fee_token(fee_token)
            .build_keychain(sender, &access_key_signer)
            .inner()
            .clone()
            .into_inner();
        let TempoTxEnvelope::AA(mut signed) = envelope else {
            panic!("expected AA transaction");
        };

        let sponsor = PrivateKeySigner::random();
        signed.tx_mut().fee_payer_signature = Some(Signature::new(U256::ZERO, U256::ZERO, false));
        let fee_payer_hash = signed.tx().fee_payer_signature_hash(sender);
        signed.tx_mut().fee_payer_signature = Some(
            sponsor
                .sign_hash_sync(&fee_payer_hash)
                .expect("fee payer signing should succeed"),
        );

        (
            TempoPooledTransaction::new(Recovered::new_unchecked(
                TempoTxEnvelope::AA(signed),
                sender,
            )),
            key_id,
        )
    }

    fn sponsored_implicit_fee_transaction(sender: Address) -> (TempoPooledTransaction, Address) {
        let fee_payer_signer = loop {
            let signer = PrivateKeySigner::random();
            if signer.address() != sender {
                break signer;
            }
        };
        let fee_payer = fee_payer_signer.address();
        let envelope = crate::test_utils::TxBuilder::aa(sender)
            .build()
            .inner()
            .clone()
            .into_inner();
        let TempoTxEnvelope::AA(mut signed) = envelope else {
            panic!("expected AA transaction");
        };
        let fee_payer_hash = signed.tx().fee_payer_signature_hash(sender);
        signed.tx_mut().fee_payer_signature = Some(
            fee_payer_signer
                .sign_hash_sync(&fee_payer_hash)
                .expect("fee payer signing should succeed"),
        );

        (
            TempoPooledTransaction::new(Recovered::new_unchecked(
                TempoTxEnvelope::AA(signed),
                sender,
            )),
            fee_payer,
        )
    }

    #[tokio::test]
    async fn evicts_sponsored_implicit_fee_transaction_when_fee_payer_user_token_changes() {
        let sender = Address::random();
        let (pooled, fee_payer) = sponsored_implicit_fee_transaction(sender);
        assert_eq!(pooled.inner().fee_token(), None);
        assert_ne!(fee_payer, sender);

        let provider = create_provider_with_tip();
        provider.add_account(sender, ExtendedAccount::new(pooled.nonce(), *pooled.cost()));
        let pool = create_test_pool(provider);
        add_validated(&pool, pooled.clone());

        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates.user_token_changes.insert(fee_payer);

        let evicted = pool.evict_invalidated_transactions(&updates);
        assert_eq!(tx_hashes(&evicted), vec![*pooled.hash()]);
        assert!(pool.get(pooled.hash()).is_none());
    }

    #[tokio::test]
    async fn keeps_sponsored_implicit_fee_transaction_when_sender_user_token_changes() {
        let sender = Address::random();
        let (pooled, fee_payer) = sponsored_implicit_fee_transaction(sender);
        assert_eq!(pooled.inner().fee_token(), None);
        assert_ne!(fee_payer, sender);

        let provider = create_provider_with_tip();
        provider.add_account(sender, ExtendedAccount::new(pooled.nonce(), *pooled.cost()));
        let pool = create_test_pool(provider);
        add_validated(&pool, pooled.clone());

        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates.user_token_changes.insert(sender);

        assert!(pool.evict_invalidated_transactions(&updates).is_empty());
        assert!(pool.get(pooled.hash()).is_some());
    }

    #[tokio::test]
    async fn evicts_sender_paid_implicit_fee_transaction_when_sender_user_token_changes() {
        let sender = Address::random();
        let pooled = crate::test_utils::TxBuilder::aa(sender).build();
        assert_eq!(pooled.inner().fee_token(), None);

        let provider = create_provider_with_tip();
        provider.add_account(sender, ExtendedAccount::new(pooled.nonce(), *pooled.cost()));
        let pool = create_test_pool(provider);
        add_validated(&pool, pooled.clone());

        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates.user_token_changes.insert(sender);

        let evicted = pool.evict_invalidated_transactions(&updates);
        assert_eq!(tx_hashes(&evicted), vec![*pooled.hash()]);
        assert!(pool.get(pooled.hash()).is_none());
    }

    #[tokio::test]
    async fn keeps_sponsored_keychain_transaction_on_spending_limit_invalidations() {
        let sender = Address::random();
        let fee_token = PATH_USD_ADDRESS;
        let (pooled, key_id) = sponsored_keychain_transaction(sender, fee_token);

        let provider = create_provider_with_tip();
        provider.add_account(sender, ExtendedAccount::new(pooled.nonce(), *pooled.cost()));
        set_keychain_spending_limit(
            &provider,
            sender,
            key_id,
            fee_token,
            pooled.fee_token_cost() - U256::ONE,
        );
        let pool = create_test_pool(provider);
        add_validated(&pool, pooled.clone());

        let mut limit_change = crate::maintain::TempoPoolUpdates::new();
        limit_change
            .spending_limit_changes
            .insert(sender, key_id, Some(fee_token));

        assert!(
            pool.evict_invalidated_transactions(&limit_change)
                .is_empty()
        );
        assert!(pool.get(pooled.hash()).is_some());

        let mut limit_spend = crate::maintain::TempoPoolUpdates::new();
        limit_spend
            .spending_limit_spends
            .insert(sender, key_id, Some(fee_token));

        assert!(pool.evict_invalidated_transactions(&limit_spend).is_empty());
        assert!(pool.get(pooled.hash()).is_some());
    }

    #[tokio::test]
    async fn evicts_sponsored_transactions_when_fee_payer_becomes_insolvent() {
        let fee_payer_signer = PrivateKeySigner::random();
        let fee_payer = fee_payer_signer.address();
        let sender = Address::random();

        let envelope = crate::test_utils::TxBuilder::aa(sender)
            .fee_token(PATH_USD_ADDRESS)
            .build()
            .inner()
            .clone()
            .into_inner();
        let TempoTxEnvelope::AA(mut signed) = envelope else {
            panic!("expected AA transaction");
        };
        let fee_payer_hash = signed.tx().fee_payer_signature_hash(sender);
        signed.tx_mut().fee_payer_signature = Some(
            fee_payer_signer
                .sign_hash_sync(&fee_payer_hash)
                .expect("fee payer signing should succeed"),
        );
        let pooled = TempoPooledTransaction::new(Recovered::new_unchecked(
            TempoTxEnvelope::AA(signed),
            sender,
        ));

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

        let initial_balance = pooled.fee_token_cost() + U256::ONE;
        set_fee_token_balance(&provider, PATH_USD_ADDRESS, fee_payer, initial_balance);

        let inner =
            EthTransactionValidatorBuilder::new(provider.clone(), TempoEvmConfig::mainnet())
                .disable_balance_check()
                .build(InMemoryBlobStore::default());
        let amm_cache =
            AmmLiquidityCache::new(provider.clone()).expect("failed to setup AmmLiquidityCache");
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
        let pool = TempoTransactionPool::new(
            protocol_pool,
            AA2dPool::new(Default::default()),
            DelayedPool::default(),
        );

        pooled.set_resolved_fee_token(ResolvedFeeToken::Selected(PATH_USD_ADDRESS));
        let validated = TransactionValidationOutcome::Valid {
            balance: *pooled.cost(),
            state_nonce: pooled.nonce(),
            bytecode_hash: None,
            transaction: ValidTransaction::new(pooled.clone(), None),
            propagate: true,
            authorities: None,
        };
        let add_result = pool.add_validated_transaction(TransactionOrigin::External, validated);
        assert!(
            add_result.is_ok(),
            "transaction should be admitted before sponsor drains balance: {add_result:?}"
        );

        set_fee_token_balance(
            &provider,
            PATH_USD_ADDRESS,
            fee_payer,
            pooled.fee_token_cost() - U256::ONE,
        );

        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates
            .fee_balance_changes
            .entry(PATH_USD_ADDRESS)
            .or_default()
            .insert(fee_payer);

        let evicted = pool.evict_invalidated_transactions(&updates);
        assert_eq!(tx_hashes(&evicted), vec![*pooled.hash()]);
        assert!(pool.get(pooled.hash()).is_none());
    }

    #[tokio::test]
    async fn blacklist_eviction_uses_resolved_fee_token() {
        let sender = Address::random();
        let resolved_fee_token = address!("20C0000000000000000000000000000000000002");
        let policy_id = 7;
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
        set_transfer_policy(&provider, resolved_fee_token, policy_id);

        let pool = create_test_pool(provider);
        add_validated(&pool, pooled.clone());

        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates.blacklist_additions.push((policy_id, sender));

        let evicted = pool.evict_invalidated_transactions(&updates);
        assert_eq!(tx_hashes(&evicted), vec![*pooled.hash()]);
        assert!(pool.get(pooled.hash()).is_none());
    }

    #[tokio::test]
    async fn whitelist_eviction_uses_resolved_fee_token() {
        let sender = Address::random();
        let resolved_fee_token = address!("20C0000000000000000000000000000000000002");
        let policy_id = 9;
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
        set_transfer_policy(&provider, resolved_fee_token, policy_id);

        let pool = create_test_pool(provider);
        add_validated(&pool, pooled.clone());

        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates.whitelist_removals.push((policy_id, sender));

        let evicted = pool.evict_invalidated_transactions(&updates);
        assert_eq!(tx_hashes(&evicted), vec![*pooled.hash()]);
        assert!(pool.get(pooled.hash()).is_none());
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
        let pool = TempoTransactionPool::new(
            protocol_pool,
            AA2dPool::new(Default::default()),
            DelayedPool::default(),
        );

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

        let evicted = pool.evict_invalidated_transactions(&updates);
        assert!(evicted.is_empty());
        assert!(pool.get(pooled.hash()).is_some());
    }

    #[tokio::test]
    async fn evicts_transactions_with_burned_key_authorization_witness() {
        let sender = Address::random();
        let burned_witness = B256::random();
        let other_witness = B256::random();

        let key_authorization = |witness| {
            KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, Address::random())
                .with_witness(witness)
                .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature()))
        };

        let matching = crate::test_utils::TxBuilder::aa(sender)
            .nonce(0)
            .key_authorization(key_authorization(burned_witness))
            .build();
        let untouched = crate::test_utils::TxBuilder::aa(sender)
            .nonce(1)
            .key_authorization(key_authorization(other_witness))
            .build();

        let provider = MockEthProvider::<TempoPrimitives>::new()
            .with_chain_spec(std::sync::Arc::unwrap_or_clone(MODERATO.clone()));
        provider.add_account(sender, ExtendedAccount::new(matching.nonce(), U256::MAX));
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
        let pool = TempoTransactionPool::new(
            protocol_pool,
            AA2dPool::new(Default::default()),
            DelayedPool::default(),
        );

        for pooled in [&matching, &untouched] {
            add_validated(&pool, pooled.clone());
        }

        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates
            .key_authorization_witness_burns
            .entry(sender)
            .or_default()
            .insert(burned_witness);

        let evicted = pool.evict_invalidated_transactions(&updates);
        assert_eq!(tx_hashes(&evicted), vec![*matching.hash()]);
        assert!(pool.get(matching.hash()).is_none());
        assert!(pool.get(untouched.hash()).is_some());
    }

    #[tokio::test]
    async fn evicts_transactions_with_revoked_key_authorization_signer() {
        let sender = Address::random();
        let admin_signer = PrivateKeySigner::random();
        let admin_key = alloy_signer::Signer::address(&admin_signer);
        let other_signer = PrivateKeySigner::random();

        let key_authorization = |signer: &PrivateKeySigner| {
            let authorization =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, Address::random())
                    .with_account(sender);
            let signature = signer
                .sign_hash_sync(&authorization.signature_hash())
                .expect("key authorization signing should succeed");
            authorization.into_signed(PrimitiveSignature::Secp256k1(signature))
        };

        let matching = crate::test_utils::TxBuilder::aa(sender)
            .nonce(0)
            .key_authorization(key_authorization(&admin_signer))
            .build();
        let untouched = crate::test_utils::TxBuilder::aa(sender)
            .nonce(1)
            .key_authorization(key_authorization(&other_signer))
            .build();

        let provider = MockEthProvider::<TempoPrimitives>::new()
            .with_chain_spec(std::sync::Arc::unwrap_or_clone(MODERATO.clone()));
        provider.add_account(sender, ExtendedAccount::new(matching.nonce(), U256::MAX));
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
        let pool = TempoTransactionPool::new(
            protocol_pool,
            AA2dPool::new(Default::default()),
            DelayedPool::default(),
        );

        for pooled in [&matching, &untouched] {
            add_validated(&pool, pooled.clone());
        }

        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates.revoked_keys.insert(sender, admin_key);

        let evicted = pool.evict_invalidated_transactions(&updates);
        assert_eq!(tx_hashes(&evicted), vec![*matching.hash()]);
        assert!(pool.get(matching.hash()).is_none());
        assert!(pool.get(untouched.hash()).is_some());
    }

    #[tokio::test]
    async fn evicts_transactions_with_stale_key_authorization_target() {
        let sender = Address::random();
        let signer = PrivateKeySigner::random();
        let target_key = Address::random();
        let other_key = Address::random();

        let key_authorization = |key_id| {
            let authorization =
                KeyAuthorization::unrestricted(42431, SignatureType::Secp256k1, key_id)
                    .with_account(sender);
            let signature = signer
                .sign_hash_sync(&authorization.signature_hash())
                .expect("key authorization signing should succeed");
            authorization.into_signed(PrimitiveSignature::Secp256k1(signature))
        };

        let matching = crate::test_utils::TxBuilder::aa(sender)
            .nonce(0)
            .key_authorization(key_authorization(target_key))
            .build();
        let untouched = crate::test_utils::TxBuilder::aa(sender)
            .nonce(1)
            .key_authorization(key_authorization(other_key))
            .build();

        let provider = MockEthProvider::<TempoPrimitives>::new()
            .with_chain_spec(std::sync::Arc::unwrap_or_clone(MODERATO.clone()));
        provider.add_account(sender, ExtendedAccount::new(matching.nonce(), U256::MAX));
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
        let pool = TempoTransactionPool::new(
            protocol_pool,
            AA2dPool::new(Default::default()),
            DelayedPool::default(),
        );

        for pooled in [&matching, &untouched] {
            add_validated(&pool, pooled.clone());
        }

        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates
            .key_authorization_target_changes
            .insert(sender, target_key);

        let evicted = pool.evict_invalidated_transactions(&updates);
        assert_eq!(tx_hashes(&evicted), vec![*matching.hash()]);
        assert!(pool.get(matching.hash()).is_none());
        assert!(pool.get(untouched.hash()).is_some());
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
        provider
            .setup_storage(TempoHardfork::default(), || {
                let mut registry = TIP403Registry::new();
                registry.policy_records[compound_policy_id]
                    .base
                    .write(PolicyData {
                        policy_type: ITIP403Registry::PolicyType::COMPOUND as u8,
                        admin: Address::ZERO,
                    })?;
                registry.policy_records[compound_policy_id]
                    .compound
                    .write(CompoundPolicyData {
                        sender_policy_id: sender_sub_policy,
                        recipient_policy_id: recipient_sub_policy,
                        mint_recipient_policy_id: 0,
                    })
            })
            .unwrap();

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

        provider
            .setup_storage(TempoHardfork::default(), || {
                let mut registry = TIP403Registry::new();
                registry.policy_records[compound_policy_id]
                    .base
                    .write(PolicyData {
                        policy_type: ITIP403Registry::PolicyType::COMPOUND as u8,
                        admin: Address::ZERO,
                    })?;
                registry.policy_records[compound_policy_id]
                    .compound
                    .write(CompoundPolicyData {
                        sender_policy_id: sender_sub_policy,
                        recipient_policy_id: recipient_sub_policy,
                        mint_recipient_policy_id: 0,
                    })
            })
            .unwrap();

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

        provider
            .setup_storage(TempoHardfork::default(), || {
                let mut registry = TIP403Registry::new();
                registry.policy_records[compound_policy_id]
                    .base
                    .write(PolicyData {
                        policy_type: ITIP403Registry::PolicyType::COMPOUND as u8,
                        admin: Address::ZERO,
                    })?;
                registry.policy_records[compound_policy_id]
                    .compound
                    .write(CompoundPolicyData {
                        sender_policy_id: sender_sub,
                        recipient_policy_id: recipient_sub,
                        mint_recipient_policy_id: mint_recipient_sub,
                    })
            })
            .unwrap();

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

    /// Pre-T8, `get_recipient_policy_ids` returns the compound root and recipient sub-policy.
    #[test]
    fn recipient_policy_ids_includes_recipient_sub_policy_pre_t8() {
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

        provider
            .setup_storage(TempoHardfork::default(), || {
                let mut registry = TIP403Registry::new();
                registry.policy_records[compound_policy_id]
                    .base
                    .write(PolicyData {
                        policy_type: ITIP403Registry::PolicyType::COMPOUND as u8,
                        admin: Address::ZERO,
                    })?;
                registry.policy_records[compound_policy_id]
                    .compound
                    .write(CompoundPolicyData {
                        sender_policy_id: sender_sub,
                        recipient_policy_id: recipient_sub,
                        mint_recipient_policy_id: 0,
                    })
            })
            .unwrap();

        let mut state = provider.latest().unwrap();
        let ids = get_recipient_policy_ids(&mut state, fee_token, TempoHardfork::T7)
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

    /// For simple (non-compound) policies, pre-T8 `get_recipient_policy_ids` returns just the root.
    #[test]
    fn recipient_policy_ids_simple_policy_pre_t8() {
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

        provider
            .setup_storage(TempoHardfork::default(), || {
                let mut registry = TIP403Registry::new();
                registry.policy_records[simple_policy_id]
                    .base
                    .write(PolicyData {
                        policy_type: ITIP403Registry::PolicyType::BLACKLIST as u8,
                        admin: Address::ZERO,
                    })
            })
            .unwrap();

        let mut state = provider.latest().unwrap();
        let ids = get_recipient_policy_ids(&mut state, fee_token, TempoHardfork::T7)
            .expect("should resolve policy IDs");

        assert_eq!(ids, vec![simple_policy_id]);
    }

    #[test]
    fn recipient_policy_ids_exempt_on_t8() {
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

        let mut state = provider.latest().unwrap();
        assert!(get_recipient_policy_ids(&mut state, fee_token, TempoHardfork::T8).is_none());
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
            alloy_primitives::U256::from(200),
            0,
            TempoHardfork::default(),
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
            alloy_primitives::U256::from(200),
            0,
            TempoHardfork::default(),
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
        provider
            .setup_storage(TempoHardfork::default(), || {
                AccountKeychain::new().keys[account][key_id].write(AuthorizedKey {
                    signature_type: StoredSignatureType::Secp256k1,
                    expiry: u64::MAX,
                    enforce_limits: true,
                    is_revoked: false,
                    is_admin: false,
                })
            })
            .unwrap();

        assert!(exceeds_spending_limit(
            &mut provider.latest().unwrap(),
            &subject,
            U256::ONE,
            0,
            TempoHardfork::default(),
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
        provider
            .setup_storage(TempoHardfork::default(), || {
                AccountKeychain::new().keys[account][key_id].write(AuthorizedKey {
                    signature_type: StoredSignatureType::Secp256k1,
                    expiry: u64::MAX,
                    enforce_limits: false,
                    is_revoked: false,
                    is_admin: false,
                })
            })
            .unwrap();

        assert!(!exceeds_spending_limit(
            &mut provider.latest().unwrap(),
            &subject,
            U256::ONE,
            0,
            TempoHardfork::default(),
        ));
    }

    #[test]
    fn exceeds_spending_limit_uses_period_reset_after_rollover() {
        let account = Address::random();
        let key_id = Address::random();
        let fee_token = Address::random();
        let subject = KeychainSubject {
            account,
            key_id,
            fee_token,
        };

        let mut state = provider_with_spending_limit_state(
            account,
            key_id,
            fee_token,
            SpendingLimitState {
                remaining: alloy_primitives::U256::ZERO,
                max: 100,
                period: 60,
                period_end: 10,
            },
            TempoHardfork::T3,
        );

        assert!(!exceeds_spending_limit(
            &mut state,
            &subject,
            alloy_primitives::U256::from(50),
            10,
            TempoHardfork::T3,
        ));
        assert!(exceeds_spending_limit(
            &mut state,
            &subject,
            alloy_primitives::U256::from(150),
            10,
            TempoHardfork::T3,
        ));
    }

    #[test]
    fn aa_2d_queued_eviction_rejects_self_and_emits_discarded() {
        let pool = create_test_pool(create_provider_with_tip());
        *pool.aa_2d_pool.write() = AA2dPool::new(AA2dPoolConfig {
            queued_limit: SubPoolLimit {
                max_txs: 1,
                max_size: usize::MAX,
            },
            ..Default::default()
        });
        let mut events = pool.all_transactions_event_listener();
        let add_queued = |priority_fee| {
            let tx = TxBuilder::aa(Address::random())
                .nonce_key(U256::ONE)
                .nonce(1)
                .max_priority_fee(priority_fee)
                .build();
            add_aa_2d(&pool, tx)
        };

        let (queued, result) = add_queued(2_000_000_000);
        assert!(result.is_ok());
        let (self_evicted, result) = add_queued(1_000_000_000);
        assert!(matches!(
            result.unwrap_err().kind,
            PoolErrorKind::DiscardedOnInsert
        ));
        let (displacing, result) = add_queued(3_000_000_000);
        assert!(result.is_ok());

        assert!(!pool.contains(&queued));
        assert!(!pool.contains(&self_evicted));
        assert!(pool.contains(&displacing));
        assert_eq!(discarded_hashes(&mut events), [self_evicted, queued]);
    }

    #[test]
    fn aa_2d_promoted_then_evicted_transaction_ends_discarded() {
        let pool = create_test_pool(create_provider_with_tip());
        *pool.aa_2d_pool.write() = AA2dPool::new(AA2dPoolConfig {
            pending_limit: SubPoolLimit {
                max_txs: 1,
                max_size: usize::MAX,
            },
            ..Default::default()
        });
        let mut events = pool.all_transactions_event_listener();
        let sender = Address::random();
        let lane_tx = |nonce, priority_fee| {
            TxBuilder::aa(sender)
                .nonce_key(U256::ONE)
                .nonce(nonce)
                .max_priority_fee(priority_fee)
                .build()
        };

        let (promoted, result) = add_aa_2d(&pool, lane_tx(1, 1_000_000_000));
        assert!(result.is_ok());
        // Filling the gap promotes the queued transaction, which the pending limit then evicts.
        let (head, result) = add_aa_2d(&pool, lane_tx(0, 3_000_000_000));
        assert!(result.is_ok());
        assert!(pool.contains(&head));
        assert!(!pool.contains(&promoted));

        let last_event = std::iter::from_fn(|| events.next().now_or_never().flatten())
            .filter(|event| {
                matches!(
                    event,
                    FullTransactionEvent::Pending(hash)
                        | FullTransactionEvent::Queued(hash, _)
                        | FullTransactionEvent::Discarded(hash)
                        if *hash == promoted
                )
            })
            .last();
        assert!(
            matches!(last_event, Some(FullTransactionEvent::Discarded(hash)) if hash == promoted)
        );
    }

    #[test]
    fn aa_2d_self_evicted_replacement_discards_replaced_transaction() {
        let sender = Address::random();
        let lane_tx = TxBuilder::aa(sender).nonce_key(U256::ONE).nonce(1);
        let replaced = lane_tx.clone().build();
        let pool = create_test_pool(create_provider_with_tip());
        *pool.aa_2d_pool.write() = AA2dPool::new(AA2dPoolConfig {
            queued_limit: SubPoolLimit {
                max_txs: usize::MAX,
                max_size: replaced.size(),
            },
            ..Default::default()
        });
        let mut events = pool.all_transactions_event_listener();

        let (replaced, result) = add_aa_2d(&pool, replaced);
        assert!(result.is_ok());
        // A larger replacement pushes the queued subpool over its size limit and evicts itself.
        let replacement = lane_tx
            .max_fee(40_000_000_000)
            .max_priority_fee(2_000_000_000)
            .calls(vec![Call {
                to: TxKind::Call(Address::random()),
                value: U256::ZERO,
                input: vec![0; 256].into(),
            }])
            .build();
        let (replacement, result) = add_aa_2d(&pool, replacement);
        assert!(matches!(
            result.unwrap_err().kind,
            PoolErrorKind::DiscardedOnInsert
        ));

        assert!(!pool.contains(&replaced));
        assert!(!pool.contains(&replacement));
        assert_eq!(discarded_hashes(&mut events), [replacement, replaced]);
    }

    /// Adds `tx` with an on-chain nonce of 0 and returns its hash with the insert result.
    fn add_aa_2d(
        pool: &TempoTransactionPool<MockEthProvider<TempoPrimitives, TempoChainSpec>>,
        tx: TempoPooledTransaction,
    ) -> (TxHash, PoolResult<AddedTransactionOutcome>) {
        let hash = *tx.hash();
        let outcome = TransactionValidationOutcome::Valid {
            balance: *tx.cost(),
            state_nonce: 0,
            bytecode_hash: None,
            transaction: ValidTransaction::new(tx, None),
            propagate: true,
            authorities: None,
        };
        (
            hash,
            pool.add_validated_transaction(TransactionOrigin::External, outcome),
        )
    }

    /// Returns the first lifecycle event received so far for `hash`, skipping other transactions'.
    fn next_event_for(
        events: &mut AllTransactionsEvents<TempoPooledTransaction>,
        hash: TxHash,
    ) -> Option<FullTransactionEvent<TempoPooledTransaction>> {
        std::iter::from_fn(|| events.next().now_or_never().flatten()).find(|event| {
            matches!(
                event,
                FullTransactionEvent::Pending(h)
                    | FullTransactionEvent::Queued(h, _)
                    | FullTransactionEvent::Discarded(h)
                    | FullTransactionEvent::Invalid(h)
                    | FullTransactionEvent::Mined { tx_hash: h, .. }
                    if *h == hash
            )
        })
    }

    /// Returns the hashes of the `Discarded` events received so far, in order.
    fn discarded_hashes(events: &mut AllTransactionsEvents<TempoPooledTransaction>) -> Vec<TxHash> {
        std::iter::from_fn(|| events.next().now_or_never().flatten())
            .filter_map(|event| match event {
                FullTransactionEvent::Discarded(hash) => Some(hash),
                _ => None,
            })
            .collect()
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Moves the validator's tip to a block at `timestamp`.
    fn set_tip(
        pool: &TempoTransactionPool<MockEthProvider<TempoPrimitives, TempoChainSpec>>,
        timestamp: u64,
    ) {
        pool.protocol_pool
            .validator()
            .validator()
            .on_new_head_block(&SealedBlock::seal_slow(Block {
                header: TempoHeader {
                    inner: Header {
                        timestamp,
                        gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                        excess_blob_gas: Some(0),
                        base_fee_per_gas: Some(TEMPO_T0_BASE_FEE),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                body: Default::default(),
            }));
    }

    /// Returns a pool that fully validates transactions, with `sender` funded in pathUSD and
    /// the tip at `tip`. Must run inside a Tokio runtime, which drives validation.
    fn create_validating_pool(
        sender: Address,
        tip: u64,
        delayed_config: delayed_pool::Config,
    ) -> (
        MockEthProvider<TempoPrimitives, TempoChainSpec>,
        TempoTransactionPool<MockEthProvider<TempoPrimitives, TempoChainSpec>>,
    ) {
        let provider = create_provider_with_tip();
        provider.add_account(sender, ExtendedAccount::new(0, U256::ZERO));
        set_fee_token_balance(
            &provider,
            PATH_USD_ADDRESS,
            sender,
            U256::from(1_000_000_000_000u64),
        );

        let inner = EthTransactionValidatorBuilder::new(
            provider.clone(),
            TempoEvmConfig::new(provider.chain_spec()),
        )
        .with_custom_tx_type(TempoTxType::AA as u8)
        .disable_balance_check()
        .build(InMemoryBlobStore::default());
        let amm_cache =
            AmmLiquidityCache::new(provider.clone()).expect("failed to setup AmmLiquidityCache");
        let validator = TempoTransactionValidator::new(
            inner,
            crate::validator::DEFAULT_AA_VALID_AFTER_MAX_SECS,
            crate::validator::DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
            amm_cache,
        );
        let (executor, task) = TransactionValidationTaskExecutor::new(validator);
        tokio::spawn(task.run());

        let pool = TempoTransactionPool::new(
            Pool::new(
                executor,
                TempoTipOrdering::default(),
                InMemoryBlobStore::default(),
                PoolConfig::default(),
            ),
            AA2dPool::new(Default::default()),
            DelayedPool::new(delayed_config),
        );
        set_tip(&pool, tip);
        (provider, pool)
    }

    /// Returns a builder for an expiring nonce transaction from `sender` that the pool holds
    /// with the default lead time while the tip is at `tip`. Released from a tip of `tip + 18`.
    fn held_tx(sender: Address, tip: u64) -> TxBuilder {
        TxBuilder::aa(sender)
            .nonce_key(U256::MAX)
            .valid_after(tip + 20)
            .valid_before(tip + 28)
    }

    #[tokio::test]
    async fn delayed_transaction_is_held_and_visible() {
        let sender = Address::random();
        let tip = now_secs();
        let (_provider, pool) = create_validating_pool(sender, tip, Default::default());
        let mut pending = pool.pending_transactions_listener_for(TransactionListenerKind::All);
        let mut new_transactions = pool.new_transactions_listener_for(TransactionListenerKind::All);
        let tx = held_tx(sender, tip).build();
        let hash = *tx.hash();

        let outcome = pool
            .add_transaction(TransactionOrigin::External, tx.clone())
            .await
            .expect("transaction should be held");
        assert!(outcome.is_queued());
        assert!(pool.aa_2d_pool.read().delayed().contains(&hash));
        assert!(!pool.protocol_pool.contains(&hash));
        assert!(!pool.aa_2d_pool.read().contains(&hash));

        assert!(pool.contains(&hash));
        assert!(pool.get(&hash).is_some());
        assert_eq!(tx_hashes(&pool.get_all(vec![hash])), vec![hash]);
        assert_eq!(pool.all_transaction_hashes(), vec![hash]);
        assert_eq!(tx_hashes(&pool.all_transactions().queued), vec![hash]);
        assert_eq!(
            tx_hashes(&pool.all_transactions_by_sender(sender).queued),
            vec![hash]
        );
        assert_eq!(
            tx_hashes(&pool.get_transactions_by_sender(sender)),
            vec![hash]
        );
        assert_eq!(
            tx_hashes(&pool.get_queued_transactions_by_sender(sender)),
            vec![hash]
        );
        assert!(
            pool.queued_transactions().is_empty(),
            "held transactions must stay out of reth's stale-queued eviction"
        );
        assert_eq!(pool.pending_and_queued_txn_count(), (0, 1));
        assert_eq!(pool.pooled_transaction_hashes(), vec![hash]);
        assert_eq!(pool.pooled_transaction_hashes_max(1), vec![hash]);
        assert_eq!(
            pool.get_pooled_transaction_elements(vec![hash], GetPooledTransactionLimit::None)
                .len(),
            1
        );
        assert!(pool.get_pooled_transaction_element(hash).is_some());
        let size = pool.pool_size();
        assert_eq!((size.pending, size.queued, size.total), (0, 1, 1));
        assert_eq!(size.queued_size, InMemorySize::size(&tx));

        assert!(pool.pending_transactions().is_empty());
        assert!(pool.best_transactions().next().is_none());
        assert_eq!(pending.try_recv(), Ok(hash));
        let event = new_transactions.try_recv().expect("new transaction event");
        assert_eq!(event.subpool, SubPool::Queued);
        assert_eq!(*event.transaction.hash(), hash);

        let err = pool
            .add_transaction(TransactionOrigin::External, tx)
            .await
            .expect_err("held transaction is already imported");
        assert!(matches!(err.kind, PoolErrorKind::AlreadyImported));
    }

    #[test_case::test_case(U256::ZERO; "protocol")]
    #[test_case::test_case(U256::ONE; "2d")]
    #[tokio::test]
    async fn future_transaction_with_sequential_nonce_is_not_held(nonce_key: U256) {
        let sender = Address::random();
        let tip = now_secs();
        let (_provider, pool) = create_validating_pool(sender, tip, Default::default());
        let tx = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .valid_after(tip + 60)
            .build();
        let hash = *tx.hash();

        pool.add_transaction(TransactionOrigin::External, tx)
            .await
            .expect("transaction should be admitted");

        assert_eq!(pool.aa_2d_pool.read().delayed().len(), 0);
        assert!(pool.protocol_pool.contains(&hash) || pool.aa_2d_pool.read().contains(&hash));
    }

    #[tokio::test]
    async fn transaction_valid_within_lead_time_enters_live_pool() {
        let sender = Address::random();
        let tip = now_secs();
        let (_provider, pool) = create_validating_pool(
            sender,
            tip,
            delayed_pool::Config {
                lead_secs: 2,
                ..Default::default()
            },
        );
        let tx = held_tx(sender, tip).valid_after(tip + 2).build();
        let hash = *tx.hash();

        pool.add_transaction(TransactionOrigin::External, tx)
            .await
            .expect("transaction should be admitted");

        assert_eq!(pool.aa_2d_pool.read().delayed().len(), 0);
        assert_eq!(tx_hashes(&pool.pending_transactions()), vec![hash]);
    }

    #[tokio::test]
    async fn release_moves_due_transaction_into_live_pool() {
        let sender = Address::random();
        let tip = now_secs();
        let (_provider, pool) = create_validating_pool(
            sender,
            tip,
            delayed_pool::Config {
                lead_secs: 2,
                ..Default::default()
            },
        );
        let tx = held_tx(sender, tip).build();
        let hash = *tx.hash();
        pool.add_transaction(TransactionOrigin::External, tx)
            .await
            .expect("transaction should be held");
        let mut events = pool.all_transactions_event_listener();

        set_tip(&pool, tip + 17);
        pool.release_delayed_transactions(tip + 17).await;
        assert!(pool.aa_2d_pool.read().delayed().contains(&hash));

        set_tip(&pool, tip + 18);
        pool.release_delayed_transactions(tip + 18).await;
        assert!(!pool.aa_2d_pool.read().delayed().contains(&hash));
        assert_eq!(tx_hashes(&pool.pending_transactions()), vec![hash]);
        assert!(matches!(
            next_event_for(&mut events, hash),
            Some(FullTransactionEvent::Pending(_))
        ));
    }

    #[tokio::test]
    async fn release_drops_transaction_failing_revalidation() {
        let sender = Address::random();
        let tip = now_secs();
        let (provider, pool) = create_validating_pool(sender, tip, Default::default());
        let tx = held_tx(sender, tip).build();
        let hash = *tx.hash();
        pool.add_transaction(TransactionOrigin::External, tx)
            .await
            .expect("transaction should be held");
        let mut events = pool.all_transactions_event_listener();

        // The sender can no longer pay its fee when the transaction is released.
        set_fee_token_balance(&provider, PATH_USD_ADDRESS, sender, U256::ZERO);
        set_tip(&pool, tip + 18);
        pool.release_delayed_transactions(tip + 18).await;

        assert!(!pool.contains(&hash));
        assert!(matches!(
            next_event_for(&mut events, hash),
            Some(FullTransactionEvent::Discarded(_))
        ));
    }

    #[tokio::test]
    async fn removal_and_expiry_cover_held_transactions() {
        let sender = Address::random();
        let tip = now_secs();
        let (_provider, pool) = create_validating_pool(sender, tip, Default::default());
        let txs = [
            held_tx(sender, tip).build(),
            held_tx(sender, tip).valid_before(tip + 22).build(),
            held_tx(sender, tip).build(),
        ];
        let [removed, expiring, by_sender] = [0, 1, 2].map(|i| *txs[i].hash());
        for tx in txs {
            pool.add_transaction(TransactionOrigin::External, tx)
                .await
                .expect("transaction should be held");
        }
        assert_eq!(pool.aa_2d_pool.read().delayed().len(), 3);
        let mut events = pool.all_transactions_event_listener();

        assert_eq!(
            tx_hashes(&pool.remove_transactions(vec![removed])),
            vec![removed]
        );
        assert!(matches!(
            next_event_for(&mut events, removed),
            Some(FullTransactionEvent::Discarded(_))
        ));

        let all = pool.all_transactions();
        assert_eq!(
            tx_hashes(&pool.evict_invalidated_transactions_from(
                &crate::TempoPoolUpdates::new(),
                all.iter(),
                Some(tip + 22),
            )),
            vec![expiring]
        );

        assert_eq!(
            tx_hashes(&pool.remove_transactions_by_sender(sender)),
            vec![by_sender]
        );
        assert_eq!(pool.aa_2d_pool.read().delayed().len(), 0);
    }

    #[tokio::test]
    async fn delayed_limits_reject_transactions() {
        let sender = Address::random();
        let tip = now_secs();
        let (_provider, pool) = create_validating_pool(
            sender,
            tip,
            delayed_pool::Config {
                max_per_sender: std::num::NonZeroUsize::MIN,
                ..Default::default()
            },
        );
        pool.add_transaction(TransactionOrigin::External, held_tx(sender, tip).build())
            .await
            .expect("transaction should be held");

        let err = pool
            .add_transaction(TransactionOrigin::External, held_tx(sender, tip).build())
            .await
            .expect_err("sender limit is reached");
        assert!(!err.is_bad_transaction());
        assert!(matches!(
            err.kind,
            PoolErrorKind::SpammerExceededCapacity(authority) if authority == sender
        ));
    }

    #[tokio::test]
    async fn held_transactions_take_no_sequential_nonce() {
        let sender = Address::random();
        let tip = now_secs();
        let (_provider, pool) = create_validating_pool(sender, tip, Default::default());
        let held = held_tx(sender, tip).build();
        let held_hash = *held.hash();
        pool.add_transaction(TransactionOrigin::External, held)
            .await
            .expect("transaction should be held");

        assert!(
            pool.get_transaction_by_sender_and_nonce(sender, 0)
                .is_none()
        );
        assert!(pool.get_highest_transaction_by_sender(sender).is_none());

        let live = TxBuilder::aa(sender).build();
        let live_hash = *live.hash();
        pool.add_transaction(TransactionOrigin::External, live)
            .await
            .expect("protocol nonce 0 is free");
        assert_eq!(
            pool.get_transaction_by_sender_and_nonce(sender, 0)
                .map(|tx| *tx.hash()),
            Some(live_hash)
        );

        // Removing the held transaction leaves the sender's live transaction alone.
        assert_eq!(
            tx_hashes(&pool.remove_transactions_and_descendants(vec![held_hash])),
            vec![held_hash]
        );
        assert!(pool.contains(&live_hash));
    }

    #[tokio::test]
    async fn full_delayed_pool_evicts_lower_fee_transaction() {
        let sender = Address::random();
        let tip = now_secs();
        let (provider, pool) = create_validating_pool(
            sender,
            tip,
            delayed_pool::Config {
                max_count: std::num::NonZeroUsize::MIN,
                ..Default::default()
            },
        );
        let cheap = held_tx(sender, tip).build();
        let cheap_hash = *cheap.hash();
        pool.add_transaction(TransactionOrigin::External, cheap)
            .await
            .expect("transaction should be held");
        let mut events = pool.all_transactions_event_listener();

        let other = Address::random();
        provider.add_account(other, ExtendedAccount::new(0, U256::ZERO));
        set_fee_token_balance(
            &provider,
            PATH_USD_ADDRESS,
            other,
            U256::from(1_000_000_000_000u64),
        );
        let expensive = held_tx(other, tip).max_priority_fee(2_000_000_000).build();
        let expensive_hash = *expensive.hash();
        pool.add_transaction(TransactionOrigin::External, expensive)
            .await
            .expect("a higher fee evicts the cheaper held transaction");

        assert!(!pool.contains(&cheap_hash));
        assert!(pool.aa_2d_pool.read().delayed().contains(&expensive_hash));
        assert!(matches!(
            next_event_for(&mut events, cheap_hash),
            Some(FullTransactionEvent::Discarded(_))
        ));
    }

    #[tokio::test]
    async fn held_transaction_mined_in_block_is_not_discarded() {
        let sender = Address::random();
        let tip = now_secs();
        let (_provider, pool) = create_validating_pool(sender, tip, Default::default());
        let mined = held_tx(sender, tip).build();
        let consumed = held_tx(sender, tip).build();
        let mut storage = HashMap::default();
        for tx in [&mined, &consumed] {
            storage.insert(
                tx.expiring_nonce_slot().unwrap(),
                StorageSlot::new_changed(U256::ZERO, U256::from(tip + 28)),
            );
        }
        let (mined, consumed) = (*mined.hash(), {
            let hash = *consumed.hash();
            for tx in [mined, consumed] {
                pool.add_transaction(TransactionOrigin::External, tx)
                    .await
                    .expect("transaction should be held");
            }
            hash
        });
        let mut events = pool.all_transactions_event_listener();

        let mut state = AddressMap::default();
        state.insert(
            tempo_precompiles::NONCE_PRECOMPILE_ADDRESS,
            BundleAccount::new(None, None, storage, AccountStatus::Changed),
        );
        let mut removed = tx_hashes(
            &pool.remove_consumed_delayed_transactions(&state, &B256Set::from_iter([mined])),
        );
        removed.sort();
        let mut expected = vec![mined, consumed];
        expected.sort();
        assert_eq!(removed, expected);
        assert_eq!(pool.aa_2d_pool.read().delayed().len(), 0);
        assert_eq!(discarded_hashes(&mut events), vec![consumed]);
    }
}
