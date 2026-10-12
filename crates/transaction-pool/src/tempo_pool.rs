// Tempo transaction pool that implements Reth's TransactionPool trait
// Routes protocol nonces (nonce_key=0) to Reth pool
// Routes user nonces (nonce_key>0) to minimal 2D nonce pool

use crate::{
    amm::AmmLiquidityCache,
    best::MergeBestTransactions,
    fee_payer_costs::{FeePayerKey, PooledFeeCosts},
    ordering::TempoTipOrdering,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
    tt_2d_pool::AA2dPool,
    validator::{ConfigureTempoPoolEvm, TempoTransactionValidator},
};
use alloy_consensus::Transaction;
use alloy_primitives::{
    Address, B256, TxHash, U256,
    map::{AddressMap, AddressSet, B256Set, HashMap},
};
use parking_lot::{Mutex, RwLock};
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_eth_wire_types::HandleMempoolData;
use reth_provider::{ChangedAccount, StateProviderFactory};
use reth_storage_api::StateProvider;
use reth_transaction_pool::{
    AddedTransactionOutcome, AllPoolTransactions, BestTransactions, BestTransactionsAttributes,
    BlockInfo, CanonicalStateUpdate, GetPooledTransactionLimit, NewBlobSidecar, Pool, PoolResult,
    PoolSize, PoolTransaction, PropagatedTransactions, TransactionEvents, TransactionOrdering,
    TransactionOrigin, TransactionPool, TransactionPoolExt, TransactionValidationOutcome,
    TransactionValidationTaskExecutor, TransactionValidator, ValidPoolTransaction,
    blobstore::InMemoryBlobStore,
    error::{InvalidPoolTransactionError, PoolError, PoolErrorKind},
    identifier::TransactionId,
};
use revm::database::BundleAccount;
use std::{cmp::Reverse, sync::Arc, time::Instant};
use tempo_chainspec::hardfork::{TempoHardfork, TempoHardforks};
use tempo_evm::TempoEvmConfig;
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    account_keychain::AccountKeychain,
    error::Result as TempoPrecompileResult,
    storage::{Handler, StorageActions},
    tip20::TIP20Token,
    tip403_registry::{REJECT_ALL_POLICY_ID, TIP403Registry},
};
use tempo_primitives::{Block, TempoHeader};
use tempo_revm::TempoStateAccess;

/// Stale fee payer cost entries tolerated before [`TempoTransactionPool`] prunes them.
const FEE_PAYER_COSTS_PRUNE_SLACK: usize = 1024;

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
    /// Summed fee cost of pooled transactions per `(fee_token, fee_payer)` across both pools.
    ///
    /// Lock order: this lock is taken before either pool's lock, never while holding one.
    fee_payer_costs: Arc<Mutex<PooledFeeCosts>>,
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
            fee_payer_costs: Default::default(),
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
        let mut fee_payer_costs = self.fee_payer_costs.lock();
        let (promoted, mined, discarded) = self.aa_2d_pool.write().on_state_updates(state);
        fee_payer_costs.remove_all(mined.iter().chain(&discarded).map(|tx| tx.hash()));
        drop(fee_payer_costs);
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
    /// 4. **Fee payer balance changes**: Transactions whose fee payer's balance in the resolved
    ///    fee token no longer covers the summed fee cost of its pooled transactions after a
    ///    TIP20 transfer. Evicts lowest-priority, newest transactions first until it fits.
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
        let tip_timestamp = self
            .protocol_pool
            .validator()
            .validator()
            .inner
            .fork_tracker()
            .tip_timestamp();
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
        let mut fee_balance_candidates: HashMap<
            FeePayerKey,
            Vec<&Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        > = HashMap::default();

        for tx in transactions {
            if expiry_cutoff.is_some_and(|cutoff| tx.transaction.is_expired_by(cutoff)) {
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
            // When a TIP20 transfer changes a fee payer's balance, the pooled transactions for
            // that (fee_token, fee_payer) pair may no longer fit in it. Collect them here and
            // re-check each fee payer's aggregate after the scan.
            let fee_balance_candidate = if !updates.fee_balance_changes.is_empty() {
                let fee_token = tx.transaction.effective_fee_token();
                // only resolve the fee payer if the fee token saw balance changes
                updates
                    .fee_balance_changes
                    .get(&fee_token)
                    .and_then(|accounts| {
                        tx.transaction
                            .fee_payer()
                            .ok()
                            .filter(|fee_payer| accounts.contains(fee_payer))
                    })
                    .map(|fee_payer| (fee_token, fee_payer))
            } else {
                None
            };
            let removed_before = to_remove.len();

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

            if let Some(key) = fee_balance_candidate
                && to_remove.len() == removed_before
            {
                fee_balance_candidates.entry(key).or_default().push(tx);
            }
        }

        // Check 3b: Evict each changed fee payer's pooled transactions in eviction order (lowest
        // priority first, newest first on ties) until their fee cost fits its new balance.
        if !fee_balance_candidates.is_empty()
            && let Some(ref mut provider) = state_provider
        {
            let base_fee = self.protocol_pool.block_info().pending_basefee;
            let ordering = TempoTipOrdering::<TempoPooledTransaction>::default();
            for ((fee_token, fee_payer), mut txs) in fee_balance_candidates {
                let Ok(balance) = provider.get_token_balance(
                    fee_token,
                    fee_payer,
                    spec,
                    StorageActions::disabled(),
                ) else {
                    continue;
                };
                let mut pooled_cost = txs.iter().fold(U256::ZERO, |total, tx| {
                    total.saturating_add(tx.transaction.fee_token_cost())
                });
                if pooled_cost <= balance {
                    continue;
                }

                txs.sort_by_cached_key(|tx| {
                    (
                        ordering.priority(&tx.transaction, base_fee),
                        Reverse(tx.timestamp),
                    )
                });
                for tx in txs {
                    if pooled_cost <= balance {
                        break;
                    }
                    pooled_cost -= tx.transaction.fee_token_cost();
                    to_remove.push(*tx.hash());
                    insolvent_fee_payer_count += 1;
                }
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
        // Holding the lock across insertion makes check, reservation, and insertion atomic, so a
        // concurrent admission can neither overspend the fee payer nor prune this reservation.
        let mut fee_payer_costs = self.fee_payer_costs.lock();
        let (transaction, reserved) =
            self.reserve_fee_payer_cost(&mut fee_payer_costs, transaction, &[]);
        let result = self.insert_validated_transaction(&mut fee_payer_costs, origin, transaction);
        if result.is_err()
            && let Some(hash) = reserved
        {
            fee_payer_costs.remove(&hash);
        }
        result
    }

    /// Adds validated transactions, batching protocol pool insertions under one pool lock.
    fn add_validated_transactions(
        &self,
        transactions: Vec<(
            TransactionOrigin,
            TransactionValidationOutcome<TempoPooledTransaction>,
        )>,
    ) -> Vec<PoolResult<AddedTransactionOutcome>> {
        let has_aa_2d = transactions.iter().any(|(_, outcome)| {
            matches!(
                outcome,
                TransactionValidationOutcome::Valid { transaction, .. }
                    if transaction.transaction().is_aa_2d()
            )
        });
        if has_aa_2d {
            return transactions
                .into_iter()
                .map(|(origin, outcome)| self.add_validated_transaction(origin, outcome))
                .collect();
        }

        let mut fee_payer_costs = self.fee_payer_costs.lock();
        let mut reserved = Vec::with_capacity(transactions.len());
        // Reservations of this batch are not pooled until the batch is inserted.
        let mut in_flight = Vec::new();
        let transactions = transactions
            .into_iter()
            .map(|(origin, outcome)| {
                let (outcome, hash) =
                    self.reserve_fee_payer_cost(&mut fee_payer_costs, outcome, &in_flight);
                in_flight.extend(hash);
                reserved.push(hash);
                (origin, outcome)
            })
            .collect::<Vec<_>>();
        let results = self
            .protocol_pool
            .inner()
            .add_transactions_with_origins(transactions);
        for (result, reserved) in results.iter().zip(reserved) {
            if result.is_err()
                && let Some(hash) = reserved
            {
                fee_payer_costs.remove(&hash);
            }
        }
        results
    }

    /// Reserves the transaction's fee cost against its fee payer's pooled fee cost.
    ///
    /// Converts a valid outcome into an invalid one if the fee payer's balance cannot cover the
    /// fee cost of its pooled transactions plus this one. Returns the hash if this call started
    /// tracking the transaction, so the caller can release it if insertion fails. `in_flight`
    /// holds reservations whose transactions are not inserted yet.
    fn reserve_fee_payer_cost(
        &self,
        fee_payer_costs: &mut PooledFeeCosts,
        outcome: TransactionValidationOutcome<TempoPooledTransaction>,
        in_flight: &[TxHash],
    ) -> (
        TransactionValidationOutcome<TempoPooledTransaction>,
        Option<TxHash>,
    ) {
        let TransactionValidationOutcome::Valid { transaction, .. } = &outcome else {
            return (outcome, None);
        };
        let tx = transaction.transaction();
        let Some(key) = tx.fee_payer_key() else {
            return (outcome, None);
        };
        let hash = *tx.hash();
        let cost = tx.fee_token_cost();

        if let Some(balance) = tx.fee_payer_balance()
            && let Err(err) =
                self.ensure_fee_payer_cost_fits(fee_payer_costs, tx, key, balance, in_flight)
        {
            let TransactionValidationOutcome::Valid { transaction, .. } = outcome else {
                unreachable!("checked above")
            };
            return (
                TransactionValidationOutcome::Invalid(
                    transaction.into_transaction(),
                    InvalidPoolTransactionError::other(err),
                ),
                None,
            );
        }

        let reserved = fee_payer_costs.insert(hash, key, cost).then_some(hash);
        (outcome, reserved)
    }

    /// Checks that `balance` covers the fee payer's pooled fee cost plus `tx`'s fee cost.
    fn ensure_fee_payer_cost_fits(
        &self,
        fee_payer_costs: &mut PooledFeeCosts,
        tx: &TempoPooledTransaction,
        key: FeePayerKey,
        balance: U256,
        in_flight: &[TxHash],
    ) -> Result<(), TempoPoolTransactionError> {
        let hash = *tx.hash();
        let cost = tx.fee_token_cost();
        // Stale entries only overcount, so a pass here is final.
        if fee_payer_costs
            .total_excluding(&key, &[hash])
            .saturating_add(cost)
            <= balance
        {
            return Ok(());
        }

        // Before rejecting, drop entries for transactions the pools no longer hold.
        self.prune_stale_fee_payer_costs(fee_payer_costs, &key, in_flight);

        // A replacement frees the cost of the transaction it replaces.
        let replaced = self.replaced_transaction_hash(tx);
        let pooled_cost = match replaced {
            Some(replaced) => fee_payer_costs.total_excluding(&key, &[hash, replaced]),
            None => fee_payer_costs.total_excluding(&key, &[hash]),
        };
        if pooled_cost.saturating_add(cost) <= balance {
            return Ok(());
        }

        Err(
            TempoPoolTransactionError::FeePayerPooledCostExceedsBalance {
                fee_payer: key.1,
                required: pooled_cost.saturating_add(cost),
                balance,
            },
        )
    }

    /// Drops `key`'s entries for transactions the pools no longer hold.
    ///
    /// The protocol pool removes transactions (mined, replaced, size-limit discards) without
    /// notifying us, so its removals are reconciled here.
    fn prune_stale_fee_payer_costs(
        &self,
        fee_payer_costs: &mut PooledFeeCosts,
        key: &FeePayerKey,
        in_flight: &[TxHash],
    ) {
        let mut stale: Vec<TxHash> = fee_payer_costs
            .hashes(key)
            .filter(|hash| !in_flight.contains(hash))
            .copied()
            .collect();
        {
            let aa_2d_pool = self.aa_2d_pool.read();
            stale.retain(|hash| !aa_2d_pool.contains(hash));
        }
        stale.retain(|hash| !self.protocol_pool.contains(hash));
        fee_payer_costs.remove_all(&stale);
    }

    /// Returns the summed fee cost of pooled transactions paid by `fee_payer` in `fee_token`.
    ///
    /// This is the amount admission checks against the fee payer's balance. Stale entries are
    /// dropped first, so the result is derived from the pools' current contents.
    pub fn pooled_fee_cost(&self, fee_token: Address, fee_payer: Address) -> U256 {
        let key = (fee_token, fee_payer);
        let mut fee_payer_costs = self.fee_payer_costs.lock();
        self.prune_stale_fee_payer_costs(&mut fee_payer_costs, &key, &[]);
        fee_payer_costs.total(&key)
    }

    /// Returns the hash of the pooled transaction that `tx` would replace, if any.
    fn replaced_transaction_hash(&self, tx: &TempoPooledTransaction) -> Option<TxHash> {
        if tx.is_aa_2d() {
            let id = tx.aa_transaction_id()?;
            self.aa_2d_pool
                .read()
                .get_by_id(&id)
                .map(|replaced| *replaced.hash())
        } else {
            self.protocol_pool
                .get_transaction_by_sender_and_nonce(tx.sender(), tx.nonce())
                .map(|replaced| *replaced.hash())
        }
    }

    /// Runs a pool removal and stops tracking the fee cost of the removed transactions.
    ///
    /// The fee payer cost lock is held across the removal so a concurrent re-insertion of a
    /// removed transaction is tracked again after it is untracked here.
    fn remove_tracked(
        &self,
        remove: impl FnOnce() -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    ) -> Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>> {
        let mut fee_payer_costs = self.fee_payer_costs.lock();
        let txs = remove();
        fee_payer_costs.remove_all(txs.iter().map(|tx| tx.hash()));
        txs
    }

    /// Drops fee cost entries of transactions that left the pools without being untracked.
    ///
    /// Every pooled transaction is tracked, so more entries than pooled transactions means
    /// stale entries. A small slack keeps this from rescanning the pool on every block.
    fn prune_fee_payer_costs(&self) {
        let mut fee_payer_costs = self.fee_payer_costs.lock();
        let pooled = self.protocol_pool.len() + self.aa_2d_pool.read().len();
        if fee_payer_costs.len() <= pooled + FEE_PAYER_COSTS_PRUNE_SLACK.max(pooled / 8) {
            return;
        }

        let mut hashes: B256Set = self
            .protocol_pool
            .all_transaction_hashes()
            .into_iter()
            .collect();
        hashes.extend(self.aa_2d_pool.read().all_transaction_hashes_iter());
        fee_payer_costs.retain(|hash| hashes.contains(hash));
    }

    /// Inserts a validated transaction into the subpool for its nonce key.
    fn insert_validated_transaction(
        &self,
        fee_payer_costs: &mut PooledFeeCosts,
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
                    if let Some(replaced) = added.replaced() {
                        fee_payer_costs.remove(replaced.hash());
                    }
                    if let Some(pending) = added.as_pending() {
                        fee_payer_costs.remove_all(pending.discarded.iter().map(|tx| tx.hash()));
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
            fee_payer_costs: Arc::clone(&self.fee_payer_costs),
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
        + Send
        + Sync
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

        let outcomes = self
            .protocol_pool
            .validator()
            .validate_transactions_with_origin(origin, transactions)
            .await
            .into_iter()
            .map(|outcome| (origin, outcome))
            .collect();
        self.add_validated_transactions(outcomes)
    }

    async fn add_transactions_with_origins(
        &self,
        transactions: Vec<(TransactionOrigin, Self::Transaction)>,
    ) -> Vec<PoolResult<AddedTransactionOutcome>> {
        if transactions.is_empty() {
            return Vec::new();
        }

        let origins = transactions
            .iter()
            .map(|(origin, _)| *origin)
            .collect::<Vec<_>>();

        let outcomes = self
            .protocol_pool
            .validator()
            .validate_transactions(transactions)
            .await
            .into_iter()
            .zip(origins)
            .map(|(outcome, origin)| (origin, outcome))
            .collect();
        self.add_validated_transactions(outcomes)
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
        self.remove_tracked(|| {
            let mut txs = self.aa_2d_pool.write().remove_transactions(hashes.iter());
            txs.extend(self.protocol_pool.remove_transactions(hashes));
            txs
        })
    }

    fn remove_transactions_and_descendants(
        &self,
        hashes: Vec<B256>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        self.remove_tracked(|| {
            let mut txs = self
                .aa_2d_pool
                .write()
                .remove_transactions_and_descendants(hashes.iter());
            txs.extend(
                self.protocol_pool
                    .remove_transactions_and_descendants(hashes),
            );
            txs
        })
    }

    fn remove_transactions_by_sender(
        &self,
        sender: Address,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        self.remove_tracked(|| {
            let mut txs = self
                .aa_2d_pool
                .write()
                .remove_transactions_by_sender(sender);
            txs.extend(self.protocol_pool.remove_transactions_by_sender(sender));
            txs
        })
    }

    fn prune_transactions(
        &self,
        hashes: Vec<TxHash>,
    ) -> Vec<Arc<ValidPoolTransaction<Self::Transaction>>> {
        self.remove_tracked(|| {
            let mut txs = self.aa_2d_pool.write().remove_transactions(hashes.iter());
            txs.extend(self.protocol_pool.prune_transactions(hashes));
            txs
        })
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
        self.fee_payer_costs
            .lock()
            .remove_all(&update.mined_transactions);
        self.protocol_pool.on_canonical_state_change(update);
        self.aa_2d_pool.write().set_base_fee(pending_basefee);
        self.prune_fee_payer_costs();
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

    use crate::{test_utils::MockProviderStorageExt, transaction::KeychainSubject};
    use alloy_consensus::Header;
    use alloy_primitives::{Signature, U256, address, uint};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;
    use reth_primitives_traits::Recovered;
    use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
    use reth_storage_api::StateProviderFactory;
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
    use tempo_contracts::precompiles::ITIP403Registry;
    use tempo_evm::TempoEvmConfig;
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
        transaction::{KeyAuthorization, PrimitiveSignature, SignatureType},
    };

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
        let pool = TempoTransactionPool::new(protocol_pool, AA2dPool::new(Default::default()));

        pooled.set_resolved_fee_token(PATH_USD_ADDRESS);
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

    fn create_test_pool_with_2d_config(
        provider: MockEthProvider<TempoPrimitives, TempoChainSpec>,
        aa_2d_config: crate::tt_2d_pool::AA2dPoolConfig,
    ) -> TempoTransactionPool<MockEthProvider<TempoPrimitives, TempoChainSpec>> {
        let pool = create_test_pool(provider);
        TempoTransactionPool::new(pool.protocol_pool, AA2dPool::new(aa_2d_config))
    }

    /// Builds an AA transaction paid by `fee_payer` in `PATH_USD`.
    fn sponsored_tx(
        builder: crate::test_utils::TxBuilder,
        sender: Address,
        fee_payer: &PrivateKeySigner,
    ) -> TempoPooledTransaction {
        let envelope = builder
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
            fee_payer
                .sign_hash_sync(&fee_payer_hash)
                .expect("fee payer signing should succeed"),
        );
        let pooled = TempoPooledTransaction::new(Recovered::new_unchecked(
            TempoTxEnvelope::AA(signed),
            sender,
        ));
        pooled.set_resolved_fee_token(PATH_USD_ADDRESS);
        pooled
    }

    fn valid_with_balance(
        pooled: TempoPooledTransaction,
        balance: U256,
    ) -> TransactionValidationOutcome<TempoPooledTransaction> {
        pooled.set_fee_payer_balance(balance);
        TransactionValidationOutcome::Valid {
            balance: *pooled.cost(),
            state_nonce: 0,
            bytecode_hash: None,
            transaction: ValidTransaction::new(pooled, None),
            propagate: true,
            authorities: None,
        }
    }

    /// Adds `pooled` as if validation read `balance` for its fee payer.
    fn add_with_balance(
        pool: &TempoTransactionPool<MockEthProvider<TempoPrimitives, TempoChainSpec>>,
        pooled: TempoPooledTransaction,
        balance: U256,
    ) -> PoolResult<AddedTransactionOutcome> {
        pool.add_validated_transaction(
            TransactionOrigin::External,
            valid_with_balance(pooled, balance),
        )
    }

    fn assert_fee_payer_cost_rejected(result: PoolResult<AddedTransactionOutcome>) {
        let err = result.expect_err("fee payer cost should exceed balance");
        let PoolErrorKind::InvalidTransaction(err) = &err.kind else {
            panic!("expected invalid transaction, got {err:?}");
        };
        assert!(
            matches!(
                err.downcast_other_ref::<TempoPoolTransactionError>(),
                Some(TempoPoolTransactionError::FeePayerPooledCostExceedsBalance { .. })
            ),
            "unexpected error: {err:?}"
        );
    }

    /// Asserts that the tracked fee payer costs match the pools' contents once stale entries
    /// are pruned.
    fn assert_fee_payer_costs_consistent(
        pool: &TempoTransactionPool<MockEthProvider<TempoPrimitives, TempoChainSpec>>,
    ) {
        let mut expected: HashMap<FeePayerKey, U256> = HashMap::default();
        let hashes: B256Set = pool
            .all_transactions()
            .iter()
            .map(|tx| {
                let key = tx.transaction.fee_payer_key().expect("fee payer");
                let total = expected.entry(key).or_default();
                *total += tx.transaction.fee_token_cost();
                *tx.hash()
            })
            .collect();

        let mut fee_payer_costs = pool.fee_payer_costs.lock();
        fee_payer_costs.retain(|hash| hashes.contains(hash));
        assert_eq!(fee_payer_costs.totals(), expected);
        assert_eq!(fee_payer_costs.len(), hashes.len());
    }

    #[test]
    fn sponsored_flood_cannot_evict_tip_zero_2d_transaction() {
        use crate::test_utils::TxBuilder;
        use reth_transaction_pool::SubPoolLimit;

        let pool = create_test_pool_with_2d_config(
            create_provider_with_tip(),
            crate::tt_2d_pool::AA2dPoolConfig {
                pending_limit: SubPoolLimit::new(2, usize::MAX),
                ..Default::default()
            },
        );

        // Zones settlement style transaction: self-paid, nonce key 1, zero tip.
        let settler = PrivateKeySigner::random();
        let settlement = sponsored_tx(
            TxBuilder::aa(settler.address())
                .nonce_key(U256::ONE)
                .max_priority_fee(0),
            settler.address(),
            &settler,
        );
        let settlement_hash = *settlement.hash();
        add_with_balance(&pool, settlement, U256::MAX).expect("settlement should be admitted");

        // Fee payer funded for exactly one flood transaction.
        let fee_payer = PrivateKeySigner::random();
        let flood: Vec<_> = (0..5)
            .map(|_| {
                let sender = Address::random();
                sponsored_tx(
                    TxBuilder::aa(sender)
                        .nonce_key(U256::ONE)
                        .max_priority_fee(1_000_000_000),
                    sender,
                    &fee_payer,
                )
            })
            .collect();
        let balance = flood[0].fee_token_cost();

        let mut flood = flood.into_iter();
        let admitted = flood.next().unwrap();
        let admitted_hash = *admitted.hash();
        add_with_balance(&pool, admitted, balance).expect("first flood tx fits the balance");
        for tx in flood {
            assert_fee_payer_cost_rejected(add_with_balance(&pool, tx, balance));
        }

        assert!(pool.contains(&settlement_hash));
        assert!(pool.contains(&admitted_hash));
        assert_eq!(
            pool.pooled_fee_cost(PATH_USD_ADDRESS, fee_payer.address()),
            balance
        );
        assert_fee_payer_costs_consistent(&pool);

        pool.remove_transactions(vec![settlement_hash, admitted_hash]);
        assert_eq!(
            pool.pooled_fee_cost(PATH_USD_ADDRESS, fee_payer.address()),
            U256::ZERO
        );
        assert_eq!(pool.fee_payer_costs.lock().len(), 0);
    }

    #[test]
    fn fee_payer_funded_for_k_transactions_admits_k() {
        use crate::test_utils::TxBuilder;

        let pool = create_test_pool(create_provider_with_tip());
        let fee_payer = PrivateKeySigner::random();
        let txs: Vec<_> = (0..6)
            .map(|_| {
                let sender = Address::random();
                sponsored_tx(TxBuilder::aa(sender), sender, &fee_payer)
            })
            .collect();
        let cost = txs[0].fee_token_cost();
        let balance = cost * U256::from(3);

        let mut admitted = Vec::new();
        let mut rejected = Vec::new();
        for tx in txs {
            let hash = *tx.hash();
            match add_with_balance(&pool, tx.clone(), balance) {
                Ok(_) => admitted.push(hash),
                Err(_) => rejected.push(tx),
            }
        }
        assert_eq!(admitted.len(), 3);
        assert_eq!(rejected.len(), 3);
        assert_eq!(
            pool.pooled_fee_cost(PATH_USD_ADDRESS, fee_payer.address()),
            balance
        );

        // Removing through the pool frees room for one more transaction.
        pool.remove_transactions(vec![admitted[0]]);
        add_with_balance(&pool, rejected[0].clone(), balance)
            .expect("removal frees fee payer balance");
        assert_fee_payer_cost_rejected(add_with_balance(&pool, rejected[1].clone(), balance));

        // The protocol pool can drop transactions without telling us (mined, discarded). The
        // rejection path reconciles against the pool before rejecting.
        pool.protocol_pool.remove_transactions(vec![admitted[1]]);
        add_with_balance(&pool, rejected[1].clone(), balance)
            .expect("stale entries are pruned before rejecting");
        assert_fee_payer_cost_rejected(add_with_balance(&pool, rejected[2].clone(), balance));
        assert_fee_payer_costs_consistent(&pool);

        // A larger balance read at validation admits more.
        add_with_balance(&pool, rejected[2].clone(), balance + cost)
            .expect("higher balance admits another transaction");
        assert_fee_payer_costs_consistent(&pool);

        let all = pool.all_transaction_hashes();
        pool.remove_transactions(all);
        assert_eq!(
            pool.pooled_fee_cost(PATH_USD_ADDRESS, fee_payer.address()),
            U256::ZERO
        );
        assert_eq!(pool.fee_payer_costs.lock().len(), 0);
    }

    #[test]
    fn batch_admission_counts_earlier_transactions_in_the_batch() {
        use crate::test_utils::TxBuilder;

        let pool = create_test_pool(create_provider_with_tip());
        let fee_payer = PrivateKeySigner::random();
        let txs: Vec<_> = (0..3)
            .map(|_| {
                let sender = Address::random();
                sponsored_tx(TxBuilder::aa(sender), sender, &fee_payer)
            })
            .collect();
        let balance = txs[0].fee_token_cost() * U256::from(2);

        let results = pool.add_validated_transactions(
            txs.into_iter()
                .map(|tx| (TransactionOrigin::External, valid_with_balance(tx, balance)))
                .collect(),
        );
        let mut results = results.into_iter();
        results.next().unwrap().expect("first fits");
        results.next().unwrap().expect("second fits");
        assert_fee_payer_cost_rejected(results.next().unwrap());
        assert_fee_payer_costs_consistent(&pool);
    }

    #[test]
    fn replacement_does_not_double_count_fee_payer_cost() {
        use crate::test_utils::TxBuilder;

        let pool = create_test_pool(create_provider_with_tip());
        let fee_payer = PrivateKeySigner::random();

        for nonce_key in [U256::ZERO, U256::ONE] {
            let sender = Address::random();
            let original = sponsored_tx(
                TxBuilder::aa(sender).nonce_key(nonce_key),
                sender,
                &fee_payer,
            );
            let replacement = sponsored_tx(
                TxBuilder::aa(sender)
                    .nonce_key(nonce_key)
                    .max_fee(30_000_000_000)
                    .max_priority_fee(2_000_000_000),
                sender,
                &fee_payer,
            );
            // The balance covers the replacement alone, not both.
            let balance = replacement.fee_token_cost();
            assert!(original.fee_token_cost() + replacement.fee_token_cost() > balance);

            let original_hash = *original.hash();
            let replacement_hash = *replacement.hash();
            add_with_balance(&pool, original, balance).expect("original fits");
            add_with_balance(&pool, replacement, balance).expect("replacement fits");

            assert!(!pool.contains(&original_hash));
            assert!(pool.contains(&replacement_hash));
            assert_eq!(
                pool.pooled_fee_cost(PATH_USD_ADDRESS, fee_payer.address()),
                balance,
                "nonce key {nonce_key}"
            );
            assert_fee_payer_costs_consistent(&pool);

            pool.remove_transactions(vec![replacement_hash]);
            assert_eq!(
                pool.pooled_fee_cost(PATH_USD_ADDRESS, fee_payer.address()),
                U256::ZERO
            );
        }
        assert_eq!(pool.fee_payer_costs.lock().len(), 0);
    }

    #[test]
    fn mined_transactions_release_fee_payer_cost() {
        use crate::test_utils::TxBuilder;
        use reth_primitives_traits::SealedBlock;
        use reth_transaction_pool::PoolUpdateKind;
        use revm::database::{AccountStatus, BundleAccount, states::StorageSlot};
        use tempo_precompiles::NONCE_PRECOMPILE_ADDRESS;

        let pool = create_test_pool(create_provider_with_tip());
        let fee_payer = PrivateKeySigner::random();
        let sender_2d = Address::random();
        let tx_2d = sponsored_tx(
            TxBuilder::aa(sender_2d).nonce_key(U256::ONE),
            sender_2d,
            &fee_payer,
        );
        let sender = Address::random();
        let tx_protocol = sponsored_tx(TxBuilder::aa(sender), sender, &fee_payer);
        let balance = tx_2d.fee_token_cost() + tx_protocol.fee_token_cost();
        let nonce_slot = tx_2d.nonce_key_slot().expect("2D nonce slot");
        let protocol_hash = *tx_protocol.hash();

        add_with_balance(&pool, tx_2d, balance).unwrap();
        add_with_balance(&pool, tx_protocol, balance).unwrap();
        assert_eq!(
            pool.pooled_fee_cost(PATH_USD_ADDRESS, fee_payer.address()),
            balance
        );

        // 2D nonce advanced on chain.
        let mut storage = HashMap::default();
        storage.insert(nonce_slot, StorageSlot::new_changed(U256::ZERO, U256::ONE));
        let mut state = AddressMap::default();
        state.insert(
            NONCE_PRECOMPILE_ADDRESS,
            BundleAccount::new(None, None, storage, AccountStatus::Changed),
        );
        assert_eq!(pool.notify_aa_pool_on_state_updates(&state).len(), 1);
        assert_eq!(pool.fee_payer_costs.lock().len(), 1);

        // Protocol nonce transaction mined via reth's canonical update.
        let base_fee = pool.aa_2d_pool.read().base_fee();
        let new_tip = SealedBlock::seal_slow(Block {
            header: TempoHeader {
                inner: Header {
                    gas_limit: TEMPO_T1_TX_GAS_LIMIT_CAP,
                    base_fee_per_gas: Some(base_fee),
                    excess_blob_gas: Some(0),
                    ..Default::default()
                },
                ..Default::default()
            },
            body: Default::default(),
        });
        pool.on_canonical_state_change(CanonicalStateUpdate {
            new_tip: &new_tip,
            pending_block_base_fee: base_fee,
            pending_block_blob_fee: None,
            changed_accounts: Vec::new(),
            mined_transactions: vec![protocol_hash],
            update_kind: PoolUpdateKind::Commit,
        });
        assert!(!pool.contains(&protocol_hash));
        assert_eq!(pool.fee_payer_costs.lock().len(), 0);
        assert_eq!(
            pool.pooled_fee_cost(PATH_USD_ADDRESS, fee_payer.address()),
            U256::ZERO
        );
    }

    #[tokio::test]
    async fn fee_balance_drop_evicts_lowest_priority_until_aggregate_fits() {
        use crate::test_utils::TxBuilder;

        let provider = create_provider_with_tip();
        let fee_payer = PrivateKeySigner::random();
        let txs: Vec<_> = [3_000_000_000u128, 1_000_000_000, 2_000_000_000]
            .into_iter()
            .map(|tip| {
                let sender = Address::random();
                sponsored_tx(
                    TxBuilder::aa(sender)
                        .nonce_key(U256::ONE)
                        .max_priority_fee(tip),
                    sender,
                    &fee_payer,
                )
            })
            .collect();
        let cost = txs[0].fee_token_cost();
        let hashes: Vec<_> = txs.iter().map(|tx| *tx.hash()).collect();
        set_fee_token_balance(
            &provider,
            PATH_USD_ADDRESS,
            fee_payer.address(),
            cost * U256::from(3),
        );
        let pool = create_test_pool(provider.clone());
        for tx in txs {
            add_with_balance(&pool, tx, cost * U256::from(3)).unwrap();
        }

        // Each transaction alone is still affordable, but not all three together.
        set_fee_token_balance(
            &provider,
            PATH_USD_ADDRESS,
            fee_payer.address(),
            cost * U256::from(2),
        );
        let mut updates = crate::maintain::TempoPoolUpdates::new();
        updates
            .fee_balance_changes
            .entry(PATH_USD_ADDRESS)
            .or_default()
            .insert(fee_payer.address());

        let evicted = pool.evict_invalidated_transactions(&updates);
        assert_eq!(tx_hashes(&evicted), vec![hashes[1]]);
        assert!(pool.contains(&hashes[0]));
        assert!(pool.contains(&hashes[2]));
        assert_eq!(
            pool.pooled_fee_cost(PATH_USD_ADDRESS, fee_payer.address()),
            cost * U256::from(2)
        );
        assert_fee_payer_costs_consistent(&pool);

        // Draining the balance below a single fee evicts everything.
        set_fee_token_balance(
            &provider,
            PATH_USD_ADDRESS,
            fee_payer.address(),
            cost - U256::ONE,
        );
        let evicted = pool.evict_invalidated_transactions(&updates);
        assert_eq!(evicted.len(), 2);
        assert_eq!(
            pool.pooled_fee_cost(PATH_USD_ADDRESS, fee_payer.address()),
            U256::ZERO
        );
        assert_eq!(pool.fee_payer_costs.lock().len(), 0);
    }

    #[tokio::test]
    async fn blacklist_eviction_uses_resolved_fee_token() {
        let sender = Address::random();
        let resolved_fee_token = address!("20C0000000000000000000000000000000000002");
        let policy_id = 7;
        let pooled = crate::test_utils::TxBuilder::aa(sender).build();

        assert_eq!(pooled.inner().fee_token(), None);
        pooled.set_resolved_fee_token(resolved_fee_token);

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
        pooled.set_resolved_fee_token(resolved_fee_token);

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
        pooled.set_resolved_fee_token(resolved_fee_token);

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
        let pool = TempoTransactionPool::new(protocol_pool, AA2dPool::new(Default::default()));

        for pooled in [&matching, &untouched] {
            let validated = TransactionValidationOutcome::Valid {
                balance: *pooled.cost(),
                state_nonce: pooled.nonce(),
                bytecode_hash: None,
                transaction: ValidTransaction::new(pooled.clone(), None),
                propagate: true,
                authorities: None,
            };
            pool.add_validated_transaction(TransactionOrigin::External, validated)
                .expect("transaction should be admitted");
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
        let pool = TempoTransactionPool::new(protocol_pool, AA2dPool::new(Default::default()));

        for pooled in [&matching, &untouched] {
            let validated = TransactionValidationOutcome::Valid {
                balance: *pooled.cost(),
                state_nonce: pooled.nonce(),
                bytecode_hash: None,
                transaction: ValidTransaction::new(pooled.clone(), None),
                propagate: true,
                authorities: None,
            };
            pool.add_validated_transaction(TransactionOrigin::External, validated)
                .expect("transaction should be admitted");
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
        let pool = TempoTransactionPool::new(protocol_pool, AA2dPool::new(Default::default()));

        for pooled in [&matching, &untouched] {
            let validated = TransactionValidationOutcome::Valid {
                balance: *pooled.cost(),
                state_nonce: pooled.nonce(),
                bytecode_hash: None,
                transaction: ValidTransaction::new(pooled.clone(), None),
                propagate: true,
                authorities: None,
            };
            pool.add_validated_transaction(TransactionOrigin::External, validated)
                .expect("transaction should be admitted");
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
}
