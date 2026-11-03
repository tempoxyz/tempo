//! An iterator over the best transactions in the tempo pool.

use crate::{
    TempoPoolUpdates,
    ordering::TempoTipOrdering,
    tempo_pool::{exceeds_spending_limit, get_recipient_policy_ids, get_sender_policy_ids},
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
    tt_2d_pool::BestAA2dTransactions,
};
use alloy_primitives::{
    Address, U256,
    map::{AddressMap, AddressSet, HashMap},
};
use evm2::evm::{AccountChangeRef, DynDatabase, StateChangeSink, StateChangeSource, StorageChange};
use reth_evm::BlockTransactionResult;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, Priority, TransactionOrdering, ValidPoolTransaction,
    error::InvalidPoolTransactionError,
};
use std::sync::Arc;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoEvmTypes, TempoStateAccess};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    error::Result as TempoPrecompileResult,
    storage::StorageActions,
    tip_fee_manager::{TipFeeManager, amm::Pool},
    tip20::is_tip20_prefix,
};

pub type BestTransaction = Arc<ValidPoolTransaction<TempoPooledTransaction>>;
type BestTransactionWithPriority = (BestTransaction, Priority<u64>);

/// State changes of the transactions executed so far in the block being built.
#[derive(Debug, Default)]
struct BlockChanges {
    /// Decreased TIP20 balance slots: `(token_address, slot) -> new_balance`.
    decreased_balances: HashMap<(Address, U256), U256>,
    /// Accounts whose configuration commitment changed (TIP-1112).
    changed_commitments: AddressSet,
    /// Current protocol nonce of every account whose nonce changed.
    nonces: AddressMap<u64>,
    /// Whether the validator-token reserve of a fee AMM pool decreased.
    fee_amm_reserve_decreased: bool,
}

impl StateChangeSink for BlockChanges {
    type Error = core::convert::Infallible;

    fn account(&mut self, change: AccountChangeRef<'_>) -> Result<(), Self::Error> {
        if change
            .original
            .map(|info| info.extension.as_ref())
            .unwrap_or_default()
            != change
                .current
                .map(|info| info.extension.as_ref())
                .unwrap_or_default()
        {
            self.changed_commitments.insert(change.address);
        }
        if let Some(current) = change.current
            && change
                .original
                .is_none_or(|original| original.nonce != current.nonce)
        {
            self.nonces.insert(change.address, current.nonce);
        }
        Ok(())
    }

    fn storage(&mut self, change: StorageChange) -> Result<(), Self::Error> {
        if change.address == TIP_FEE_MANAGER_ADDRESS {
            // Slots other than pools decode to arbitrary reserves, which can only cause a
            // superfluous liquidity re-check.
            if Pool::decode_from_slot(change.current).reserve_validator_token
                < Pool::decode_from_slot(change.original).reserve_validator_token
            {
                self.fee_amm_reserve_decreased = true;
            }
            return Ok(());
        }

        if !is_tip20_prefix(change.address) {
            return Ok(());
        }

        if change.current < change.original {
            self.decreased_balances
                .insert((change.address, change.key), change.current);
        } else if let Some(balance) = self
            .decreased_balances
            .get_mut(&(change.address, change.key))
        {
            *balance = change.current;
        }
        Ok(())
    }

    fn storage_read(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), Self::Error> {
        if is_tip20_prefix(address)
            && let Some(balance) = self.decreased_balances.get_mut(&(address, key))
        {
            *balance = value;
        }
        Ok(())
    }
}

/// A best-transaction iterator that merges the protocol pool and the 2D nonces pool,
/// always yielding the next best item from either iterator.
pub struct MergeBestTransactions {
    protocol_pool: Box<dyn BestTransactions<Item = BestTransaction>>,
    aa_2d_pool: BestAA2dTransactions,
    next_protocol_pool: Option<BestTransactionWithPriority>,
    next_aa_2d_pool: Option<BestTransactionWithPriority>,
    base_fee: u64,
}

impl MergeBestTransactions {
    /// Creates a new iterator over the given iterators.
    pub(crate) fn new(
        protocol_pool: Box<dyn BestTransactions<Item = BestTransaction>>,
        aa_2d_pool: BestAA2dTransactions,
        base_fee: u64,
    ) -> Self {
        Self {
            protocol_pool,
            aa_2d_pool,
            next_protocol_pool: None,
            next_aa_2d_pool: None,
            base_fee,
        }
    }
}

impl MergeBestTransactions {
    /// Returns the next transaction from either pool with the higher priority.
    fn next_best(&mut self) -> Option<BestTransactionWithPriority> {
        if self.next_protocol_pool.is_none() {
            self.next_protocol_pool = self.protocol_pool.next().map(|tx| {
                let priority = TempoTipOrdering::default().priority(&tx.transaction, self.base_fee);
                (tx, priority)
            });
        }
        if self.next_aa_2d_pool.is_none() {
            self.next_aa_2d_pool = self.aa_2d_pool.next_tx_and_priority();
        }

        match (&mut self.next_protocol_pool, &mut self.next_aa_2d_pool) {
            (None, None) => {
                // both iters are done
                None
            }
            // Only the protocol pool has an item - take it
            (Some(_), None) => {
                let (item, priority) = self.next_protocol_pool.take()?;
                Some((item, priority))
            }
            // Only the AA2D pool has an item - take it
            (None, Some(_)) => {
                let (item, priority) = self.next_aa_2d_pool.take()?;
                Some((item, priority))
            }
            // Both pools have items - compare priorities and take the higher one
            (Some((_, protocol_priority)), Some((_, aa_2d_priority))) => {
                // Higher priority value is better
                if protocol_priority >= aa_2d_priority {
                    let (item, priority) = self.next_protocol_pool.take()?;
                    Some((item, priority))
                } else {
                    let (item, priority) = self.next_aa_2d_pool.take()?;
                    Some((item, priority))
                }
            }
        }
    }
}

impl Iterator for MergeBestTransactions {
    type Item = BestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_best().map(|(tx, _)| tx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let buffered = usize::from(self.next_protocol_pool.is_some())
            + usize::from(self.next_aa_2d_pool.is_some());
        let (protocol_lower, protocol_upper) = self.protocol_pool.size_hint();
        let (aa_2d_lower, aa_2d_upper) = self.aa_2d_pool.size_hint();

        (
            buffered
                .saturating_add(protocol_lower)
                .saturating_add(aa_2d_lower),
            protocol_upper
                .zip(aa_2d_upper)
                .and_then(|(protocol_upper, aa_2d_upper)| protocol_upper.checked_add(aa_2d_upper))
                .and_then(|upper| upper.checked_add(buffered)),
        )
    }
}

impl BestTransactions for MergeBestTransactions {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        if transaction.transaction.is_aa_2d() {
            self.aa_2d_pool.mark_invalid(transaction, kind);
        } else {
            self.protocol_pool.mark_invalid(transaction, kind);
        }
    }

    fn no_updates(&mut self) {
        self.protocol_pool.no_updates();
        self.aa_2d_pool.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.protocol_pool.set_skip_blobs(skip_blobs);
        self.aa_2d_pool.set_skip_blobs(skip_blobs);
    }
}

/// A [`BestTransactions`] wrapper that tracks execution state changes and skips
/// transactions that previously included transactions made unexecutable.
///
/// It applies the invalidations pool maintenance applies once the block commits, while the block
/// is built, so that a single transaction cannot make the builder spend its time budget on
/// many transactions that fail: balance and spending-limit drains, configuration commitment
/// changes, key revocations and authorizations, fee token pauses and policy changes, fee payer
/// fee-token changes, fee AMM liquidity drains and protocol nonce bumps.
pub struct StateAwareBestTransactions<I> {
    inner: I,
    /// State changes of the transactions executed so far.
    changes: BlockChanges,
    /// Invalidation events the transactions executed so far emitted.
    updates: TempoPoolUpdates,
    /// Ordered fallback fee tokens active for the block being built.
    fallback_fee_tokens: &'static [Address],
}

/// The block a [`StateAwareBestTransactions`] fills, for the checks that read its state.
pub struct BlockState<'a> {
    /// State after the transactions executed so far.
    pub db: &'a mut dyn DynDatabase,
    /// Hardfork active for the block.
    pub spec: TempoHardfork,
    /// Block timestamp, in seconds.
    pub timestamp: u64,
    /// Block beneficiary, whose validator token the block's fees are swapped into.
    pub beneficiary: Address,
}

/// Why [`StateAwareBestTransactions`] leaves out a transaction.
enum Skip {
    /// The transaction cannot execute; neither can its descendants.
    Invalid(InvalidPoolTransactionError),
    /// Leave the transaction out without marking it invalid, so that its descendants stay, as
    /// when an earlier transaction raised the sender's protocol nonce past it.
    Omit,
}

impl<I> StateAwareBestTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    /// Wraps an existing [`BestTransactions`] iterator.
    ///
    /// `fallback_fee_tokens` lists the tokens execution may fall back to when no transaction
    /// field or fee-manager rule selects the fee token.
    pub fn new(inner: I, fallback_fee_tokens: &'static [Address]) -> Self {
        Self {
            inner,
            changes: BlockChanges::default(),
            updates: TempoPoolUpdates::default(),
            fallback_fee_tokens,
        }
    }

    /// Processes a new transaction execution result and collects any relevant
    /// state changes and events that might affect other transactions validity.
    pub fn on_new_result<R: BlockTransactionResult<TempoEvmTypes>>(&mut self, result: &R) {
        let result = result.result();
        result.pending_state.visit(&mut self.changes).unwrap();
        for log in &result.result.logs {
            self.updates.apply_log(log);
        }
    }

    /// Returns the next transaction that the transactions executed so far did not make
    /// unexecutable.
    ///
    /// Unlike [`Iterator::next`], it also runs the checks that read `block`'s state:
    /// spending limits, TIP-403 policy membership and fee AMM liquidity.
    pub fn next_with_state(&mut self, mut block: BlockState<'_>) -> Option<I::Item> {
        self.next_inner(Some(&mut block))
    }

    fn next_inner(&mut self, mut block: Option<&mut BlockState<'_>>) -> Option<I::Item> {
        loop {
            let tx = self.inner.next()?;
            match self.invalidation(tx.best_transaction(), block.as_deref_mut()) {
                None => return Some(tx),
                Some(Skip::Invalid(kind)) => self.inner.mark_invalid(&tx, kind),
                Some(Skip::Omit) => {}
            }
        }
    }

    /// Returns why `tx` cannot execute after the transactions executed so far, if it can't.
    ///
    /// Without `block`, the checks that read state pass.
    fn invalidation(
        &self,
        tx: &BestTransaction,
        mut block: Option<&mut BlockState<'_>>,
    ) -> Option<Skip> {
        let pooled = &tx.transaction;
        let invalid = |reason| {
            Some(Skip::Invalid(InvalidPoolTransactionError::other(
                TempoPoolTransactionError::InvalidatedInBlock(reason),
            )))
        };

        let Some(key) = pooled.fee_balance_slot() else {
            debug_assert!(false, "pool transaction must have cached fee_balance_slot");
            return Some(Skip::Omit);
        };
        let fee = pooled.fee_token_cost();
        if let Some(&balance) = self.changes.decreased_balances.get(&key)
            && balance < fee
            && !self.may_use_other_fallback_token(tx, key, fee)
        {
            return Some(Skip::Invalid(InvalidPoolTransactionError::Consensus(
                InvalidTransactionError::InsufficientFunds((balance, fee).into()),
            )));
        }

        // Expiring and 2D nonces live in the nonce manager, not the account nonce.
        if !pooled.is_aa_2d()
            && let Some(&nonce) = self.changes.nonces.get(pooled.sender_ref())
            && tx.nonce() < nonce
        {
            return Some(Skip::Omit);
        }

        if !self.changes.changed_commitments.is_empty()
            && pooled.has_authority_in(&self.changes.changed_commitments)
        {
            return invalid("configuration commitment changed");
        }

        let updates = &self.updates;
        let fee_token = pooled.effective_fee_token();
        if updates.paused_tokens.contains(&fee_token) {
            return invalid("fee token paused");
        }
        if updates.transfer_policy_updates.contains(&fee_token) {
            return invalid("fee token transfer policy changed");
        }
        if updates.quote_token_updates.contains(&fee_token) {
            return invalid("fee token quote token changed");
        }

        if updates.has_keychain_subject_updates()
            || !updates.key_authorization_target_changes.is_empty()
            || !updates.key_authorization_witness_burns.is_empty()
        {
            let keychain_subject = pooled.keychain_subject();
            if !updates.revoked_keys.is_empty()
                && (keychain_subject
                    .as_ref()
                    .is_some_and(|subject| subject.matches_revoked(&updates.revoked_keys))
                    || pooled
                        .key_authorization_signer_subject()
                        .is_some_and(|subject| subject.matches_revoked(&updates.revoked_keys)))
            {
                return invalid("access key revoked");
            }
            if pooled
                .key_authorization_target_subject()
                .is_some_and(|subject| {
                    subject.matches_key_update(&updates.key_authorization_target_changes)
                })
            {
                return invalid("key authorization target changed");
            }
            if pooled
                .key_authorization_witness_subject()
                .is_some_and(|subject| {
                    updates
                        .key_authorization_witness_burns
                        .get(&subject.account)
                        .is_some_and(|witnesses| witnesses.contains(&subject.witness))
                })
            {
                return invalid("key authorization witness burned");
            }
            if let Some(subject) = &keychain_subject
                && pooled.is_sender_paid_fee()
                && (subject.matches_spending_limit_update(&updates.spending_limit_changes)
                    || subject.matches_spending_limit_update(&updates.spending_limit_spends))
                && let Some(block) = block.as_deref_mut()
                && exceeds_spending_limit(&mut block.db, subject, fee, block.timestamp, block.spec)
            {
                return invalid("spending limit exceeded");
            }
        }

        if !updates.user_token_changes.is_empty()
            && pooled.inner().fee_token().is_none()
            && pooled
                .fee_payer()
                .is_ok_and(|fee_payer| updates.user_token_changes.contains(&fee_payer))
        {
            return invalid("fee payer changed its fee token");
        }

        let block = block?;

        if !updates.blacklist_additions.is_empty() || !updates.whitelist_removals.is_empty() {
            let fee_payer = pooled.fee_payer().unwrap_or_else(|_| pooled.sender());
            let restricting = |account| {
                updates
                    .blacklist_additions
                    .iter()
                    .chain(&updates.whitelist_removals)
                    .filter(move |(_, restricted)| *restricted == account)
                    .map(|(policy_id, _)| *policy_id)
            };
            if restricting(fee_payer).next().is_some()
                && let Some(ids) = get_sender_policy_ids(
                    &mut block.db,
                    fee_token,
                    block.spec,
                    &mut AddressMap::default(),
                )
                && restricting(fee_payer).any(|policy_id| ids.contains(&policy_id))
            {
                return invalid("fee payer no longer authorized by the fee token policy");
            }

            // Pre-T8 fee collection also authorizes the fee manager as recipient.
            if restricting(TIP_FEE_MANAGER_ADDRESS).next().is_some()
                && let Some(ids) = get_recipient_policy_ids(&mut block.db, fee_token, block.spec)
                && restricting(TIP_FEE_MANAGER_ADDRESS).any(|policy_id| ids.contains(&policy_id))
            {
                return invalid("fee manager no longer authorized by the fee token policy");
            }
        }

        if self.changes.fee_amm_reserve_decreased {
            let spec = block.spec;
            let beneficiary = block.beneficiary;
            let route = block.db.with_read_only_storage_ctx(
                spec,
                StorageActions::disabled(),
                || -> TempoPrecompileResult<_> {
                    let fee_manager = TipFeeManager::new();
                    let validator_token = fee_manager.get_validator_token(beneficiary)?;
                    let (route, ..) =
                        fee_manager.plan_fee_route(fee_token, validator_token, fee)?;
                    Ok(route)
                },
            );
            // Errors fall through to execution, which reports them.
            if matches!(route, Ok(None)) {
                return invalid("insufficient fee AMM liquidity");
            }
        }

        None
    }

    /// Returns whether execution may pay the fee with another fallback token.
    ///
    /// Untracked balances may have grown during the block, so they count as sufficient.
    fn may_use_other_fallback_token(
        &self,
        tx: &BestTransaction,
        (token, slot): (Address, U256),
        fee: U256,
    ) -> bool {
        tx.transaction.is_fallback_fee_token()
            && self.fallback_fee_tokens.iter().any(|&candidate| {
                // TIP-20 balance slots share a layout.
                candidate != token
                    && self
                        .changes
                        .decreased_balances
                        .get(&(candidate, slot))
                        .is_none_or(|&balance| balance >= fee)
            })
    }
}

impl<I> Iterator for StateAwareBestTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    type Item = I::Item;

    /// Returns the next transaction, skipping only those the checks that need no state rule
    /// out. See [`StateAwareBestTransactions::next_with_state`].
    fn next(&mut self) -> Option<Self::Item> {
        self.next_inner(None)
    }
}

impl<I> BestTransactions for StateAwareBestTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        self.inner.mark_invalid(transaction, kind);
    }

    fn no_updates(&mut self) {
        self.inner.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.inner.set_skip_blobs(skip_blobs);
    }
}

/// [`StateAwareBestTransactions`] iterator item.
pub trait StateAwarePoolTransaction {
    fn best_transaction(&self) -> &BestTransaction;
}

impl StateAwarePoolTransaction for BestTransaction {
    fn best_transaction(&self) -> &BestTransaction {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ordering::TempoTipOrdering,
        test_utils::{TxBuilder, wrap_valid_tx},
        tt_2d_pool::AA2dPool,
    };
    use alloy_primitives::Address;
    use alloy_signer_local::PrivateKeySigner;
    use evm2::evm::{AccountExtension, AccountInfo, InMemoryDB};
    use futures::executor::block_on;
    use reth_primitives_traits::transaction::error::InvalidTransactionError;
    use reth_transaction_pool::{
        Pool, PoolConfig, TransactionOrigin, TransactionPool, blobstore::InMemoryBlobStore,
        test_utils::OkValidator,
    };
    use std::sync::Arc;
    use tempo_chainspec::{hardfork::TempoHardfork, spec::TEMPO_T1_BASE_FEE};
    use tempo_evm::ResolvedFeeToken;
    use tempo_precompiles::{
        DEFAULT_FEE_TOKEN, PATH_USD_ADDRESS,
        account_keychain::{
            AccountKeychain, AuthorizedKey, SpendingLimitState, StoredSignatureType,
        },
        storage::{Handler, StorageCtx, hashmap::HashMapStorageProvider},
        tip20,
    };

    type TestTx = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn tx_with_nonce_key(nonce_key: U256, sender: Address, nonce: u64, priority: u128) -> TestTx {
        Arc::new(wrap_valid_tx(
            TxBuilder::aa(sender)
                .nonce_key(nonce_key)
                .nonce(nonce)
                .max_priority_fee(priority)
                .max_fee(u128::from(TEMPO_T1_BASE_FEE) + priority)
                .build(),
            TransactionOrigin::External,
        ))
    }

    fn protocol_tx(nonce: u64, priority: u128) -> TestTx {
        protocol_tx_for_sender(Address::random(), nonce, priority)
    }

    fn protocol_tx_for_sender(sender: Address, nonce: u64, priority: u128) -> TestTx {
        tx_with_nonce_key(U256::ZERO, sender, nonce, priority)
    }

    fn aa_2d_tx(nonce: u64, priority: u128) -> TestTx {
        aa_2d_tx_for_sequence(Address::random(), nonce, priority)
    }

    fn aa_2d_tx_for_sequence(sender: Address, nonce: u64, priority: u128) -> TestTx {
        tx_with_nonce_key(U256::ONE, sender, nonce, priority)
    }

    fn protocol_best_transactions(
        txs: Vec<TestTx>,
    ) -> Box<dyn BestTransactions<Item = BestTransaction>> {
        let pool = Pool::new(
            OkValidator::<TempoPooledTransaction>::default(),
            TempoTipOrdering::default(),
            InMemoryBlobStore::default(),
            PoolConfig::default(),
        );

        let results = block_on(pool.add_transactions(
            TransactionOrigin::External,
            txs.into_iter().map(|tx| tx.transaction.clone()).collect(),
        ));
        assert!(
            results.iter().all(Result::is_ok),
            "all protocol transactions must be added successfully: {results:?}"
        );
        Box::new(pool.inner().best_transactions())
    }

    fn aa_2d_best_transactions(txs: Vec<TestTx>) -> BestAA2dTransactions {
        let mut pool = AA2dPool::default();
        let mut on_chain_nonces: HashMap<crate::tt_2d_pool::AASequenceId, u64> = HashMap::default();
        for tx in &txs {
            let id = tx
                .transaction
                .aa_transaction_id()
                .expect("AA2D transaction must have an AA transaction id");
            on_chain_nonces
                .entry(id.seq_id)
                .and_modify(|nonce: &mut u64| *nonce = (*nonce).min(id.nonce))
                .or_insert(id.nonce);
        }

        pool.set_base_fee(TEMPO_T1_BASE_FEE);
        for tx in txs {
            let id = tx
                .transaction
                .aa_transaction_id()
                .expect("AA2D transaction must have an AA transaction id");
            let on_chain_nonce = on_chain_nonces[&id.seq_id];
            pool.add_transaction(tx, on_chain_nonce, TempoHardfork::T1)
                .expect("AA2D transaction must be added successfully");
        }
        pool.best_transactions()
    }

    fn merged_best_transactions(
        protocol_txs: Vec<TestTx>,
        aa_2d_txs: Vec<TestTx>,
    ) -> MergeBestTransactions {
        MergeBestTransactions::new(
            protocol_best_transactions(protocol_txs),
            aa_2d_best_transactions(aa_2d_txs),
            TEMPO_T1_BASE_FEE,
        )
    }

    #[test]
    fn test_merge_best_transactions_basic() {
        // Create two mock iterators with different priorities
        // Left: priorities [10, 5, 3]
        // Right: priorities [8, 4, 1]
        // Expected order: [10, 8, 5, 4, 3, 1]
        let tx_a = protocol_tx(0, 10);
        let tx_b = protocol_tx(1, 5);
        let tx_c = protocol_tx(2, 3);
        let tx_d = aa_2d_tx(3, 8);
        let tx_e = aa_2d_tx(4, 4);
        let tx_f = aa_2d_tx(5, 1);
        let mut merged = merged_best_transactions(
            vec![tx_a.clone(), tx_b.clone(), tx_c.clone()],
            vec![tx_d.clone(), tx_e.clone(), tx_f.clone()],
        );

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash())); // priority 10
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_d.hash())); // priority 8
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash())); // priority 5
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_e.hash())); // priority 4
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_c.hash())); // priority 3
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_f.hash())); // priority 1
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_size_hint() {
        let protocol_sender = Address::random();
        let protocol_tx_0 = protocol_tx_for_sender(protocol_sender, 0, 10);
        let protocol_tx_1 = protocol_tx_for_sender(protocol_sender, 1, 9);
        let aa_2d_tx = aa_2d_tx(0, 8);
        let mut merged = merged_best_transactions(
            vec![protocol_tx_0.clone(), protocol_tx_1.clone()],
            vec![aa_2d_tx.clone()],
        );
        merged.no_updates();

        assert_eq!(merged.size_hint(), (0, Some(3)));

        assert_eq!(
            merged.next().map(|tx| *tx.hash()),
            Some(*protocol_tx_0.hash())
        );
        assert_eq!(merged.size_hint(), (1, Some(2)));

        assert_eq!(
            merged.next().map(|tx| *tx.hash()),
            Some(*protocol_tx_1.hash())
        );
        assert_eq!(merged.size_hint(), (1, Some(1)));

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*aa_2d_tx.hash()));
        assert_eq!(merged.size_hint(), (0, Some(0)));
    }

    #[test]
    fn test_merge_best_transactions_empty_left() {
        // Left iterator is empty
        let tx_a = aa_2d_tx(0, 10);
        let tx_b = aa_2d_tx(1, 5);
        let mut merged = merged_best_transactions(vec![], vec![tx_a.clone(), tx_b.clone()]);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_empty_right() {
        // Right iterator is empty
        let tx_a = protocol_tx(0, 10);
        let tx_b = protocol_tx(1, 5);
        let mut merged = merged_best_transactions(vec![tx_a.clone(), tx_b.clone()], vec![]);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_both_empty() {
        let mut merged = merged_best_transactions(vec![], vec![]);

        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_equal_priorities() {
        // When priorities are equal, left should be preferred (based on >= comparison)
        let tx_a = protocol_tx(0, 10);
        let tx_b = protocol_tx(1, 5);
        let tx_c = aa_2d_tx(2, 10);
        let tx_d = aa_2d_tx(3, 5);
        let mut merged = merged_best_transactions(
            vec![tx_a.clone(), tx_b.clone()],
            vec![tx_c.clone(), tx_d.clone()],
        );

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash())); // equal priority, left preferred
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_c.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash())); // equal priority, left preferred
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_d.hash()));
        assert!(merged.next().is_none());
    }

    // ============================================
    // Single item tests
    // ============================================

    #[test]
    fn test_merge_best_transactions_single_left() {
        let tx_a = protocol_tx(0, 10);
        let mut merged = merged_best_transactions(vec![tx_a.clone()], vec![]);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_single_right() {
        let tx_a = aa_2d_tx(0, 10);
        let mut merged = merged_best_transactions(vec![], vec![tx_a.clone()]);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert!(merged.next().is_none());
    }

    // ============================================
    // Interleaved priority tests
    // ============================================

    #[test]
    fn test_merge_best_transactions_interleaved() {
        // Left has higher odd positions, right has higher even positions
        let l1 = protocol_tx(0, 9);
        let l2 = protocol_tx(1, 7);
        let l3 = protocol_tx(2, 5);
        let r1 = aa_2d_tx(3, 10);
        let r2 = aa_2d_tx(4, 6);
        let r3 = aa_2d_tx(5, 4);
        let mut merged = merged_best_transactions(
            vec![l1.clone(), l2.clone(), l3.clone()],
            vec![r1.clone(), r2.clone(), r3.clone()],
        );

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*r1.hash())); // 10
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l1.hash())); // 9
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l2.hash())); // 7
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*r2.hash())); // 6
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l3.hash())); // 5
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*r3.hash())); // 4
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_mark_invalid_routes_aa_2d_to_right_pool() {
        // Invalidating an AA2D tx must NOT propagate to the
        // left-side (protocol) pool.
        let aa_2d_sender = Address::random();
        let l1 = protocol_tx(0, 9);
        let l2 = protocol_tx(1, 7);
        let r1 = aa_2d_tx_for_sequence(aa_2d_sender, 0, 10);
        let r2 = aa_2d_tx_for_sequence(aa_2d_sender, 1, 8);
        let mut merged =
            merged_best_transactions(vec![l1.clone(), l2.clone()], vec![r1.clone(), r2]);

        // Right has highest priority, so R1 is yielded first
        let first = merged.next().unwrap();
        assert_eq!(*first.hash(), *r1.hash());

        // Simulate payload builder marking R1 as invalid
        let kind =
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported);
        merged.mark_invalid(&first, kind);

        // The AA2D descendant must be skipped, while protocol txs still yield.
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l1.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l2.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_mark_invalid_routes_aa_2d_after_later_protocol_next() {
        let aa_2d_sender = Address::random();
        let protocol_sender = Address::random();
        let l1 = protocol_tx_for_sender(protocol_sender, 0, 9);
        let l2 = protocol_tx_for_sender(protocol_sender, 1, 7);
        let r1 = aa_2d_tx_for_sequence(aa_2d_sender, 0, 10);
        let mut merged = merged_best_transactions(vec![l1.clone(), l2.clone()], vec![r1.clone()]);
        let first = merged.next().unwrap();
        let second = merged.next().unwrap();

        assert_eq!(*first.hash(), *r1.hash());
        assert_eq!(*second.hash(), *l1.hash());

        let kind =
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported);
        merged.mark_invalid(&first, kind);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l2.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_mark_invalid_routes_protocol_aa_to_left_pool() {
        let protocol_sender = Address::random();
        let left_tx = protocol_tx_for_sender(protocol_sender, 0, 10);
        let left_descendant = protocol_tx_for_sender(protocol_sender, 1, 9);
        let right_tx = aa_2d_tx(0, 8);
        assert!(left_tx.transaction.is_aa());
        assert!(!left_tx.transaction.is_aa_2d());
        assert!(right_tx.transaction.is_aa_2d());

        let mut merged = merged_best_transactions(
            vec![left_tx.clone(), left_descendant],
            vec![right_tx.clone()],
        );
        let first = merged.next().unwrap();
        assert_eq!(*first.hash(), *left_tx.hash());

        let kind =
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported);
        merged.mark_invalid(&first, kind);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*right_tx.hash()));
        assert!(merged.next().is_none());
    }

    /// Returns whether a transaction survives when `drained` balances drop just below its fee.
    fn state_aware_yields(
        tx: TestTx,
        fallback_fee_tokens: &'static [Address],
        drained: &[Address],
    ) -> bool {
        let (_, slot) = tx.transaction.fee_balance_slot().unwrap();
        let fee = tx.transaction.fee_token_cost();
        assert!(!fee.is_zero());
        let mut best = StateAwareBestTransactions::new(
            protocol_best_transactions(vec![tx]),
            fallback_fee_tokens,
        );
        for &token in drained {
            best.changes
                .decreased_balances
                .insert((token, slot), fee - U256::ONE);
        }
        best.next().is_some()
    }

    #[test]
    fn test_state_aware_skips_only_when_no_fallback_token_can_pay() {
        let t13 = TempoHardfork::T13.fallback_fee_tokens();
        let &[path_usd, ousd] = t13 else {
            panic!("T13 falls back to pathUSD, then OUSD");
        };
        let tx = |resolved| {
            let tx = protocol_tx(0, 0);
            tx.transaction.set_resolved_fee_token(resolved);
            tx
        };
        let fallback = || tx(ResolvedFeeToken::Fallback(path_usd));
        // An explicit token, stored preference, or TIP-20 inference never falls back.
        let selected = || tx(ResolvedFeeToken::Selected(path_usd));

        assert!(state_aware_yields(fallback(), t13, &[path_usd]));
        assert!(!state_aware_yields(fallback(), t13, &[path_usd, ousd]));
        assert!(!state_aware_yields(selected(), t13, &[path_usd]));
        assert!(!state_aware_yields(
            fallback(),
            TempoHardfork::T12.fallback_fee_tokens(),
            &[path_usd]
        ));
    }

    type TestStateAware =
        StateAwareBestTransactions<Box<dyn BestTransactions<Item = BestTransaction>>>;

    const TEST_SPEC: TempoHardfork = TempoHardfork::T13;

    fn state_aware(txs: Vec<TestTx>) -> TestStateAware {
        StateAwareBestTransactions::new(protocol_best_transactions(txs), &[])
    }

    fn next_with_db(best: &mut TestStateAware, db: &mut InMemoryDB) -> Option<TestTx> {
        best.next_with_state(BlockState {
            db,
            spec: TEST_SPEC,
            timestamp: 1,
            beneficiary: Address::ZERO,
        })
    }

    fn fee_token_tx(fee_token: Address) -> TestTx {
        Arc::new(wrap_valid_tx(
            TxBuilder::aa(Address::random())
                .fee_token(fee_token)
                .max_fee(u128::from(TEMPO_T1_BASE_FEE))
                .build(),
            TransactionOrigin::External,
        ))
    }

    fn keychain_tx(user: Address, access_key: &PrivateKeySigner) -> TestTx {
        Arc::new(wrap_valid_tx(
            TxBuilder::aa(user)
                .fee_token(PATH_USD_ADDRESS)
                .max_fee(u128::from(TEMPO_T1_BASE_FEE))
                .build_keychain(user, access_key),
            TransactionOrigin::External,
        ))
    }

    /// Returns a database holding the precompile storage `setup` writes.
    fn db_with_storage(setup: impl FnOnce()) -> InMemoryDB {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TEST_SPEC);
        StorageCtx::enter(&mut storage, setup);
        let mut db = InMemoryDB::default();
        for (address, slot, value) in storage.into_storage() {
            db.insert_account_storage(&address, &slot, &value);
        }
        db
    }

    #[test]
    fn state_aware_omits_raised_protocol_nonce_but_keeps_descendants() {
        let sender = Address::random();
        let mut best = state_aware(vec![
            protocol_tx_for_sender(sender, 0, 1),
            protocol_tx_for_sender(sender, 1, 1),
        ]);
        best.changes.nonces.insert(sender, 1);
        assert_eq!(best.next().map(|tx| tx.nonce()), Some(1));
    }

    #[test]
    fn state_aware_skips_transactions_of_changed_commitment() {
        let sender = Address::random();
        let other = protocol_tx(0, 0);
        let other_hash = *other.hash();
        let mut best = state_aware(vec![protocol_tx_for_sender(sender, 0, 1), other]);
        best.changes.changed_commitments.insert(sender);
        assert_eq!(
            best.map(|tx| *tx.hash()).collect::<Vec<_>>(),
            vec![other_hash]
        );
    }

    #[test]
    fn state_aware_skips_fee_token_paused_or_with_changed_policy() {
        let records: [fn(&mut TempoPoolUpdates, Address); 3] = [
            |updates, token| {
                updates.paused_tokens.insert(token);
            },
            |updates, token| {
                updates.transfer_policy_updates.insert(token);
            },
            |updates, token| {
                updates.quote_token_updates.insert(token);
            },
        ];
        for record in records {
            for (token, yields) in [(PATH_USD_ADDRESS, false), (Address::random(), true)] {
                let mut best = state_aware(vec![fee_token_tx(PATH_USD_ADDRESS)]);
                record(&mut best.updates, token);
                assert_eq!(best.next().is_some(), yields);
            }
        }
    }

    #[test]
    fn state_aware_skips_implicit_fee_token_after_fee_payer_changes_preference() {
        let implicit = protocol_tx(0, 0);
        let fee_payer = implicit.transaction.fee_payer().unwrap();
        let mut best = state_aware(vec![implicit]);
        best.updates.user_token_changes.insert(fee_payer);
        assert!(best.next().is_none());

        let explicit = fee_token_tx(PATH_USD_ADDRESS);
        let fee_payer = explicit.transaction.fee_payer().unwrap();
        let mut best = state_aware(vec![explicit]);
        best.updates.user_token_changes.insert(fee_payer);
        assert!(best.next().is_some());
    }

    #[test]
    fn state_aware_skips_revoked_access_key() {
        let user = Address::random();
        let access_key = PrivateKeySigner::random();
        let mut best = state_aware(vec![keychain_tx(user, &access_key)]);
        best.updates.revoked_keys.insert(user, access_key.address());
        assert!(best.next().is_none());
    }

    #[test]
    fn state_aware_checks_spent_spending_limit_against_block_state() {
        let user = Address::random();
        let access_key = PrivateKeySigner::random();
        let key_id = access_key.address();
        let tx = keychain_tx(user, &access_key);
        let fee = tx.transaction.fee_token_cost();
        let db_with_remaining = |remaining| {
            db_with_storage(|| {
                let mut keychain = AccountKeychain::new();
                keychain.keys[user][key_id]
                    .write(AuthorizedKey {
                        signature_type: StoredSignatureType::Secp256k1,
                        expiry: u64::MAX,
                        enforce_limits: true,
                        is_revoked: false,
                        is_admin: false,
                    })
                    .unwrap();
                keychain.spending_limits[AccountKeychain::spending_limit_key(user, key_id)]
                    [PATH_USD_ADDRESS]
                    .write(SpendingLimitState {
                        remaining,
                        ..Default::default()
                    })
                    .unwrap();
            })
        };
        let spent_best = || {
            let mut best = state_aware(vec![tx.clone()]);
            best.updates
                .spending_limit_spends
                .insert(user, key_id, Some(PATH_USD_ADDRESS));
            best
        };

        assert!(next_with_db(&mut spent_best(), &mut db_with_remaining(fee - U256::ONE)).is_none());
        assert!(next_with_db(&mut spent_best(), &mut db_with_remaining(fee)).is_some());
        // Without block state, execution decides.
        assert!(spent_best().next().is_some());
    }

    #[test]
    fn state_aware_checks_policy_restrictions_against_block_state() {
        let policy_id = 7;
        let tx = fee_token_tx(PATH_USD_ADDRESS);
        let fee_payer = tx.transaction.fee_payer().unwrap();
        let mut db = InMemoryDB::default();
        db.insert_account_storage(
            &PATH_USD_ADDRESS,
            &tip20::slots::TRANSFER_POLICY_ID,
            &(U256::from(policy_id) << (tip20::slots::TRANSFER_POLICY_ID_OFFSET * 8)),
        );

        for (restricted_policy, yields) in [(policy_id, false), (policy_id + 1, true)] {
            let mut best = state_aware(vec![tx.clone()]);
            best.updates
                .blacklist_additions
                .push((restricted_policy, fee_payer));
            assert_eq!(next_with_db(&mut best, &mut db).is_some(), yields);
        }
    }

    #[test]
    fn state_aware_checks_fee_amm_liquidity_after_reserve_decrease() {
        let user_token = TEST_SPEC
            .fallback_fee_tokens()
            .iter()
            .copied()
            .find(|&token| token != DEFAULT_FEE_TOKEN)
            .unwrap();
        let best = || {
            state_aware(vec![
                fee_token_tx(user_token),
                fee_token_tx(DEFAULT_FEE_TOKEN),
            ])
        };
        // The empty database has no liquidity for any pair.
        let mut db = InMemoryDB::default();
        let mut yielded = |best: &mut TestStateAware| {
            core::iter::from_fn(|| next_with_db(best, &mut db))
                .map(|tx| tx.transaction.effective_fee_token())
                .collect::<Vec<_>>()
        };
        let mut drained = best();
        drained.changes.fee_amm_reserve_decreased = true;
        assert_eq!(yielded(&mut drained), vec![DEFAULT_FEE_TOKEN]);
        // Liquidity is admission's concern until a reserve decreases in the block.
        assert_eq!(yielded(&mut best()).len(), 2);
    }

    #[test]
    fn block_changes_track_commitments_nonces_and_fee_amm_reserves() {
        let account = Address::random();
        let original = AccountInfo::default();
        let mut current = AccountInfo {
            nonce: 1,
            ..Default::default()
        };
        let mut changes = BlockChanges::default();
        let record = |changes: &mut BlockChanges, original: &AccountInfo, current: &AccountInfo| {
            changes
                .account(AccountChangeRef {
                    address: account,
                    original: Some(original),
                    current: Some(current),
                    created: false,
                    selfdestructed: false,
                })
                .unwrap();
        };
        record(&mut changes, &original, &current);
        assert!(changes.changed_commitments.is_empty());
        assert_eq!(changes.nonces.get(&account), Some(&1));

        current.extension = AccountExtension::copy_from_slice(&[1]);
        record(&mut changes, &original, &current);
        assert!(changes.changed_commitments.contains(&account));

        let pool = |reserve_validator_token| {
            tempo_precompiles::tip_fee_manager::amm::Pool {
                reserve_user_token: 0,
                reserve_validator_token,
            }
            .encode_to_slot()
            .unwrap()
        };
        let fee_manager_write = |changes: &mut BlockChanges, original, current| {
            changes
                .storage(StorageChange {
                    address: TIP_FEE_MANAGER_ADDRESS,
                    key: U256::ZERO,
                    original,
                    current,
                })
                .unwrap();
        };
        fee_manager_write(&mut changes, pool(1), pool(2));
        assert!(!changes.fee_amm_reserve_decreased);
        fee_manager_write(&mut changes, pool(2), pool(1));
        assert!(changes.fee_amm_reserve_decreased);
    }
}
