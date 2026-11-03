//! An iterator over the best transactions in the tempo pool.

use crate::{
    invalidation::{InvalidationState, Invalidations, Verdict},
    ordering::TempoTipOrdering,
    tempo_pool::{get_recipient_policy_ids, get_sender_policy_ids},
    transaction::{KeychainSubject, TempoPoolTransactionError, TempoPooledTransaction},
    tt_2d_pool::BestAA2dTransactions,
};
use alloy_primitives::{Address, U256, map::AddressMap};
use evm2::evm::DynDatabase;
use reth_evm::BlockTransactionResult;
use reth_transaction_pool::{
    BestTransactions, Priority, TransactionOrdering, ValidPoolTransaction,
    error::InvalidPoolTransactionError,
};
use std::sync::Arc;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoEvmTypes, TempoStateAccess};
use tempo_precompiles::{
    error::Result as TempoPrecompileResult,
    storage::{StorageActions, StorageKey},
    tip_fee_manager::{TipFeeManager, amm::compute_amount_out},
};

pub type BestTransaction = Arc<ValidPoolTransaction<TempoPooledTransaction>>;
type BestTransactionWithPriority = (BestTransaction, Priority<u64>);

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
/// It asks the same [`Invalidations`] pool maintenance asks once the block commits, so that a
/// single transaction cannot make the builder spend its time budget on many transactions that
/// fail. It skips transactions that may need revalidation too: they wait for the next block,
/// after maintenance revalidates them.
pub struct StateAwareBestTransactions<I> {
    inner: I,
    /// What the transactions executed so far changed.
    changes: Invalidations,
    /// Ordered fallback fee tokens active for the block being built.
    fallback_fee_tokens: &'static [Address],
    /// Sender policy IDs read so far, by fee token.
    policy_cache: AddressMap<Vec<u64>>,
    /// The block beneficiary's validator token, read once.
    validator_token: Option<Address>,
}

/// The block a [`StateAwareBestTransactions`] fills, for the rare checks that read its state.
pub struct BlockState<'a> {
    /// State after the transactions executed so far.
    pub db: &'a mut dyn DynDatabase,
    /// Hardfork active for the block.
    pub spec: TempoHardfork,
    /// Block beneficiary, whose validator token the block's fees are swapped into.
    pub beneficiary: Address,
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
            changes: Invalidations::default(),
            fallback_fee_tokens,
            policy_cache: AddressMap::default(),
            validator_token: None,
        }
    }

    /// Processes a new transaction execution result and collects any relevant
    /// state changes and events that might affect other transactions validity.
    pub fn on_new_result<R: BlockTransactionResult<TempoEvmTypes>>(&mut self, result: &R) {
        self.changes.on_transaction_result(result);
    }

    /// Returns the next transaction that the transactions executed so far did not make
    /// unexecutable.
    ///
    /// Unlike [`Iterator::next`], it also runs the checks that read `block`'s state: TIP-403
    /// policy IDs of a fee token whose payer a policy restricted, and fee AMM routes whose direct
    /// pool can no longer pay.
    pub fn next_with_state(&mut self, block: BlockState<'_>) -> Option<I::Item> {
        self.next_inner(Some(block))
    }

    fn next_inner(&mut self, mut block: Option<BlockState<'_>>) -> Option<I::Item> {
        loop {
            let tx = self.inner.next()?;
            let mut state = BuilderInvalidationState {
                block: block.as_mut(),
                policy_cache: &mut self.policy_cache,
                validator_token: &mut self.validator_token,
            };
            match self.changes.verdict(
                &tx.best_transaction().transaction,
                &mut state,
                self.fallback_fee_tokens,
            ) {
                Verdict::Valid => return Some(tx),
                Verdict::Invalid(reason) | Verdict::Revalidate(reason) => self.inner.mark_invalid(
                    &tx,
                    InvalidPoolTransactionError::other(
                        TempoPoolTransactionError::InvalidatedInBlock(reason.as_str()),
                    ),
                ),
                // Leave it out without marking it invalid, so that its descendants stay.
                Verdict::StaleNonce => {}
            }
        }
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

/// Answers [`Invalidations`]'s reads for the payload builder.
///
/// Spending limits and most liquidity checks need no reads: the transactions executed so far
/// wrote the values. Without a block, the checks that would read state pass.
struct BuilderInvalidationState<'a, 'b> {
    block: Option<&'a mut BlockState<'b>>,
    policy_cache: &'a mut AddressMap<Vec<u64>>,
    validator_token: &'a mut Option<Address>,
}

impl InvalidationState for BuilderInvalidationState<'_, '_> {
    fn exceeds_spending_limit(
        &mut self,
        changes: &Invalidations,
        subject: &KeychainSubject,
        fee: U256,
    ) -> bool {
        changes
            .written_spending_limit(subject)
            .is_some_and(|remaining| remaining < fee)
    }

    fn has_fee_liquidity(&mut self, changes: &Invalidations, token: Address, fee: U256) -> bool {
        let Some(block) = self.block.as_deref_mut() else {
            return true;
        };
        let spec = block.spec;
        let beneficiary = block.beneficiary;
        let validator_token =
            match *self.validator_token {
                Some(token) => token,
                // A block's beneficiary cannot change its validator token within the block.
                None => match block.db.with_read_only_storage_ctx(
                    spec,
                    StorageActions::disabled(),
                    || TipFeeManager::new().get_validator_token(beneficiary),
                ) {
                    Ok(token) => *self.validator_token.insert(token),
                    Err(_) => return true,
                },
            };
        if token == validator_token {
            return true;
        }

        let fee_manager = TipFeeManager::new();
        let direct = fee_manager
            .pool_id(token, validator_token)
            .mapping_slot(fee_manager.pools.slot());
        // An untouched direct pool still pays as at admission. Two-hop routes whose legs were
        // drained are left to execution.
        let Some(pool) = changes.decreased_pool(direct) else {
            return true;
        };
        if compute_amount_out(fee).is_ok_and(|out| pool.has_enough_reserve_validator_token(out)) {
            return true;
        }
        let route = block.db.with_read_only_storage_ctx(
            spec,
            StorageActions::disabled(),
            || -> TempoPrecompileResult<_> {
                let (route, ..) =
                    TipFeeManager::new().plan_fee_route(token, validator_token, fee)?;
                Ok(route)
            },
        );
        // Errors fall through to execution, which reports them.
        !matches!(route, Ok(None))
    }

    fn sender_policy_ids(&mut self, token: Address) -> Option<Vec<u64>> {
        let block = self.block.as_deref_mut()?;
        get_sender_policy_ids(&mut block.db, token, block.spec, self.policy_cache)
    }

    fn recipient_policy_ids(&mut self, token: Address) -> Option<Vec<u64>> {
        let block = self.block.as_deref_mut()?;
        get_recipient_policy_ids(&mut block.db, token, block.spec)
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
    use alloy_primitives::{Address, map::HashMap};
    use alloy_signer_local::PrivateKeySigner;
    use evm2::evm::InMemoryDB;
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
        ACCOUNT_KEYCHAIN_ADDRESS, DEFAULT_FEE_TOKEN, PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        account_keychain::AccountKeychain, tip20,
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
        let records: [fn(&mut crate::TempoPoolUpdates, Address); 3] = [
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
                record(&mut best.changes.events, token);
                assert_eq!(best.next().is_some(), yields);
            }
        }
    }

    #[test]
    fn state_aware_skips_implicit_fee_token_after_fee_payer_changes_preference() {
        let implicit = protocol_tx(0, 0);
        let fee_payer = implicit.transaction.fee_payer().unwrap();
        let mut best = state_aware(vec![implicit]);
        best.changes.events.user_token_changes.insert(fee_payer);
        assert!(best.next().is_none());

        let explicit = fee_token_tx(PATH_USD_ADDRESS);
        let fee_payer = explicit.transaction.fee_payer().unwrap();
        let mut best = state_aware(vec![explicit]);
        best.changes.events.user_token_changes.insert(fee_payer);
        assert!(best.next().is_some());
    }

    #[test]
    fn state_aware_skips_revoked_access_key() {
        let user = Address::random();
        let access_key = PrivateKeySigner::random();
        let mut best = state_aware(vec![keychain_tx(user, &access_key)]);
        best.changes
            .events
            .revoked_keys
            .insert(user, access_key.address());
        assert!(best.next().is_none());
    }

    #[test]
    fn state_aware_checks_spending_limit_the_block_wrote() {
        let user = Address::random();
        let access_key = PrivateKeySigner::random();
        let key_id = access_key.address();
        let tx = keychain_tx(user, &access_key);
        let fee = tx.transaction.fee_token_cost();
        let remaining_slot = AccountKeychain::new().spending_limits
            [AccountKeychain::spending_limit_key(user, key_id)][PATH_USD_ADDRESS]
            .remaining
            .slot();
        let spent_to = |remaining| {
            let mut best = state_aware(vec![tx.clone()]);
            best.changes
                .events
                .spending_limit_spends
                .insert(user, key_id, Some(PATH_USD_ADDRESS));
            best.changes.record_storage(
                ACCOUNT_KEYCHAIN_ADDRESS,
                remaining_slot,
                U256::MAX,
                remaining,
            );
            best
        };

        // The spend wrote the remaining limit, so no state is read.
        assert!(spent_to(fee - U256::ONE).next().is_none());
        assert!(spent_to(fee).next().is_some());
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
            best.changes
                .events
                .set_policy_restriction(restricted_policy, fee_payer, true);
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
        let fee_manager = TipFeeManager::new();
        let direct = fee_manager
            .pool_id(user_token, DEFAULT_FEE_TOKEN)
            .mapping_slot(fee_manager.pools.slot());
        let with_reserve = |reserve_validator_token| {
            let mut best = best();
            let original = tempo_precompiles::tip_fee_manager::amm::Pool {
                reserve_user_token: 0,
                reserve_validator_token: u128::MAX,
            };
            let current = tempo_precompiles::tip_fee_manager::amm::Pool {
                reserve_user_token: 0,
                reserve_validator_token,
            };
            best.changes.record_storage(
                TIP_FEE_MANAGER_ADDRESS,
                direct,
                original.encode_to_slot().unwrap(),
                current.encode_to_slot().unwrap(),
            );
            best
        };
        // Drained: the empty database offers no two-hop route either.
        assert_eq!(yielded(&mut with_reserve(0)), vec![DEFAULT_FEE_TOKEN]);
        // Decreased but still enough for the fee.
        assert_eq!(yielded(&mut with_reserve(u128::MAX - 1)).len(), 2);
        // Liquidity is admission's concern until a reserve decreases in the block.
        assert_eq!(yielded(&mut best()).len(), 2);
    }
}
