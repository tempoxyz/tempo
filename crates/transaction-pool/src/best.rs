//! An iterator over the best transactions in the tempo pool.

use crate::{
    invalidation::{Invalidations, Verdict},
    ordering::TempoTipOrdering,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
    tt_2d_pool::BestAA2dTransactions,
};
use alloy_primitives::{Address, U256, map::HashMap};
use evm2::{DatabaseError, evm::AccountInfo};
use reth_evm::BlockTransactionResult;
use reth_transaction_pool::{
    BestTransactions, Priority, TransactionOrdering, ValidPoolTransaction,
    error::InvalidPoolTransactionError,
};
use std::sync::Arc;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoEvmTypes, TempoStateAccess};
use tempo_precompiles::{storage::StorageActions, tip_fee_manager::TipFeeManager};

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

/// Reads the parent state of the block being built.
pub trait ParentStorage: Send {
    /// Returns the value of `address`'s storage `slot`, or `None` when it cannot be read.
    fn storage(&mut self, address: Address, slot: U256) -> Option<U256>;
}

/// Checks fee AMM routes into the block's validator token against the block's state.
///
/// Admission cannot: it does not know which validator builds the block. This runs the fee
/// manager's own route planning over the parent state and the block's writes, reading each pool
/// once per block.
pub struct FeeRouteCheck {
    validator_token: Address,
    spec: TempoHardfork,
    parent: Box<dyn ParentStorage>,
    /// Parent-state slots read so far.
    cache: HashMap<(Address, U256), U256>,
}

impl FeeRouteCheck {
    /// Creates a route check into `validator_token`, the block beneficiary's token, which it
    /// cannot change within its own block.
    pub fn new(
        validator_token: Address,
        spec: TempoHardfork,
        parent: Box<dyn ParentStorage>,
    ) -> Self {
        Self {
            validator_token,
            spec,
            parent,
            cache: HashMap::default(),
        }
    }

    /// Returns whether the fee AMM can swap `fee` of `token` into the validator token. Unreadable
    /// state leaves the transaction to execution.
    fn has_liquidity(
        &mut self,
        writes: &HashMap<(Address, U256), U256>,
        token: Address,
        fee: U256,
    ) -> bool {
        if token == self.validator_token {
            return true;
        }
        let mut state = BlockStorage {
            writes,
            cache: &mut self.cache,
            parent: &mut *self.parent,
            unreadable: false,
        };
        let validator_token = self.validator_token;
        let route = state.with_read_only_storage_ctx(self.spec, StorageActions::disabled(), || {
            TipFeeManager::new().plan_fee_route(token, validator_token, fee)
        });
        state.unreadable || route.map_or(true, |(route, ..)| route.is_some())
    }
}

/// The block's writes over its parent state.
struct BlockStorage<'a> {
    writes: &'a HashMap<(Address, U256), U256>,
    cache: &'a mut HashMap<(Address, U256), U256>,
    parent: &'a mut dyn ParentStorage,
    unreadable: bool,
}

/// [`TempoStateAccess`] marker for [`BlockStorage`].
struct BlockStorageMarker;

impl TempoStateAccess<BlockStorageMarker> for BlockStorage<'_> {
    fn basic(&mut self, _address: Address) -> Result<AccountInfo, DatabaseError> {
        Ok(AccountInfo::default())
    }

    fn sload(&mut self, address: Address, key: U256) -> Result<U256, DatabaseError> {
        if let Some(&value) = self.writes.get(&(address, key)) {
            return Ok(value);
        }
        if let Some(&value) = self.cache.get(&(address, key)) {
            return Ok(value);
        }
        let Some(value) = self.parent.storage(address, key) else {
            self.unreadable = true;
            return Ok(U256::ZERO);
        };
        self.cache.insert((address, key), value);
        Ok(value)
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
    /// What the unmaintained parent blocks and the transactions executed so far changed.
    changes: Invalidations,
    /// The timestamp of the block being built.
    timestamp: u64,
    /// Fee AMM routes into the block's validator token; without it, execution decides.
    fee_route: Option<FeeRouteCheck>,
}

impl<I> StateAwareBestTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    /// Wraps an existing [`BestTransactions`] iterator for a block at `timestamp`.
    ///
    /// `parents` holds the changes of the parent blocks pool maintenance has not processed yet,
    /// whose invalidated transactions the pool snapshot may still hold.
    pub fn new(
        inner: I,
        timestamp: u64,
        fee_route: Option<FeeRouteCheck>,
        parents: Invalidations,
    ) -> Self {
        Self {
            inner,
            changes: parents,
            timestamp,
            fee_route,
        }
    }

    /// Processes a new transaction execution result and collects any relevant
    /// state changes that might affect other transactions validity.
    pub fn on_new_result<R: BlockTransactionResult<TempoEvmTypes>>(&mut self, result: &R) {
        self.changes.on_transaction_result(result);
    }
}

impl<I> Iterator for StateAwareBestTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let tx = self.inner.next()?;
            let pooled = &tx.best_transaction().transaction;
            // Time bounds depend on the block, not on state: such a transaction may still
            // execute in a later block.
            if !pooled.is_executable_at(self.timestamp) {
                continue;
            }
            let Self {
                changes, fee_route, ..
            } = self;
            let verdict = changes.verdict(pooled, |_, token, fee| {
                fee_route
                    .as_mut()
                    .is_none_or(|check| check.has_liquidity(&changes.slots, token, fee))
            });
            match verdict {
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
    use alloy_primitives::{U256, map::HashMap};

    use crate::preconditions::{Condition, Preconditions};
    use futures::executor::block_on;
    use reth_primitives_traits::transaction::error::InvalidTransactionError;
    use reth_transaction_pool::{
        Pool, PoolConfig, TransactionOrigin, TransactionPool, blobstore::InMemoryBlobStore,
        test_utils::OkValidator,
    };
    use tempo_chainspec::{hardfork::TempoHardfork, spec::TEMPO_T1_BASE_FEE};
    use tempo_precompiles::PATH_USD_ADDRESS;

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

    type TestStateAware =
        StateAwareBestTransactions<Box<dyn BestTransactions<Item = BestTransaction>>>;

    const TIMESTAMP: u64 = 1_000;

    fn state_aware(txs: Vec<TestTx>) -> TestStateAware {
        StateAwareBestTransactions::new(
            protocol_best_transactions(txs),
            TIMESTAMP,
            None,
            Invalidations::default(),
        )
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

    /// Returns a transaction whose validation recorded `preconditions` on a slot of `ADDRESS`.
    fn tx_with(conditions: &[(U256, Condition)]) -> TestTx {
        let tx = fee_token_tx(PATH_USD_ADDRESS);
        tx.transaction
            .set_preconditions(Preconditions::from_conditions(
                conditions
                    .iter()
                    .map(|&(slot, condition)| (ADDRESS, slot, condition)),
            ));
        tx
    }

    const ADDRESS: Address = PATH_USD_ADDRESS;

    /// Returns whether `tx` survives a block that wrote `value` to `slot`.
    fn yields_after_write(tx: TestTx, slot: U256, value: U256) -> bool {
        let mut best = state_aware(vec![tx]);
        best.changes
            .record_storage(ADDRESS, slot, U256::ZERO, value);
        best.next().is_some()
    }

    #[test]
    fn state_aware_skips_only_writes_that_break_a_precondition() {
        let slot = U256::from(7);
        let equals = || tx_with(&[(slot, Condition::Equals(U256::from(5)))]);
        assert!(yields_after_write(equals(), slot, U256::from(5)));
        assert!(!yields_after_write(equals(), slot, U256::from(6)));
        // Writes to other slots do not matter.
        assert!(yields_after_write(equals(), U256::from(8), U256::from(6)));

        let at_least = || tx_with(&[(slot, Condition::AtLeast(U256::from(100)))]);
        assert!(yields_after_write(at_least(), slot, U256::from(100)));
        assert!(!yields_after_write(at_least(), slot, U256::from(99)));

        let below = || tx_with(&[(slot, Condition::Below(U256::from(100)))]);
        assert!(yields_after_write(below(), slot, U256::from(99)));
        assert!(!yields_after_write(below(), slot, U256::from(100)));

        // A periodic limit spent to exactly zero stores the T7 sentinel.
        let remaining = || tx_with(&[(slot, Condition::RemainingAtLeast(U256::from(10)))]);
        assert!(yields_after_write(remaining(), slot, U256::from(10)));
        assert!(!yields_after_write(remaining(), slot, U256::MAX));
    }

    #[test]
    fn state_aware_leaves_out_moved_nonce_lanes_without_marking_them() {
        let slot = U256::from(9);
        let lane = || tx_with(&[(slot, Condition::LaneAtMost(3))]);
        assert!(yields_after_write(lane(), slot, U256::from(3)));
        let mut best = state_aware(vec![lane()]);
        best.changes
            .record_storage(ADDRESS, slot, U256::ZERO, U256::from(4));
        assert!(best.next().is_none());
    }

    #[test]
    fn state_aware_checks_the_parent_blocks_maintenance_has_not_processed() {
        let slot = U256::from(7);
        let mut parents = Invalidations::default();
        parents.record_storage(ADDRESS, slot, U256::ZERO, U256::from(6));
        let mut best = StateAwareBestTransactions::new(
            protocol_best_transactions(vec![tx_with(&[(slot, Condition::Equals(U256::from(5)))])]),
            TIMESTAMP,
            None,
            parents,
        );
        assert!(best.next().is_none());
    }

    #[test]
    fn state_aware_skips_transactions_outside_the_block_time_bounds() {
        let tx = |builder: TxBuilder| {
            Arc::new(wrap_valid_tx(
                builder.max_fee(u128::from(TEMPO_T1_BASE_FEE)).build(),
                TransactionOrigin::External,
            ))
        };
        let sender = Address::random();
        assert!(
            state_aware(vec![tx(TxBuilder::aa(sender).valid_after(TIMESTAMP + 1))])
                .next()
                .is_none()
        );
        assert!(
            state_aware(vec![tx(TxBuilder::aa(sender).valid_before(TIMESTAMP))])
                .next()
                .is_none()
        );
        assert!(
            state_aware(vec![tx(TxBuilder::aa(sender).valid_after(TIMESTAMP))])
                .next()
                .is_some()
        );
    }

    #[test]
    fn state_aware_skips_transactions_whose_authority_changed_its_code() {
        let tx = fee_token_tx(PATH_USD_ADDRESS);
        let mut best = state_aware(vec![tx.clone()]);
        best.changes.changed_accounts.insert(tx.sender());
        assert!(best.next().is_none());
    }
}
