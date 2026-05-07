//! An iterator over the best transactions in the tempo pool.

use crate::transaction::TempoPooledTransaction;
use alloy_primitives::{Address, B256, U256, map::HashMap};
use reth_evm::block::TxResult;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::{
    BestTransactions, CoinbaseTipOrdering, Priority, TransactionOrdering, ValidPoolTransaction,
    error::InvalidPoolTransactionError,
};
use std::sync::Arc;
use tempo_evm::TempoTxResult;
use tempo_precompiles::tip20::is_tip20_prefix;

/// An extension trait for [`BestTransactions`] that in addition to the transaction also yields the priority value.
pub trait BestPriorityTransactions<T: TransactionOrdering>: BestTransactions {
    /// Returns the next best transaction and its priority value.
    fn next_tx_and_priority(&mut self) -> Option<(Self::Item, Priority<T::PriorityValue>)>;
}

impl<T: TransactionOrdering> BestPriorityTransactions<T>
    for reth_transaction_pool::pool::BestTransactions<T>
{
    fn next_tx_and_priority(&mut self) -> Option<(Self::Item, Priority<T::PriorityValue>)> {
        Self::next_tx_and_priority(self)
    }
}
impl BestPriorityTransactions<CoinbaseTipOrdering<TempoPooledTransaction>>
    for crate::tt_2d_pool::BestAA2dTransactions
{
    fn next_tx_and_priority(&mut self) -> Option<(Self::Item, Priority<u128>)> {
        Self::next_tx_and_priority(self)
    }
}

/// Tracks which side of a [`MergeBestTransactions`] yielded a transaction.
#[derive(Debug, Clone, Copy)]
enum MergeSource {
    Left,
    Right,
}

/// A [`BestTransactions`] iterator that merges two individual implementations and always yields the next best item from either of the iterators.
pub struct MergeBestTransactions<L, R, T>
where
    L: BestPriorityTransactions<T, Item = Arc<ValidPoolTransaction<T::Transaction>>>,
    R: BestPriorityTransactions<T, Item = L::Item>,
    T: TransactionOrdering,
{
    left: L,
    right: R,
    next_left: Option<(L::Item, Priority<T::PriorityValue>)>,
    next_right: Option<(L::Item, Priority<T::PriorityValue>)>,
    yielded_sources: HashMap<B256, MergeSource>,
}

impl<L, R, T> MergeBestTransactions<L, R, T>
where
    L: BestPriorityTransactions<T, Item = Arc<ValidPoolTransaction<T::Transaction>>>,
    R: BestPriorityTransactions<T, Item = L::Item>,
    T: TransactionOrdering,
{
    /// Creates a new iterator over the given iterators.
    pub fn new(left: L, right: R) -> Self {
        Self {
            left,
            right,
            next_left: None,
            next_right: None,
            yielded_sources: HashMap::default(),
        }
    }
}

impl<L, R, T> MergeBestTransactions<L, R, T>
where
    L: BestPriorityTransactions<T, Item = Arc<ValidPoolTransaction<T::Transaction>>>,
    R: BestPriorityTransactions<T, Item = L::Item>,
    T: TransactionOrdering,
{
    /// Records the source for a yielded transaction.
    fn record_source(&mut self, item: &L::Item, source: MergeSource) {
        self.yielded_sources.insert(*item.hash(), source);
    }

    /// Returns the next transaction from either the left or the right iterator with the higher priority.
    fn next_best(&mut self) -> Option<(L::Item, Priority<T::PriorityValue>)> {
        if self.next_left.is_none() {
            self.next_left = self.left.next_tx_and_priority();
        }
        if self.next_right.is_none() {
            self.next_right = self.right.next_tx_and_priority();
        }

        match (&mut self.next_left, &mut self.next_right) {
            (None, None) => {
                // both iters are done
                None
            }
            // Only left has an item - take it
            (Some(_), None) => {
                let (item, priority) = self.next_left.take()?;
                self.record_source(&item, MergeSource::Left);
                Some((item, priority))
            }
            // Only right has an item - take it
            (None, Some(_)) => {
                let (item, priority) = self.next_right.take()?;
                self.record_source(&item, MergeSource::Right);
                Some((item, priority))
            }
            // Both sides have items - compare priorities and take the higher one
            (Some((_, left_priority)), Some((_, right_priority))) => {
                // Higher priority value is better
                if left_priority >= right_priority {
                    let (item, priority) = self.next_left.take()?;
                    self.record_source(&item, MergeSource::Left);
                    Some((item, priority))
                } else {
                    let (item, priority) = self.next_right.take()?;
                    self.record_source(&item, MergeSource::Right);
                    Some((item, priority))
                }
            }
        }
    }
}

impl<L, R, T> Iterator for MergeBestTransactions<L, R, T>
where
    L: BestPriorityTransactions<T, Item = Arc<ValidPoolTransaction<T::Transaction>>>,
    R: BestPriorityTransactions<T, Item = L::Item>,
    T: TransactionOrdering,
{
    type Item = L::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_best().map(|(tx, _)| tx)
    }
}

impl<L, R, T> BestTransactions for MergeBestTransactions<L, R, T>
where
    L: BestPriorityTransactions<T, Item = Arc<ValidPoolTransaction<T::Transaction>>> + Send,
    R: BestPriorityTransactions<T, Item = L::Item> + Send,
    T: TransactionOrdering,
{
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: &InvalidPoolTransactionError) {
        match self.yielded_sources.get(transaction.hash()).copied() {
            Some(MergeSource::Left) => self.left.mark_invalid(transaction, kind),
            Some(MergeSource::Right) => self.right.mark_invalid(transaction, kind),
            None => {
                self.left.mark_invalid(transaction, kind);
                self.right.mark_invalid(transaction, kind);
            }
        }
    }

    fn no_updates(&mut self) {
        self.left.no_updates();
        self.right.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.left.set_skip_blobs(skip_blobs);
        self.right.set_skip_blobs(skip_blobs);
    }
}

/// A [`BestTransactions`] wrapper that tracks execution state changes and skips
/// transactions that would fail due to state mutations from previously
/// included transactions.
pub struct StateAwareBestTransactions<I> {
    inner: I,
    /// Tracks decreased TIP20 balance slots: `(token_address, slot) -> new_balance`.
    /// Updated after each executed transaction. Used to check if a candidate
    /// transaction's fee payer can still cover its fee cost.
    decreased_balances: HashMap<(Address, U256), U256>,
}

impl<I> StateAwareBestTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
{
    /// Wraps an existing [`BestTransactions`] iterator.
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            decreased_balances: HashMap::default(),
        }
    }

    /// Processes a new transaction execution result and collects any relevant
    /// state changes that might affect other transactions validity.
    pub fn on_new_result(&mut self, result: &TempoTxResult) {
        for (&address, account) in &result.result().state {
            if !is_tip20_prefix(address) {
                continue;
            }

            for (&slot, storage_slot) in &account.storage {
                if storage_slot.present_value < storage_slot.original_value {
                    self.decreased_balances
                        .insert((address, slot), storage_slot.present_value);
                }
            }
        }
    }
}

impl<I> Iterator for StateAwareBestTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
{
    type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let tx = self.inner.next()?;

            let Some(key) = tx.transaction.fee_balance_slot() else {
                debug_assert!(false, "pool transaction must have cached fee_balance_slot");
                continue;
            };

            if let Some(&balance) = self.decreased_balances.get(&key)
                && balance < tx.transaction.fee_token_cost()
            {
                self.inner.mark_invalid(
                    &tx,
                    &InvalidPoolTransactionError::Consensus(
                        InvalidTransactionError::InsufficientFunds(
                            (balance, tx.transaction.fee_token_cost()).into(),
                        ),
                    ),
                );
                continue;
            }

            return Some(tx);
        }
    }
}

impl<I> BestTransactions for StateAwareBestTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + Send,
{
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: &InvalidPoolTransactionError) {
        self.inner.mark_invalid(transaction, kind);
    }

    fn no_updates(&mut self) {
        self.inner.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.inner.set_skip_blobs(skip_blobs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TxBuilder, wrap_valid_tx};
    use alloy_primitives::Address;
    use reth_primitives_traits::transaction::error::InvalidTransactionError;
    use reth_transaction_pool::TransactionOrigin;
    use std::sync::{Arc, Mutex};

    type MockTx = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn mock_tx(nonce: u64) -> MockTx {
        Arc::new(wrap_valid_tx(
            TxBuilder::aa(Address::random()).nonce(nonce).build(),
            TransactionOrigin::External,
        ))
    }

    /// A simple mock iterator for testing that yields items with priorities
    struct MockBestTransactions<T> {
        items: Vec<(T, Priority<u128>)>,
        index: usize,
        invalidated: Arc<Mutex<Vec<T>>>,
    }

    impl<T> MockBestTransactions<T> {
        fn new(items: Vec<(T, u128)>) -> Self {
            let items = items
                .into_iter()
                .map(|(item, priority)| (item, Priority::Value(priority)))
                .collect();
            Self {
                items,
                index: 0,
                invalidated: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn invalidated(&self) -> Arc<Mutex<Vec<T>>> {
            self.invalidated.clone()
        }
    }

    impl<T: Clone> Iterator for MockBestTransactions<T> {
        type Item = T;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index < self.items.len() {
                let item = self.items[self.index].0.clone();
                self.index += 1;
                Some(item)
            } else {
                None
            }
        }
    }

    impl<T: Clone + Send>
        BestPriorityTransactions<CoinbaseTipOrdering<crate::transaction::TempoPooledTransaction>>
        for MockBestTransactions<T>
    {
        fn next_tx_and_priority(&mut self) -> Option<(Self::Item, Priority<u128>)> {
            if self.index < self.items.len() {
                let (item, priority) = &self.items[self.index];
                let result = (item.clone(), priority.clone());
                self.index += 1;
                Some(result)
            } else {
                None
            }
        }
    }

    impl<T: Clone + Send> BestTransactions for MockBestTransactions<T> {
        fn mark_invalid(&mut self, transaction: &Self::Item, _kind: &InvalidPoolTransactionError) {
            self.invalidated.lock().unwrap().push(transaction.clone());
        }

        fn no_updates(&mut self) {
            // No-op for mock
        }

        fn set_skip_blobs(&mut self, _skip_blobs: bool) {
            // No-op for mock
        }
    }

    #[test]
    fn test_merge_best_transactions_basic() {
        // Create two mock iterators with different priorities
        // Left: priorities [10, 5, 3]
        // Right: priorities [8, 4, 1]
        // Expected order: [10, 8, 5, 4, 3, 1]
        let tx_a = mock_tx(0);
        let tx_b = mock_tx(1);
        let tx_c = mock_tx(2);
        let tx_d = mock_tx(3);
        let tx_e = mock_tx(4);
        let tx_f = mock_tx(5);
        let left = MockBestTransactions::new(vec![
            (tx_a.clone(), 10),
            (tx_b.clone(), 5),
            (tx_c.clone(), 3),
        ]);
        let right = MockBestTransactions::new(vec![
            (tx_d.clone(), 8),
            (tx_e.clone(), 4),
            (tx_f.clone(), 1),
        ]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash())); // priority 10
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_d.hash())); // priority 8
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash())); // priority 5
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_e.hash())); // priority 4
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_c.hash())); // priority 3
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_f.hash())); // priority 1
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_empty_left() {
        // Left iterator is empty
        let tx_a = mock_tx(0);
        let tx_b = mock_tx(1);
        let left = MockBestTransactions::new(vec![]);
        let right = MockBestTransactions::new(vec![(tx_a.clone(), 10), (tx_b.clone(), 5)]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_empty_right() {
        // Right iterator is empty
        let tx_a = mock_tx(0);
        let tx_b = mock_tx(1);
        let left = MockBestTransactions::new(vec![(tx_a.clone(), 10), (tx_b.clone(), 5)]);
        let right = MockBestTransactions::new(vec![]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_both_empty() {
        let left: MockBestTransactions<MockTx> = MockBestTransactions::new(vec![]);
        let right: MockBestTransactions<MockTx> = MockBestTransactions::new(vec![]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_equal_priorities() {
        // When priorities are equal, left should be preferred (based on >= comparison)
        let tx_a = mock_tx(0);
        let tx_b = mock_tx(1);
        let tx_c = mock_tx(2);
        let tx_d = mock_tx(3);
        let left = MockBestTransactions::new(vec![(tx_a.clone(), 10), (tx_b.clone(), 5)]);
        let right = MockBestTransactions::new(vec![(tx_c.clone(), 10), (tx_d.clone(), 5)]);

        let mut merged = MergeBestTransactions::new(left, right);

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
        let tx_a = mock_tx(0);
        let left = MockBestTransactions::new(vec![(tx_a.clone(), 10)]);
        let right: MockBestTransactions<MockTx> = MockBestTransactions::new(vec![]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_single_right() {
        let tx_a = mock_tx(0);
        let left: MockBestTransactions<MockTx> = MockBestTransactions::new(vec![]);
        let right = MockBestTransactions::new(vec![(tx_a.clone(), 10)]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert!(merged.next().is_none());
    }

    // ============================================
    // Interleaved priority tests
    // ============================================

    #[test]
    fn test_merge_best_transactions_interleaved() {
        // Left has higher odd positions, right has higher even positions
        let l1 = mock_tx(0);
        let l2 = mock_tx(1);
        let l3 = mock_tx(2);
        let r1 = mock_tx(3);
        let r2 = mock_tx(4);
        let r3 = mock_tx(5);
        let left =
            MockBestTransactions::new(vec![(l1.clone(), 9), (l2.clone(), 7), (l3.clone(), 5)]);
        let right =
            MockBestTransactions::new(vec![(r1.clone(), 10), (r2.clone(), 6), (r3.clone(), 4)]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*r1.hash())); // 10
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l1.hash())); // 9
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l2.hash())); // 7
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*r2.hash())); // 6
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l3.hash())); // 5
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*r3.hash())); // 4
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_mark_invalid_only_forwards_to_source_pool() {
        // Invalidating a right-side (AA-2D) tx must NOT propagate to the
        // left-side (protocol) pool.
        let l1 = mock_tx(0);
        let l2 = mock_tx(1);
        let r1 = mock_tx(2);
        let left = MockBestTransactions::new(vec![(l1.clone(), 5), (l2.clone(), 3)]);
        let right = MockBestTransactions::new(vec![(r1.clone(), 10)]);

        let left_invalidated = left.invalidated();
        let right_invalidated = right.invalidated();

        let mut merged = MergeBestTransactions::new(left, right);

        // Right has highest priority, so R1 is yielded first
        let first = merged.next().unwrap();
        assert_eq!(*first.hash(), *r1.hash());

        // Simulate payload builder marking R1 as invalid
        let kind =
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported);
        merged.mark_invalid(&first, &kind);

        // Only the right (source) pool should have received the invalidation
        assert!(
            left_invalidated.lock().unwrap().is_empty(),
            "left pool must NOT be invalidated when a right-side tx fails"
        );
        assert_eq!(
            right_invalidated
                .lock()
                .unwrap()
                .iter()
                .map(|tx| *tx.hash())
                .collect::<Vec<_>>(),
            vec![*r1.hash()],
            "right pool must receive the invalidation"
        );

        // Remaining left-side txs must still be yielded
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l1.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l2.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_mark_invalid_uses_original_source_after_later_next() {
        let l1 = mock_tx(0);
        let l2 = mock_tx(1);
        let r1 = mock_tx(2);
        let r2 = mock_tx(3);
        let left = MockBestTransactions::new(vec![(l1.clone(), 9), (l2, 7)]);
        let right = MockBestTransactions::new(vec![(r1.clone(), 10), (r2, 8)]);

        let left_invalidated = left.invalidated();
        let right_invalidated = right.invalidated();

        let mut merged = MergeBestTransactions::new(left, right);
        let first = merged.next().unwrap();
        let second = merged.next().unwrap();

        assert_eq!(*first.hash(), *r1.hash());
        assert_eq!(*second.hash(), *l1.hash());

        let kind =
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported);
        merged.mark_invalid(&first, &kind);

        assert!(
            left_invalidated.lock().unwrap().is_empty(),
            "delayed invalidation must not use the most recent source"
        );
        assert_eq!(
            right_invalidated
                .lock()
                .unwrap()
                .iter()
                .map(|tx| *tx.hash())
                .collect::<Vec<_>>(),
            vec![*r1.hash()]
        );
    }
}
