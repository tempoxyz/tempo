//! An iterator over the best transactions in the tempo pool.

use crate::transaction::TempoPooledTransaction;
use reth_transaction_pool::{
    BestTransactions, CoinbaseTipOrdering, Priority, TransactionOrdering,
    error::InvalidPoolTransactionError,
};

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

/// Tracks which side of a [`MergeBestTransactions`] yielded the last transaction.
#[derive(Debug, Clone, Copy)]
enum MergeSource {
    Left,
    Right,
}

/// A [`BestTransactions`] iterator that merges two individual implementations and always yields the next best item from either of the iterators.
pub struct MergeBestTransactions<L, R, T>
where
    L: BestPriorityTransactions<T>,
    R: BestPriorityTransactions<T, Item = L::Item>,
    T: TransactionOrdering,
{
    left: L,
    right: R,
    next_left: Option<(L::Item, Priority<T::PriorityValue>)>,
    next_right: Option<(L::Item, Priority<T::PriorityValue>)>,
    last_source: Option<MergeSource>,
}

impl<L, R, T> MergeBestTransactions<L, R, T>
where
    L: BestPriorityTransactions<T>,
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
            last_source: None,
        }
    }
}

impl<L, R, T> MergeBestTransactions<L, R, T>
where
    L: BestPriorityTransactions<T>,
    R: BestPriorityTransactions<T, Item = L::Item>,
    T: TransactionOrdering,
{
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
                self.last_source = Some(MergeSource::Left);
                let (item, priority) = self.next_left.take()?;
                Some((item, priority))
            }
            // Only right has an item - take it
            (None, Some(_)) => {
                self.last_source = Some(MergeSource::Right);
                let (item, priority) = self.next_right.take()?;
                Some((item, priority))
            }
            // Both sides have items - compare priorities and take the higher one
            (Some((_, left_priority)), Some((_, right_priority))) => {
                // Higher priority value is better
                if left_priority >= right_priority {
                    self.last_source = Some(MergeSource::Left);
                    let (item, priority) = self.next_left.take()?;
                    Some((item, priority))
                } else {
                    self.last_source = Some(MergeSource::Right);
                    let (item, priority) = self.next_right.take()?;
                    Some((item, priority))
                }
            }
        }
    }
}

impl<L, R, T> Iterator for MergeBestTransactions<L, R, T>
where
    L: BestPriorityTransactions<T>,
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
    L: BestPriorityTransactions<T, Item: Send> + Send,
    R: BestPriorityTransactions<T, Item = L::Item> + Send,
    T: TransactionOrdering,
{
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: &InvalidPoolTransactionError) {
        match self.last_source {
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

#[cfg(test)]
mod tests {
    use super::*;
    use reth_primitives_traits::transaction::error::InvalidTransactionError;
    use std::sync::{Arc, Mutex};

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
        let left = MockBestTransactions::new(vec![("tx_a", 10), ("tx_b", 5), ("tx_c", 3)]);
        let right = MockBestTransactions::new(vec![("tx_d", 8), ("tx_e", 4), ("tx_f", 1)]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next(), Some("tx_a")); // priority 10
        assert_eq!(merged.next(), Some("tx_d")); // priority 8
        assert_eq!(merged.next(), Some("tx_b")); // priority 5
        assert_eq!(merged.next(), Some("tx_e")); // priority 4
        assert_eq!(merged.next(), Some("tx_c")); // priority 3
        assert_eq!(merged.next(), Some("tx_f")); // priority 1
        assert_eq!(merged.next(), None);
    }

    #[test]
    fn test_merge_best_transactions_empty_left() {
        // Left iterator is empty
        let left = MockBestTransactions::new(vec![]);
        let right = MockBestTransactions::new(vec![("tx_a", 10), ("tx_b", 5)]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next(), Some("tx_a"));
        assert_eq!(merged.next(), Some("tx_b"));
        assert_eq!(merged.next(), None);
    }

    #[test]
    fn test_merge_best_transactions_empty_right() {
        // Right iterator is empty
        let left = MockBestTransactions::new(vec![("tx_a", 10), ("tx_b", 5)]);
        let right = MockBestTransactions::new(vec![]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next(), Some("tx_a"));
        assert_eq!(merged.next(), Some("tx_b"));
        assert_eq!(merged.next(), None);
    }

    #[test]
    fn test_merge_best_transactions_both_empty() {
        let left: MockBestTransactions<&str> = MockBestTransactions::new(vec![]);
        let right: MockBestTransactions<&str> = MockBestTransactions::new(vec![]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next(), None);
    }

    #[test]
    fn test_merge_best_transactions_equal_priorities() {
        // When priorities are equal, left should be preferred (based on >= comparison)
        let left = MockBestTransactions::new(vec![("tx_a", 10), ("tx_b", 5)]);
        let right = MockBestTransactions::new(vec![("tx_c", 10), ("tx_d", 5)]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next(), Some("tx_a")); // equal priority, left preferred
        assert_eq!(merged.next(), Some("tx_c"));
        assert_eq!(merged.next(), Some("tx_b")); // equal priority, left preferred
        assert_eq!(merged.next(), Some("tx_d"));
        assert_eq!(merged.next(), None);
    }

    // ============================================
    // Single item tests
    // ============================================

    #[test]
    fn test_merge_best_transactions_single_left() {
        let left = MockBestTransactions::new(vec![("tx_a", 10)]);
        let right: MockBestTransactions<&str> = MockBestTransactions::new(vec![]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next(), Some("tx_a"));
        assert_eq!(merged.next(), None);
    }

    #[test]
    fn test_merge_best_transactions_single_right() {
        let left: MockBestTransactions<&str> = MockBestTransactions::new(vec![]);
        let right = MockBestTransactions::new(vec![("tx_a", 10)]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next(), Some("tx_a"));
        assert_eq!(merged.next(), None);
    }

    // ============================================
    // Interleaved priority tests
    // ============================================

    #[test]
    fn test_merge_best_transactions_interleaved() {
        // Left has higher odd positions, right has higher even positions
        let left = MockBestTransactions::new(vec![("L1", 9), ("L2", 7), ("L3", 5)]);
        let right = MockBestTransactions::new(vec![("R1", 10), ("R2", 6), ("R3", 4)]);

        let mut merged = MergeBestTransactions::new(left, right);

        assert_eq!(merged.next(), Some("R1")); // 10
        assert_eq!(merged.next(), Some("L1")); // 9
        assert_eq!(merged.next(), Some("L2")); // 7
        assert_eq!(merged.next(), Some("R2")); // 6
        assert_eq!(merged.next(), Some("L3")); // 5
        assert_eq!(merged.next(), Some("R3")); // 4
        assert_eq!(merged.next(), None);
    }

    #[test]
    fn test_mark_invalid_only_forwards_to_source_pool() {
        // Invalidating a right-side (AA-2D) tx must NOT propagate to the
        // left-side (protocol) pool.
        let left = MockBestTransactions::new(vec![("L1", 5), ("L2", 3)]);
        let right = MockBestTransactions::new(vec![("R1", 10)]);

        let left_invalidated = left.invalidated();
        let right_invalidated = right.invalidated();

        let mut merged = MergeBestTransactions::new(left, right);

        // Right has highest priority, so R1 is yielded first
        let first = merged.next().unwrap();
        assert_eq!(first, "R1");

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
            *right_invalidated.lock().unwrap(),
            vec!["R1"],
            "right pool must receive the invalidation"
        );

        // Remaining left-side txs must still be yielded
        assert_eq!(merged.next(), Some("L1"));
        assert_eq!(merged.next(), Some("L2"));
        assert_eq!(merged.next(), None);
    }
}
