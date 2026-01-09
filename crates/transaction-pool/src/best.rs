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
                let (item, priority) = self.next_left.take()?;
                Some((item, priority))
            }
            // Only right has an item - take it
            (None, Some(_)) => {
                let (item, priority) = self.next_right.take()?;
                Some((item, priority))
            }
            // Both sides have items - compare priorities and take the higher one
            (Some((_, left_priority)), Some((_, right_priority))) => {
                // Higher priority value is better
                if left_priority >= right_priority {
                    let (item, priority) = self.next_left.take()?;
                    Some((item, priority))
                } else {
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
        self.left.mark_invalid(transaction, kind);
        self.right.mark_invalid(transaction, kind);
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

    /// A simple mock iterator for testing that yields items with priorities
    struct MockBestTransactions<T> {
        items: Vec<(T, Priority<u128>)>,
        index: usize,
    }

    impl<T> MockBestTransactions<T> {
        fn new(items: Vec<(T, u128)>) -> Self {
            let items = items
                .into_iter()
                .map(|(item, priority)| (item, Priority::Value(priority)))
                .collect();
            Self { items, index: 0 }
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
        fn mark_invalid(&mut self, _transaction: &Self::Item, _kind: &InvalidPoolTransactionError) {
            // No-op for mock
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
    // BestTransactions trait method tests
    // ============================================

    #[test]
    fn test_merge_best_transactions_mark_invalid() {
        use reth_primitives_traits::transaction::error::InvalidTransactionError;

        let left = MockBestTransactions::new(vec![("tx_a", 10)]);
        let right = MockBestTransactions::new(vec![("tx_b", 5)]);

        let mut merged = MergeBestTransactions::new(left, right);

        // Should not panic - just delegates to both sides
        let error =
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported);
        merged.mark_invalid(&"tx_a", &error);
    }

    #[test]
    fn test_merge_best_transactions_no_updates() {
        let left = MockBestTransactions::new(vec![("tx_a", 10)]);
        let right = MockBestTransactions::new(vec![("tx_b", 5)]);

        let mut merged = MergeBestTransactions::new(left, right);

        // Should not panic - just delegates to both sides
        merged.no_updates();
    }

    #[test]
    fn test_merge_best_transactions_set_skip_blobs() {
        let left = MockBestTransactions::new(vec![("tx_a", 10)]);
        let right = MockBestTransactions::new(vec![("tx_b", 5)]);

        let mut merged = MergeBestTransactions::new(left, right);

        // Should not panic - just delegates to both sides
        merged.set_skip_blobs(true);
        merged.set_skip_blobs(false);
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
}
