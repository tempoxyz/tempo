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
    for crate::aa_2d_pool::BestAA2dTransactions
{
    fn next_tx_and_priority(&mut self) -> Option<(Self::Item, Priority<u128>)> {
        Self::next_tx_and_priority(self)
    }
}

/// A [`BestTransactions`] iterator that combines two individual implementations and always yields the next best item from either of the iterators.
pub struct BiBestTransactions<L, R, T>
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

impl<L, R, T> BiBestTransactions<L, R, T>
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

impl<L, R, T> BiBestTransactions<L, R, T>
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

        match (&self.next_left, &self.next_right) {
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

impl<L, R, T> Iterator for BiBestTransactions<L, R, T>
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

impl<L, R, T> BestTransactions for BiBestTransactions<L, R, T>
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
