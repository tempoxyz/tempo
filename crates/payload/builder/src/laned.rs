use alloy_primitives::Address;
use reth_transaction_pool::{BestTransactions, ValidPoolTransaction};
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};
use tempo_transaction_pool::transaction::TempoPooledTransaction;

/// A wrapper around `BestTransactions` that enforces lane ordering for payment transactions.
///
/// This type ensures that all non-payment transactions are yielded before any payment transactions,
/// as required by the Payment Lane specification. It buffers payment transactions while searching
/// for non-payment transactions that fit within the gas limit, then drains the buffer when the
/// inner iterator is exhausted.
pub(crate) struct LanedTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
{
    /// The inner iterator that provides transactions from the pool
    inner: I,
    /// Buffer for payment transactions that arrived while processing non-payment transactions
    payment_buffer: VecDeque<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    /// Gas remaining for non-payment transactions
    non_payment_gas_left: u64,
    /// Whether non-payment gas has been exhausted
    non_payment_gas_exhausted: bool,
    /// Total gas used by non-payment transactions
    non_payment_gas_used: u64,
    /// Track senders of invalidated transactions to filter buffered descendants
    invalidated_senders: HashSet<Address>,
}

impl<I> LanedTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
{
    /// Creates a new `LanedTransactions` wrapper with the specified non-payment gas limit.
    pub(crate) fn new(inner: I, non_payment_gas_limit: u64) -> Self {
        Self {
            inner,
            payment_buffer: VecDeque::new(),
            non_payment_gas_left: non_payment_gas_limit,
            non_payment_gas_exhausted: false,
            non_payment_gas_used: 0,
            invalidated_senders: HashSet::new(),
        }
    }

    /// Returns the total gas used by non-payment transactions.
    #[allow(dead_code)]
    pub(crate) fn non_payment_gas_used(&self) -> u64 {
        self.non_payment_gas_used
    }

    /// Updates the available gas after a transaction has been executed.
    ///
    /// This should be called by the builder after successfully executing a non-payment transaction
    /// to update the gas accounting.
    pub(crate) fn update_non_payment_gas_used(&mut self, gas_used: u64) {
        if !self.non_payment_gas_exhausted {
            self.non_payment_gas_used += gas_used;
            self.non_payment_gas_left = self.non_payment_gas_left.saturating_sub(gas_used);
        }
    }

    /// Checks if we're currently in payment-only mode.
    pub(crate) fn is_in_payment_lane(&self) -> bool {
        self.non_payment_gas_exhausted
    }
}

impl<I> BestTransactions for LanedTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
{
    fn mark_invalid(
        &mut self,
        tx: &Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        error: reth_transaction_pool::error::InvalidPoolTransactionError,
    ) {
        // Track the sender to filter out buffered transactions from the same sender
        let sender = tx.sender();
        self.invalidated_senders.insert(sender);

        // Remove any buffered payment transactions from the same sender
        // This prevents emitting invalid transactions that depend on the invalidated one
        self.payment_buffer
            .retain(|buffered_tx| buffered_tx.sender() != sender);

        // Forward to inner iterator
        self.inner.mark_invalid(tx, error);
    }

    fn no_updates(&mut self) {
        self.inner.no_updates();
    }

    fn skip_blobs(&mut self) {
        self.inner.skip_blobs();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.inner.set_skip_blobs(skip_blobs);
    }
}

impl<I> Iterator for LanedTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
{
    type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.non_payment_gas_exhausted {
                // In payment-only mode - drain buffer first, then check pool for new payment txs

                // First, drain any buffered payment transactions
                while let Some(tx) = self.payment_buffer.pop_front() {
                    if !self.invalidated_senders.contains(&tx.sender()) {
                        return Some(tx);
                    }
                }

                // Buffer is empty, check pool for new transactions
                for tx in self.inner.by_ref() {
                    // We've exhausted non-payment gas, only process payment transactions
                    if tx.transaction.is_payment()
                        && !self.invalidated_senders.contains(&tx.sender())
                    {
                        return Some(tx);
                    }
                    // Skip non-payment transactions since we're out of non-payment gas
                }

                // No more transactions available
                return None;
            }

            // Still have non-payment gas - process transactions and fill buffer
            match self.inner.next() {
                Some(tx) => {
                    let is_payment = tx.transaction.is_payment();

                    if is_payment {
                        // Buffer payment transaction
                        if !self.invalidated_senders.contains(&tx.sender()) {
                            self.payment_buffer.push_back(tx);
                        }
                    } else {
                        let tx_gas = tx.gas_limit();
                        if tx_gas <= self.non_payment_gas_left {
                            // Non-payment transaction fits
                            return Some(tx);
                        } else {
                            // Non-payment transaction doesn't fit, skip it
                            self.inner.mark_invalid(
                                &tx,
                                reth_transaction_pool::error::InvalidPoolTransactionError::ExceedsGasLimit(
                                    tx_gas,
                                    self.non_payment_gas_left,
                                ),
                            );
                        }
                    }
                }
                None => {
                    // Iterator exhausted, switch to payment-only mode
                    self.non_payment_gas_exhausted = true;
                    // Continue loop to drain buffer
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple empty iterator for testing
    struct EmptyBestTransactions;

    impl BestTransactions for EmptyBestTransactions {
        fn mark_invalid(
            &mut self,
            _tx: &Arc<reth_transaction_pool::ValidPoolTransaction<TempoPooledTransaction>>,
            _error: reth_transaction_pool::error::InvalidPoolTransactionError,
        ) {
        }

        fn no_updates(&mut self) {}
        fn skip_blobs(&mut self) {}
        fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
    }

    impl Iterator for EmptyBestTransactions {
        type Item = Arc<reth_transaction_pool::ValidPoolTransaction<TempoPooledTransaction>>;

        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }

    #[test]
    fn test_laned_transactions_basic() {
        let mock_inner = EmptyBestTransactions {};
        let mut laned = LanedTransactions::new(mock_inner, 50000);

        // Test initial state
        assert!(!laned.is_in_payment_lane());
        assert_eq!(laned.non_payment_gas_used(), 0);
        assert_eq!(laned.non_payment_gas_left, 50000);
        assert!(!laned.non_payment_gas_exhausted);

        // Test gas tracking
        laned.update_non_payment_gas_used(20000);
        assert_eq!(laned.non_payment_gas_used(), 20000);
        assert_eq!(laned.non_payment_gas_left, 30000);

        laned.update_non_payment_gas_used(20000);
        assert_eq!(laned.non_payment_gas_used(), 40000);
        assert_eq!(laned.non_payment_gas_left, 10000);

        // Force switch to payment-only mode
        laned.non_payment_gas_exhausted = true;
        assert!(laned.is_in_payment_lane());

        // Further updates shouldn't affect gas tracking when exhausted
        let before_used = laned.non_payment_gas_used();
        let before_left = laned.non_payment_gas_left;
        laned.update_non_payment_gas_used(10000);
        assert_eq!(laned.non_payment_gas_used(), before_used);
        assert_eq!(laned.non_payment_gas_left, before_left);
    }
}
