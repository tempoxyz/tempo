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
    /// Whether to skip non-payment transactions (payment-only mode)
    skip_non_payments: bool,
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
            skip_non_payments: false,
            invalidated_senders: HashSet::new(),
        }
    }

    /// Switch to payment-only mode, skipping non-payment transactions.
    /// This should be called by the builder when non-payment gas is exhausted.
    pub(crate) fn skip_non_payments(&mut self) {
        self.skip_non_payments = true;
    }

    /// Check if we're in payment-only mode (non-payment transactions exhausted).
    pub(crate) fn non_payment_exhausted(&self) -> bool {
        self.skip_non_payments
    }

    /// Update gas after a non-payment transaction was executed
    pub(crate) fn update_non_payment_gas_used(&mut self, gas_used: u64) {
        if !self.skip_non_payments {
            self.non_payment_gas_left = self.non_payment_gas_left.saturating_sub(gas_used);
        }
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
            if self.skip_non_payments {
                // In payment-only mode - drain buffer first, then check pool for new payment txs

                // First, drain any buffered payment transactions
                while let Some(tx) = self.payment_buffer.pop_front() {
                    if !self.invalidated_senders.contains(tx.sender_ref()) {
                        return Some(tx);
                    }
                }

                // Buffer is empty, check pool for new transactions
                for tx in self.inner.by_ref() {
                    // Only process payment transactions when skipping non-payments
                    if tx.transaction.is_payment()
                        && !self.invalidated_senders.contains(tx.sender_ref())
                    {
                        return Some(tx);
                    }
                    // Skip non-payment transactions
                }

                // No more transactions available
                return None;
            }

            // Still processing non-payment transactions - process transactions and fill buffer
            while let Some(tx) = self.inner.next() {
                let is_payment = tx.transaction.is_payment();

                if is_payment {
                    // Buffer payment transaction for later
                    if !self.invalidated_senders.contains(tx.sender_ref()) {
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

            // Iterator exhausted, switch to payment-only mode
            self.skip_non_payments = true;
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
        assert!(!laned.non_payment_exhausted());
        assert!(!laned.skip_non_payments);
        assert_eq!(laned.non_payment_gas_left, 50000);

        // Test gas tracking
        laned.update_non_payment_gas_used(20000);
        assert_eq!(laned.non_payment_gas_left, 30000);

        // Test external control: builder can trigger switch to payment-only mode
        laned.skip_non_payments();
        assert!(laned.non_payment_exhausted());
        assert!(laned.skip_non_payments);

        // Gas updates should be ignored when in payment-only mode
        laned.update_non_payment_gas_used(10000);
        assert_eq!(laned.non_payment_gas_left, 30000); // Should remain unchanged
    }
}
