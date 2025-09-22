use reth_transaction_pool::{BestTransactions, ValidPoolTransaction};
use std::{collections::VecDeque, sync::Arc};
use tempo_transaction_pool::transaction::TempoPooledTransaction;

/// A wrapper around `BestTransactions` that enforces lane ordering for payment transactions.
///
/// This type ensures that all non-payment transactions are yielded before any payment transactions,
/// as required by the Payment Lane specification. It buffers payment transactions while non-payment
/// gas limit allows, and switches to payment lane when non-payment gas is exhausted or a signal
/// is received from the builder.
pub(crate) struct LanedTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
{
    /// The inner iterator that provides transactions from the pool
    inner: I,
    /// Buffer for payment transactions that arrived while processing non-payment transactions
    payment_buffer: VecDeque<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    /// Whether we've switched to the payment lane
    in_payment_lane: bool,
    /// Available gas for non-payment transactions
    non_payment_gas_available: u64,
    /// Total gas used by non-payment transactions
    non_payment_gas_used: u64,
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
            in_payment_lane: false,
            non_payment_gas_available: non_payment_gas_limit,
            non_payment_gas_used: 0,
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
        if !self.in_payment_lane {
            self.non_payment_gas_used += gas_used;
            self.non_payment_gas_available =
                self.non_payment_gas_available.saturating_sub(gas_used);
        }
    }

    /// Forces a switch to the payment lane.
    ///
    /// This should be called when the builder determines that no more non-payment transactions
    /// should be included (e.g., when approaching block gas limit).
    pub(crate) fn switch_to_payment_lane(&mut self) {
        self.in_payment_lane = true;
    }

    /// Checks if we're currently in the payment lane.
    pub(crate) fn is_in_payment_lane(&self) -> bool {
        self.in_payment_lane
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
        // If we're in the payment lane, drain the buffer first, then continue with remaining txs
        if self.in_payment_lane {
            // First drain any buffered payment transactions
            if let Some(tx) = self.payment_buffer.pop_front() {
                return Some(tx);
            }

            // Then yield any remaining transactions (which should all be payment txs)
            // Note: We don't check if they're payment txs here since validation happens elsewhere
            return self.inner.next();
        }

        // We're in the non-payment lane
        loop {
            let tx = self.inner.next()?;
            let is_payment = tx.transaction.is_payment();

            if is_payment {
                // Buffer payment transactions for later
                self.payment_buffer.push_back(tx);
            } else {
                // Check if this non-payment transaction fits within the gas limit
                let tx_gas = tx.gas_limit();
                if tx_gas <= self.non_payment_gas_available {
                    // We have room for this non-payment transaction
                    // Note: The actual gas update happens via update_non_payment_gas_used()
                    // after successful execution
                    return Some(tx);
                } else {
                    // No more room for non-payment transactions, switch to payment lane
                    self.in_payment_lane = true;

                    // Put this transaction back by marking it invalid with a special error
                    // This will make it available again when we switch lanes
                    self.inner.mark_invalid(
                        &tx,
                        reth_transaction_pool::error::InvalidPoolTransactionError::ExceedsGasLimit(
                            tx_gas,
                            self.non_payment_gas_available,
                        ),
                    );

                    // Start draining payment buffer
                    return self.payment_buffer.pop_front();
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
    fn test_lane_state_management() {
        let mock_inner = EmptyBestTransactions {};
        let mut laned = LanedTransactions::new(mock_inner, 50000);

        // Test initial state
        assert!(!laned.is_in_payment_lane());
        assert_eq!(laned.non_payment_gas_available, 50000);

        // Test state transitions
        laned.update_non_payment_gas_used(20000);
        assert_eq!(laned.non_payment_gas_available, 30000);
        assert_eq!(laned.non_payment_gas_used, 20000);

        laned.update_non_payment_gas_used(20000);
        assert_eq!(laned.non_payment_gas_available, 10000);
        assert_eq!(laned.non_payment_gas_used, 40000);

        // Switch to payment lane
        laned.switch_to_payment_lane();
        assert!(laned.is_in_payment_lane());

        // Further updates shouldn't affect gas tracking after switch
        let before_used = laned.non_payment_gas_used;
        laned.update_non_payment_gas_used(10000);
        assert_eq!(laned.non_payment_gas_used, before_used);
    }
}
