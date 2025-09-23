use alloy_primitives::Address;
use reth_transaction_pool::{BestTransactions, ValidPoolTransaction};
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};
use tempo_transaction_pool::transaction::TempoPooledTransaction;

/// State for managing transaction processing based on gas limits.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LaneState {
    /// Whether we're draining the buffer (iterator exhausted)
    draining: bool,
    /// Gas remaining for non-payment transactions
    non_payment_gas: u64,
}

impl LaneState {
    /// Create a new lane state starting in non-payment lane
    fn new(non_payment_gas_limit: u64) -> Self {
        Self {
            draining: false,
            non_payment_gas: non_payment_gas_limit,
        }
    }

    /// Process a transaction and determine what action to take
    fn process_transaction(&mut self, is_payment: bool, tx_gas: u64) -> TransactionAction {
        if self.draining {
            // Should not be called in this state
            unreachable!("process_transaction should not be called when draining buffer")
        }

        if is_payment {
            // Buffer payment transaction while in non-payment lane
            TransactionAction::Buffer
        } else if tx_gas <= self.non_payment_gas {
            // Non-payment transaction fits
            TransactionAction::Yield
        } else {
            // Non-payment transaction doesn't fit
            TransactionAction::Skip
        }
    }

    /// Update gas after a non-payment transaction was executed
    fn update_gas(&mut self, gas_used: u64) {
        if !self.draining {
            self.non_payment_gas = self.non_payment_gas.saturating_sub(gas_used);
        }
    }

    /// Check if we're draining the buffer (iterator exhausted)
    fn is_draining_buffer(&self) -> bool {
        self.draining
    }

    /// Mark that iterator is exhausted and we should drain buffer
    fn mark_exhausted(&mut self) {
        self.draining = true;
    }
}

/// Action to take for a transaction based on lane state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionAction {
    /// Yield this transaction to the builder
    Yield,
    /// Buffer this transaction for later (payment tx in non-payment lane)
    Buffer,
    /// Skip this transaction (doesn't fit in gas limit)
    Skip,
}

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
    /// Lane state machine managing transitions
    lane_state: LaneState,
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
            lane_state: LaneState::new(non_payment_gas_limit),
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
        if !self.lane_state.is_draining_buffer() {
            self.non_payment_gas_used += gas_used;
            self.lane_state.update_gas(gas_used);
        }
    }

    /// Checks if we're currently draining the payment buffer.
    pub(crate) fn is_in_payment_lane(&self) -> bool {
        self.lane_state.is_draining_buffer()
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
            if self.lane_state.is_draining_buffer() {
                // In payment lane - drain buffer first, then check pool for new payment txs

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

            // In non-payment lane - process transactions and fill buffer
            match self.inner.next() {
                Some(tx) => {
                    let is_payment = tx.transaction.is_payment();
                    let tx_gas = tx.gas_limit();

                    let action = self.lane_state.process_transaction(is_payment, tx_gas);

                    match action {
                        TransactionAction::Yield => {
                            return Some(tx);
                        }
                        TransactionAction::Buffer => {
                            if !self.invalidated_senders.contains(&tx.sender()) {
                                self.payment_buffer.push_back(tx);
                            }
                        }
                        TransactionAction::Skip => {
                            self.inner.mark_invalid(
                                &tx,
                                reth_transaction_pool::error::InvalidPoolTransactionError::ExceedsGasLimit(
                                    tx_gas,
                                    self.lane_state.non_payment_gas,
                                ),
                            );
                        }
                    }
                }
                None => {
                    // Iterator exhausted, switch to payment lane
                    self.lane_state.mark_exhausted();
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

        // Test gas tracking
        laned.update_non_payment_gas_used(20000);
        assert_eq!(laned.non_payment_gas_used(), 20000);

        laned.update_non_payment_gas_used(20000);
        assert_eq!(laned.non_payment_gas_used(), 40000);

        // Force switch to draining state
        laned.lane_state.draining = true;
        assert!(laned.is_in_payment_lane());

        // Further updates shouldn't affect gas tracking when draining
        let before_used = laned.non_payment_gas_used();
        laned.update_non_payment_gas_used(10000);
        assert_eq!(laned.non_payment_gas_used(), before_used);
    }

    mod lane_state {
        use super::*;

        #[test]
        fn test_initial_state() {
            let state = LaneState::new(100000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 100000,
                }
            );
            assert!(!state.is_draining_buffer());
        }

        #[test]
        fn test_non_payment_fits() {
            let mut state = LaneState::new(100000);
            let action = state.process_transaction(false, 50000);
            assert_eq!(action, TransactionAction::Yield);
            // Gas should remain unchanged until update_gas is called
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 100000,
                }
            );
        }

        #[test]
        fn test_non_payment_too_large() {
            let mut state = LaneState::new(50000);
            let action = state.process_transaction(false, 60000);
            assert_eq!(action, TransactionAction::Skip);
            // State remains unchanged
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 50000,
                }
            );
        }

        #[test]
        fn test_payment_in_non_payment_lane() {
            let mut state = LaneState::new(100000);
            let action = state.process_transaction(true, 50000);
            assert_eq!(action, TransactionAction::Buffer);
            // State should remain unchanged
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 100000,
                }
            );
        }

        #[test]
        fn test_skipping_finds_smaller_non_payment() {
            let mut state = LaneState {
                draining: false,
                non_payment_gas: 50000,
            };

            // Found a smaller non-payment that fits
            let action = state.process_transaction(false, 30000);
            assert_eq!(action, TransactionAction::Yield);
            // State should remain unchanged (gas not updated yet)
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 50000,
                }
            );
        }

        #[test]
        fn test_skipping_with_payment() {
            let mut state = LaneState {
                draining: false,
                non_payment_gas: 50000,
            };

            // Payment transaction should always buffer
            let action = state.process_transaction(true, 30000);
            assert_eq!(action, TransactionAction::Buffer);
            // State should remain unchanged
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 50000,
                }
            );
        }

        #[test]
        fn test_mixed_ordering_scenario() {
            // This tests the exact scenario from the reviewer's feedback:
            // - non-payment with gas limit 21000 (fits)
            // - non-payment with gas limit > available (doesn't fit)
            // - payment tx
            // - non-payment with gas limit 21000 (should still be processed)

            let mut state = LaneState::new(50000);

            // First small non-payment - should yield
            let action = state.process_transaction(false, 21000);
            assert_eq!(action, TransactionAction::Yield);
            state.update_gas(21000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 29000,
                }
            );

            // Large non-payment that doesn't fit - should skip
            let action = state.process_transaction(false, 60000);
            assert_eq!(action, TransactionAction::Skip);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 29000,
                }
            );

            // Payment transaction - should buffer
            let action = state.process_transaction(true, 30000);
            assert_eq!(action, TransactionAction::Buffer);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 29000,
                }
            );

            // Another small non-payment that fits - should yield
            let action = state.process_transaction(false, 21000);
            assert_eq!(action, TransactionAction::Yield);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 29000,
                }
            );
        }

        #[test]
        fn test_gas_updates() {
            let mut state = LaneState::new(100000);

            // Update gas
            state.update_gas(30000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 70000,
                }
            );

            // Update gas again
            state.update_gas(20000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 50000,
                }
            );

            // Switch to draining - gas updates should have no effect
            state.draining = true;
            let before_gas = state.non_payment_gas;
            state.update_gas(10000);
            assert_eq!(state.non_payment_gas, before_gas);
        }

        #[test]
        fn test_all_non_payment_txs_fit() {
            // Test scenario where all non-payment transactions fit within gas limit
            let mut state = LaneState::new(200000);

            // Multiple non-payment transactions that all fit
            let action = state.process_transaction(false, 30000);
            assert_eq!(action, TransactionAction::Yield);
            state.update_gas(30000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 170000,
                }
            );

            let action = state.process_transaction(false, 40000);
            assert_eq!(action, TransactionAction::Yield);
            state.update_gas(40000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 130000,
                }
            );

            let action = state.process_transaction(false, 50000);
            assert_eq!(action, TransactionAction::Yield);
            state.update_gas(50000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 80000,
                }
            );

            // Payment transactions should be buffered
            let action = state.process_transaction(true, 25000);
            assert_eq!(action, TransactionAction::Buffer);

            let action = state.process_transaction(true, 35000);
            assert_eq!(action, TransactionAction::Buffer);

            // More non-payment transactions that fit
            let action = state.process_transaction(false, 60000);
            assert_eq!(action, TransactionAction::Yield);
            state.update_gas(60000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 20000,
                }
            );

            let action = state.process_transaction(false, 15000);
            assert_eq!(action, TransactionAction::Yield);
            state.update_gas(15000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 5000,
                }
            );

            // State should still be NonPayment since all transactions fit
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 5000,
                }
            );
        }

        #[test]
        fn test_no_non_payment_txs_fit() {
            // Test scenario where no non-payment transactions fit
            let mut state = LaneState::new(10000);

            // Large non-payment that doesn't fit
            let action = state.process_transaction(false, 50000);
            assert_eq!(action, TransactionAction::Skip);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 10000,
                }
            );

            // Another large non-payment
            let action = state.process_transaction(false, 30000);
            assert_eq!(action, TransactionAction::Skip);

            // Payment transactions get buffered
            let action = state.process_transaction(true, 20000);
            assert_eq!(action, TransactionAction::Buffer);

            let action = state.process_transaction(true, 25000);
            assert_eq!(action, TransactionAction::Buffer);

            // More large non-payments
            let action = state.process_transaction(false, 40000);
            assert_eq!(action, TransactionAction::Skip);

            let action = state.process_transaction(false, 15000);
            assert_eq!(action, TransactionAction::Skip);

            // State remains with skipping flag since no tx fits
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 10000,
                }
            );
        }

        #[test]
        fn test_consecutive_payments_with_mixed_non_payments() {
            // Test scenario with multiple consecutive payment transactions
            // and non-payment transactions before and after them.

            let mut state = LaneState::new(100000);

            // First: Small non-payment that fits
            let action = state.process_transaction(false, 25000);
            assert_eq!(action, TransactionAction::Yield);
            state.update_gas(25000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 75000,
                }
            );

            // Second: Large non-payment that doesn't fit
            let action = state.process_transaction(false, 80000);
            assert_eq!(action, TransactionAction::Skip);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 75000,
                }
            );

            // Third: First payment transaction (buffer it)
            let action = state.process_transaction(true, 30000);
            assert_eq!(action, TransactionAction::Buffer);

            // Fourth: Second payment transaction (buffer it)
            let action = state.process_transaction(true, 25000);
            assert_eq!(action, TransactionAction::Buffer);

            // Fifth: Third payment transaction (buffer it)
            let action = state.process_transaction(true, 35000);
            assert_eq!(action, TransactionAction::Buffer);
            // Still skipping
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 75000,
                }
            );

            // Sixth: Another large non-payment that doesn't fit
            let action = state.process_transaction(false, 100000);
            assert_eq!(action, TransactionAction::Skip);

            // Seventh: Small non-payment that DOES fit - should yield and reset!
            let action = state.process_transaction(false, 20000);
            assert_eq!(action, TransactionAction::Yield);
            // Should reset to NonPayment state
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 75000,
                }
            );
            state.update_gas(20000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 55000,
                }
            );

            // Eighth: Another payment (buffer it)
            let action = state.process_transaction(true, 40000);
            assert_eq!(action, TransactionAction::Buffer);

            // Ninth: Medium non-payment that fits
            let action = state.process_transaction(false, 30000);
            assert_eq!(action, TransactionAction::Yield);
            state.update_gas(30000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 25000,
                }
            );

            // Tenth: Large non-payment that doesn't fit
            let action = state.process_transaction(false, 50000);
            assert_eq!(action, TransactionAction::Skip);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 25000,
                }
            );

            // Eleventh: Small non-payment that fits
            let action = state.process_transaction(false, 10000);
            assert_eq!(action, TransactionAction::Yield);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 25000,
                }
            );
            state.update_gas(10000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 15000,
                }
            );
        }

        #[test]
        fn test_skipping_large_tx_with_interspersed_payments() {
            // This test covers the scenario where we skip a large non-payment transaction,
            // encounter a payment transaction (which gets buffered), and then find
            // another smaller non-payment transaction that fits.

            let mut state = LaneState::new(50000);

            // First: non-payment with 21000 gas (fits)
            let action = state.process_transaction(false, 21000);
            assert_eq!(action, TransactionAction::Yield);
            state.update_gas(21000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 29000,
                }
            );

            // Second: non-payment with 60000 gas (doesn't fit, skip)
            let action = state.process_transaction(false, 60000);
            assert_eq!(action, TransactionAction::Skip);
            // State should now have skipping flag set
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 29000,
                }
            );

            // Third: payment tx (buffer it)
            let action = state.process_transaction(true, 30000);
            assert_eq!(action, TransactionAction::Buffer);
            // Should still be skipping
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 29000,
                }
            );

            // Fourth: non-payment with 21000 gas (fits! should yield and reset)
            let action = state.process_transaction(false, 21000);
            assert_eq!(action, TransactionAction::Yield);
            // Should reset back to NonPayment state
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 29000,
                }
            );
            state.update_gas(21000);
            assert_eq!(
                state,
                LaneState {
                    draining: false,
                    non_payment_gas: 8000,
                }
            );

            let action = state.process_transaction(true, 25000);
            assert_eq!(action, TransactionAction::Buffer);
        }
    }
}
