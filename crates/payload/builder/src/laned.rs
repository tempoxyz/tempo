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
    /// Track senders of invalidated transactions to filter buffered descendants
    invalidated_senders: HashSet<Address>,
    /// Flag to track if we've started skipping non-payment transactions due to gas limits
    /// Once set, we'll switch to payment lane if we only find payment txs or exhaust the iterator
    skipping_non_payment: bool,
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
            invalidated_senders: HashSet::new(),
            skipping_non_payment: false,
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
        // If we're in the payment lane, drain the buffer first, then continue with remaining txs
        if self.in_payment_lane {
            // First drain any buffered payment transactions, skipping those from invalidated senders
            while let Some(tx) = self.payment_buffer.pop_front() {
                // Skip transactions from invalidated senders
                if !self.invalidated_senders.contains(&tx.sender()) {
                    return Some(tx);
                }
            }

            // Then yield any remaining transactions (which should all be payment txs)
            // Note: We don't check if they're payment txs here since validation happens elsewhere
            return self.inner.next();
        }

        // We're in the non-payment lane
        loop {
            // If the inner iterator is exhausted, switch to payment lane
            let tx = match self.inner.next() {
                Some(tx) => tx,
                None => {
                    // No more transactions from the pool, switch to payment lane
                    self.in_payment_lane = true;
                    return self.payment_buffer.pop_front();
                }
            };

            let is_payment = tx.transaction.is_payment();

            if is_payment {
                // Buffer payment transactions for later, unless from invalidated sender
                if !self.invalidated_senders.contains(&tx.sender()) {
                    self.payment_buffer.push_back(tx);
                }

                // If we've been skipping non-payment txs and now only see payment txs,
                // it's time to switch to the payment lane
                if self.skipping_non_payment {
                    self.in_payment_lane = true;
                    return self.payment_buffer.pop_front();
                }
            } else {
                // Check if this non-payment transaction fits within the gas limit
                let tx_gas = tx.gas_limit();
                if tx_gas <= self.non_payment_gas_available {
                    // We have room for this non-payment transaction
                    // Reset the skipping flag since we found a usable non-payment tx
                    self.skipping_non_payment = false;
                    // Note: The actual gas update happens via update_non_payment_gas_used()
                    // after successful execution
                    return Some(tx);
                } else {
                    // This non-payment transaction doesn't fit
                    // Mark that we've started skipping non-payment transactions
                    self.skipping_non_payment = true;

                    // Mark it as invalid so the pool knows to skip it
                    self.inner.mark_invalid(
                        &tx,
                        reth_transaction_pool::error::InvalidPoolTransactionError::ExceedsGasLimit(
                            tx_gas,
                            self.non_payment_gas_available,
                        ),
                    );
                    // Continue searching for smaller non-payment transactions
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
