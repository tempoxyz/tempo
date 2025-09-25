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
    use alloy_consensus::{SignableTransaction, Transaction};
    use alloy_primitives::{Address, Bytes, TxHash, U256, address};
    use reth_primitives_traits::Recovered;
    use reth_transaction_pool::{ValidPoolTransaction, identifier::SenderId};
    use std::sync::Arc;
    use tempo_primitives::TempoTxEnvelope;

    // Helper to create a mock payment address (with TIP20 prefix)
    fn payment_address() -> Address {
        address!("20c0000000000000000000000000000000000001")
    }

    // Helper to create a mock non-payment address
    fn non_payment_address() -> Address {
        address!("1234567890123456789012345678901234567890")
    }

    // Helper to create a mock transaction with specified parameters
    fn create_mock_tx(
        to: Option<Address>,
        gas_limit: u64,
        nonce: u64,
        sender: Address,
    ) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        let tx = alloy_consensus::TxLegacy {
            chain_id: Some(1),
            nonce,
            gas_price: 1000,
            gas_limit,
            to: to.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        };

        // Sign the transaction
        let signature = alloy_primitives::Signature::test_signature();
        let signed_tx = tx.into_signed(signature);

        let tx_envelope = TempoTxEnvelope::Legacy(signed_tx);

        let recovered_tx = Recovered::new_unchecked(tx_envelope, sender);

        // Calculate encoded length (approximation for testing)
        let encoded_length = 200;

        let pooled = TempoPooledTransaction::new(recovered_tx, encoded_length);

        let sender_id = SenderId::from(u64::from_be_bytes(
            sender.as_slice()[12..20].try_into().unwrap(),
        ));

        let valid_tx = ValidPoolTransaction {
            transaction: pooled,
            transaction_id: reth_transaction_pool::identifier::TransactionId::new(sender_id, nonce),
            propagate: false,
            timestamp: std::time::Instant::now(),
            origin: reth_transaction_pool::TransactionOrigin::Local,
            authority_ids: Default::default(),
        };

        Arc::new(valid_tx)
    }

    // Mock iterator that yields a predefined sequence of transactions
    struct MockBestTransactions {
        transactions: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        index: usize,
        marked_invalid: Vec<(
            TxHash,
            reth_transaction_pool::error::InvalidPoolTransactionError,
        )>,
        no_updates_called: bool,
        skip_blobs_enabled: bool,
    }

    impl MockBestTransactions {
        fn new(transactions: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>) -> Self {
            Self {
                transactions,
                index: 0,
                marked_invalid: Vec::new(),
                no_updates_called: false,
                skip_blobs_enabled: false,
            }
        }

        fn was_marked_invalid(&self, tx_hash: TxHash) -> bool {
            self.marked_invalid.iter().any(|(hash, _)| *hash == tx_hash)
        }
    }

    impl BestTransactions for MockBestTransactions {
        fn mark_invalid(
            &mut self,
            tx: &Arc<ValidPoolTransaction<TempoPooledTransaction>>,
            error: reth_transaction_pool::error::InvalidPoolTransactionError,
        ) {
            self.marked_invalid.push((*tx.hash(), error));
        }

        fn no_updates(&mut self) {
            self.no_updates_called = true;
        }

        fn skip_blobs(&mut self) {
            self.skip_blobs_enabled = true;
        }

        fn set_skip_blobs(&mut self, skip_blobs: bool) {
            self.skip_blobs_enabled = skip_blobs;
        }
    }

    impl Iterator for MockBestTransactions {
        type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index < self.transactions.len() {
                let tx = self.transactions[self.index].clone();
                self.index += 1;

                // Skip transactions that were marked invalid
                if self
                    .marked_invalid
                    .iter()
                    .any(|(hash, _)| *hash == *tx.hash())
                {
                    return self.next();
                }

                Some(tx)
            } else {
                None
            }
        }
    }

    #[test]
    fn test_laned_transactions_basic() {
        let mock_inner = MockBestTransactions::new(vec![]);
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

    #[test]
    fn test_lane_ordering_all_non_payments() {
        // Create a sequence of all non-payment transactions
        let sender = address!("0000000000000000000000000000000000000001");
        let transactions = vec![
            create_mock_tx(Some(non_payment_address()), 21000, 0, sender),
            create_mock_tx(Some(non_payment_address()), 21000, 1, sender),
            create_mock_tx(Some(non_payment_address()), 21000, 2, sender),
        ];

        let mock_inner = MockBestTransactions::new(transactions);
        let mut laned = LanedTransactions::new(mock_inner, 100000);

        // Should yield all non-payment transactions in order
        assert!(laned.next().is_some());
        assert!(laned.next().is_some());
        assert!(laned.next().is_some());
        assert!(laned.next().is_none());

        // Should have switched to payment-only mode after exhausting iterator
        assert!(laned.non_payment_exhausted());
    }

    #[test]
    fn test_lane_ordering_all_payments() {
        // Create a sequence of all payment transactions
        let sender = address!("0000000000000000000000000000000000000001");
        let transactions = vec![
            create_mock_tx(Some(payment_address()), 21000, 0, sender),
            create_mock_tx(Some(payment_address()), 21000, 1, sender),
            create_mock_tx(Some(payment_address()), 21000, 2, sender),
        ];

        let mock_inner = MockBestTransactions::new(transactions);
        let mut laned = LanedTransactions::new(mock_inner, 100000);

        // The iterator will buffer all payment transactions and switch to payment-only mode,
        // then start returning them
        let tx1 = laned.next().unwrap();
        assert_eq!(tx1.transaction.nonce(), 0);

        // Should have switched to payment-only mode
        assert!(laned.non_payment_exhausted());

        // Continue yielding buffered payment transactions
        let tx2 = laned.next().unwrap();
        assert_eq!(tx2.transaction.nonce(), 1);

        let tx3 = laned.next().unwrap();
        assert_eq!(tx3.transaction.nonce(), 2);

        assert!(laned.next().is_none());
    }

    #[test]
    fn test_lane_ordering_mixed() {
        // Create a mixed sequence: payment, non-payment, payment, non-payment
        let sender = address!("0000000000000000000000000000000000000001");
        let transactions = vec![
            create_mock_tx(Some(payment_address()), 21000, 0, sender), // payment
            create_mock_tx(Some(non_payment_address()), 21000, 1, sender), // non-payment
            create_mock_tx(Some(payment_address()), 21000, 2, sender), // payment
            create_mock_tx(Some(non_payment_address()), 21000, 3, sender), // non-payment
        ];

        let mock_inner = MockBestTransactions::new(transactions);
        let mut laned = LanedTransactions::new(mock_inner, 100000);

        // Should yield non-payment transactions first (indices 1, 3)
        let tx1 = laned.next().unwrap();
        assert_eq!(tx1.transaction.nonce(), 1);

        let tx2 = laned.next().unwrap();
        assert_eq!(tx2.transaction.nonce(), 3);

        // After exhausting non-payments, should switch to payment-only mode
        // and yield buffered payment transactions (indices 0, 2)
        let tx3 = laned.next().unwrap();
        assert_eq!(tx3.transaction.nonce(), 0);

        let tx4 = laned.next().unwrap();
        assert_eq!(tx4.transaction.nonce(), 2);

        assert!(laned.next().is_none());
        assert!(laned.non_payment_exhausted());
    }

    #[test]
    fn test_gas_limit_enforcement() {
        let sender = address!("0000000000000000000000000000000000000001");
        let transactions = vec![
            create_mock_tx(Some(non_payment_address()), 30000, 0, sender), // fits
            create_mock_tx(Some(non_payment_address()), 25000, 1, sender), // fits
            create_mock_tx(Some(non_payment_address()), 40000, 2, sender), // exceeds remaining
            create_mock_tx(Some(non_payment_address()), 10000, 3, sender), // would fit if 2 was skipped
        ];

        let mock_inner = MockBestTransactions::new(transactions.clone());
        let mut laned = LanedTransactions::new(mock_inner, 60000);

        // First transaction (30000 gas) should be yielded
        let tx1 = laned.next().unwrap();
        assert_eq!(tx1.transaction.nonce(), 0);
        laned.update_non_payment_gas_used(30000);

        // Second transaction (25000 gas) should be yielded
        let tx2 = laned.next().unwrap();
        assert_eq!(tx2.transaction.nonce(), 1);
        laned.update_non_payment_gas_used(25000);

        // Third transaction (40000 gas) exceeds remaining (5000), should be skipped
        // Fourth transaction (10000 gas) also exceeds remaining, should be skipped
        assert!(laned.next().is_none());

        // Verify that transaction 2 was marked invalid
        assert!(laned.inner.was_marked_invalid(*transactions[2].hash()));
    }

    #[test]
    fn test_invalidation_removes_buffered_descendants() {
        let sender1 = address!("0000000000000000000000000000000000000001");
        let sender2 = address!("0000000000000000000000000000000000000002");

        let transactions = vec![
            create_mock_tx(Some(non_payment_address()), 21000, 0, sender1), // non-payment from sender1
            create_mock_tx(Some(payment_address()), 21000, 1, sender1),     // payment from sender1
            create_mock_tx(Some(payment_address()), 21000, 0, sender2),     // payment from sender2
            create_mock_tx(Some(payment_address()), 21000, 2, sender1), // another payment from sender1
        ];

        let mock_inner = MockBestTransactions::new(transactions);
        let mut laned = LanedTransactions::new(mock_inner, 100000);

        // Process first non-payment transaction
        let tx1 = laned.next().unwrap();
        assert_eq!(tx1.transaction.nonce(), 0);

        // Mark it as invalid
        laned.mark_invalid(
            &tx1,
            reth_transaction_pool::error::InvalidPoolTransactionError::Underpriced,
        );

        // Should have removed all buffered transactions from sender1
        // Only sender2's transaction should remain
        laned.skip_non_payments(); // Force switch to payment-only mode

        let tx2 = laned.next().unwrap();
        assert_eq!(tx2.sender(), sender2);
        assert_eq!(tx2.transaction.nonce(), 0);

        // No more transactions (sender1's were removed)
        assert!(laned.next().is_none());
    }

    #[test]
    fn test_mode_switching_with_builder_control() {
        let sender = address!("0000000000000000000000000000000000000001");
        let transactions = vec![
            create_mock_tx(Some(non_payment_address()), 21000, 0, sender),
            create_mock_tx(Some(non_payment_address()), 21000, 1, sender),
            create_mock_tx(Some(payment_address()), 21000, 2, sender),
        ];

        let mock_inner = MockBestTransactions::new(transactions);
        let mut laned = LanedTransactions::new(mock_inner, 100000);

        // Process first non-payment
        assert!(laned.next().is_some());

        // Builder decides to switch to payment-only mode early
        laned.skip_non_payments();
        assert!(laned.non_payment_exhausted());

        // Should now only yield payment transactions, skipping remaining non-payments
        let tx = laned.next().unwrap();
        assert_eq!(tx.transaction.nonce(), 2); // Payment transaction

        assert!(laned.next().is_none());
    }

    #[test]
    fn test_no_updates_forwarding() {
        let mock_inner = MockBestTransactions::new(vec![]);
        let mut laned = LanedTransactions::new(mock_inner, 100000);

        laned.no_updates();
        assert!(laned.inner.no_updates_called);
    }

    #[test]
    fn test_skip_blobs_forwarding() {
        let mock_inner = MockBestTransactions::new(vec![]);
        let mut laned = LanedTransactions::new(mock_inner, 100000);

        laned.skip_blobs();
        assert!(laned.inner.skip_blobs_enabled);

        laned.set_skip_blobs(false);
        assert!(!laned.inner.skip_blobs_enabled);
    }

    #[test]
    fn test_gas_saturation() {
        let sender = address!("0000000000000000000000000000000000000001");
        let transactions = vec![create_mock_tx(
            Some(non_payment_address()),
            21000,
            0,
            sender,
        )];

        let mock_inner = MockBestTransactions::new(transactions);
        let mut laned = LanedTransactions::new(mock_inner, 10000);

        // Update gas beyond limit (saturating subtraction should prevent underflow)
        laned.update_non_payment_gas_used(20000);
        assert_eq!(laned.non_payment_gas_left, 0);

        // Further updates should keep it at 0
        laned.update_non_payment_gas_used(5000);
        assert_eq!(laned.non_payment_gas_left, 0);
    }

    #[test]
    fn test_payment_buffer_ordering() {
        // Ensure payment transactions are buffered and returned in the order they were received
        let sender = address!("0000000000000000000000000000000000000001");
        let transactions = vec![
            create_mock_tx(Some(payment_address()), 21000, 0, sender),
            create_mock_tx(Some(payment_address()), 21000, 1, sender),
            create_mock_tx(Some(payment_address()), 21000, 2, sender),
        ];

        let mock_inner = MockBestTransactions::new(transactions);
        let mut laned = LanedTransactions::new(mock_inner, 0); // No gas for non-payments

        // Force immediate switch to payment-only mode
        laned.skip_non_payments();

        // Should yield payment transactions in order
        let tx1 = laned.next().unwrap();
        assert_eq!(tx1.transaction.nonce(), 0);

        let tx2 = laned.next().unwrap();
        assert_eq!(tx2.transaction.nonce(), 1);

        let tx3 = laned.next().unwrap();
        assert_eq!(tx3.transaction.nonce(), 2);

        assert!(laned.next().is_none());
    }

    #[test]
    fn test_non_payment_continues_after_skipping_large_tx() {
        // Test the following scenario:
        // 1. non-payment with gas limit 21000 - included
        // 2. non-payment with very high gas limit - discarded (exceeds remaining)
        // 3. payment tx - buffered
        // 4. non-payment with gas limit 21000 - should be included (fits in remaining gas)

        let sender = address!("0000000000000000000000000000000000000001");
        let non_payment_gas_limit = 50000; // Enough for ~2 small transactions

        let transactions = vec![
            create_mock_tx(Some(non_payment_address()), 21000, 0, sender), // fits
            create_mock_tx(Some(non_payment_address()), 40000, 1, sender), // too large, skipped
            create_mock_tx(Some(payment_address()), 21000, 2, sender),     // payment, buffered
            create_mock_tx(Some(non_payment_address()), 21000, 3, sender), // should fit and be included
        ];

        let mock_inner = MockBestTransactions::new(transactions.clone());
        let mut laned = LanedTransactions::new(mock_inner, non_payment_gas_limit);

        // First non-payment should be yielded (21000 gas)
        let tx1 = laned.next().unwrap();
        assert_eq!(tx1.transaction.nonce(), 0);
        laned.update_non_payment_gas_used(21000);
        assert_eq!(laned.non_payment_gas_left, 29000);

        // Second non-payment (40000) exceeds remaining (29000), should be skipped
        // But we continue processing...

        // Fourth non-payment (21000) fits in remaining gas, should be yielded
        let tx2 = laned.next().unwrap();
        assert_eq!(tx2.transaction.nonce(), 3);
        laned.update_non_payment_gas_used(21000);
        assert_eq!(laned.non_payment_gas_left, 8000);

        // Now we've exhausted the inner iterator, switch to payment mode
        // Payment transaction should be yielded
        let tx3 = laned.next().unwrap();
        assert_eq!(tx3.transaction.nonce(), 2);
        assert!(laned.non_payment_exhausted());

        // No more transactions
        assert!(laned.next().is_none());

        // Verify that the large non-payment transaction (nonce 1) was marked invalid
        assert!(laned.inner.was_marked_invalid(*transactions[1].hash()));
    }

    #[test]
    fn test_payment_transactions_after_exhaustion() {
        // Test that new payment transactions are correctly yielded even after
        // the inner iterator was initially exhausted and we switched to payment-only mode

        // mock iterator that can be updated with new transactions
        struct DynamicMockBestTransactions {
            transactions: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
            index: usize,
            phase: usize, // 0 = initial, 1 = after first exhaustion
        }

        impl DynamicMockBestTransactions {
            fn new(initial: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>) -> Self {
                Self {
                    transactions: initial,
                    index: 0,
                    phase: 0,
                }
            }

            fn add_transactions(
                &mut self,
                new_txs: Vec<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
            ) {
                self.transactions.extend(new_txs);
            }
        }

        impl BestTransactions for DynamicMockBestTransactions {
            fn mark_invalid(
                &mut self,
                _tx: &Arc<ValidPoolTransaction<TempoPooledTransaction>>,
                _error: reth_transaction_pool::error::InvalidPoolTransactionError,
            ) {
            }

            fn no_updates(&mut self) {}
            fn skip_blobs(&mut self) {}
            fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
        }

        impl Iterator for DynamicMockBestTransactions {
            type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

            fn next(&mut self) -> Option<Self::Item> {
                // First phase: return initial transactions
                if self.phase == 0 && self.index < self.transactions.len() {
                    let tx = self.transactions[self.index].clone();
                    self.index += 1;

                    // When we've exhausted initial transactions, switch to phase 1
                    if self.index >= self.transactions.len() {
                        self.phase = 1;
                        // Simulate new transactions arriving
                        let sender = address!("0000000000000000000000000000000000000002");
                        self.add_transactions(vec![
                            create_mock_tx(Some(payment_address()), 21000, 0, sender), // new payment
                            create_mock_tx(Some(non_payment_address()), 21000, 1, sender), // new non-payment (should be skipped)
                            create_mock_tx(Some(payment_address()), 21000, 2, sender), // another new payment
                        ]);
                    }

                    return Some(tx);
                }

                // Second phase: return newly added transactions
                if self.phase == 1 && self.index < self.transactions.len() {
                    let tx = self.transactions[self.index].clone();
                    self.index += 1;
                    return Some(tx);
                }

                None
            }
        }

        let sender1 = address!("0000000000000000000000000000000000000001");

        // Initial transactions: some non-payments and a payment
        let initial_transactions = vec![
            create_mock_tx(Some(non_payment_address()), 21000, 0, sender1),
            create_mock_tx(Some(non_payment_address()), 21000, 1, sender1),
            create_mock_tx(Some(payment_address()), 21000, 2, sender1),
        ];

        let mock_inner = DynamicMockBestTransactions::new(initial_transactions);
        let mut laned = LanedTransactions::new(mock_inner, 50000);

        // Process initial non-payment transactions
        let tx1 = laned.next().unwrap();
        assert_eq!(tx1.transaction.nonce(), 0);
        assert_eq!(tx1.sender(), sender1);
        laned.update_non_payment_gas_used(21000);

        let tx2 = laned.next().unwrap();
        assert_eq!(tx2.transaction.nonce(), 1);
        assert_eq!(tx2.sender(), sender1);
        laned.update_non_payment_gas_used(21000);

        // Get the buffered payment transaction (this exhausts the initial iterator)
        let tx3 = laned.next().unwrap();
        assert_eq!(tx3.transaction.nonce(), 2);
        assert_eq!(tx3.sender(), sender1);
        assert!(laned.non_payment_exhausted());

        // Now the iterator should continue checking for new payment transactions
        // The mock iterator has simulated new transactions arriving

        // Should get the first new payment transaction (sender2, nonce 0)
        let tx4 = laned.next().unwrap();
        assert_eq!(tx4.transaction.nonce(), 0);
        assert_eq!(
            tx4.sender(),
            address!("0000000000000000000000000000000000000002")
        );

        // Should skip the non-payment and get the second new payment (sender2, nonce 2)
        let tx5 = laned.next().unwrap();
        assert_eq!(tx5.transaction.nonce(), 2);
        assert_eq!(
            tx5.sender(),
            address!("0000000000000000000000000000000000000002")
        );

        // No more transactions
        assert!(laned.next().is_none());
    }

    #[test]
    fn test_invalidated_sender_filtering_in_payment_mode() {
        let sender1 = address!("0000000000000000000000000000000000000001");
        let sender2 = address!("0000000000000000000000000000000000000002");

        // Create transactions that will all be buffered initially
        let transactions = vec![
            create_mock_tx(Some(payment_address()), 21000, 0, sender1),
            create_mock_tx(Some(payment_address()), 21000, 0, sender2),
            create_mock_tx(Some(payment_address()), 21000, 1, sender1),
        ];

        let mock_inner = MockBestTransactions::new(transactions);
        let mut laned = LanedTransactions::new(mock_inner, 0); // No gas for non-payments

        // Add sender1 to invalidated list
        laned.invalidated_senders.insert(sender1);

        // Force switch to payment-only mode
        laned.skip_non_payments();

        // Should only yield sender2's transaction
        let tx = laned.next().unwrap();
        assert_eq!(tx.sender(), sender2);

        assert!(laned.next().is_none());
    }
}
