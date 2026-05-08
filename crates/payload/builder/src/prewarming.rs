use std::sync::mpsc::{self, Receiver, Sender};

use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_transaction_pool::best::BestTransaction;

/// Event returned by [`BestTransactionsPrewarming`].
#[derive(Debug)]
enum BestTransactionsEvent {
    /// A transaction is ready for sequential payload execution.
    Transaction(BestTransaction),
    /// No transaction is currently buffered.
    Empty,
}

/// Command sent by [`BestTransactionsPrewarming`] consumer.
#[derive(Debug)]
enum BestTransactionsCommand {
    Invalid(InvalidTransaction),
    NoUpdates,
    SkipBlobs(bool),
    Stop,
}

#[derive(Debug)]
struct InvalidTransaction {
    tx: BestTransaction,
    kind: InvalidPoolTransactionError,
    old_receiver: Receiver<BestTransactionsEvent>,
    new_sender: Sender<BestTransactionsEvent>,
}

/// Drains a [`BestTransactions`] iterator into a channel while preserving delayed invalidation.
pub(crate) struct BestTransactionsPrewarming {
    rx: Receiver<BestTransactionsEvent>,
    commands_tx: Sender<BestTransactionsCommand>,
}

impl BestTransactionsPrewarming {
    /// Spawns a payload-scoped coordinator for `best_txs`.
    pub(crate) fn new<Txs>(executor: &TaskExecutor, best_txs: Txs) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        executor.spawn_blocking_named("builder-prewarm", move || {
            Self::start_prewarming(best_txs, tx, commands_rx);
        });

        Self { rx, commands_tx }
    }

    fn start_prewarming<Txs>(
        mut best_txs: Txs,
        mut sender: Sender<BestTransactionsEvent>,
        command_receiver: Receiver<BestTransactionsCommand>,
    ) where
        Txs: BestTransactions<Item = BestTransaction>,
    {
        loop {
            if let Some(tx) = best_txs.next() {
                if sender.send(BestTransactionsEvent::Transaction(tx)).is_err() {
                    break;
                }

                // TODO: prewarm state by executing the transaction `tx` on top of latest state
            } else {
                // No more best transactions for now. We do not break the loop,
                // because there may be more transactions later.
                if sender.send(BestTransactionsEvent::Empty).is_err() {
                    break;
                }
            }

            while let Ok(command) = command_receiver.try_recv() {
                match command {
                    // On invalid transaction, mark it as invalid, drain all pending
                    // transactions from the old receiver, filter out invalid ones,
                    // and redirect valid to the new sender.
                    BestTransactionsCommand::Invalid(invalid) => {
                        best_txs.mark_invalid(&invalid.tx, &invalid.kind);

                        while let Ok(event) = invalid.old_receiver.try_recv() {
                            if let BestTransactionsEvent::Transaction(tx) = &event
                                && !is_invalidated_buffered_transaction(&invalid.tx, tx)
                            {
                                let _ = invalid.new_sender.send(event);
                            }
                        }

                        sender = invalid.new_sender;
                    }
                    BestTransactionsCommand::NoUpdates => best_txs.no_updates(),
                    BestTransactionsCommand::SkipBlobs(skip_blobs) => {
                        best_txs.set_skip_blobs(skip_blobs)
                    }
                    BestTransactionsCommand::Stop => break,
                }
            }
        }
    }
}

impl Drop for BestTransactionsPrewarming {
    fn drop(&mut self) {
        let _ = self.commands_tx.send(BestTransactionsCommand::Stop);
    }
}

impl Iterator for BestTransactionsPrewarming {
    type Item = BestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        match self.rx.recv() {
            Ok(BestTransactionsEvent::Transaction(tx)) => Some(tx),
            Ok(BestTransactionsEvent::Empty) | Err(_) => None,
        }
    }
}

impl BestTransactions for BestTransactionsPrewarming {
    fn mark_invalid(&mut self, transaction: &Self::Item, _kind: &InvalidPoolTransactionError) {
        let (new_sender, new_receiver) = mpsc::channel();
        let old_receiver = std::mem::replace(&mut self.rx, new_receiver);
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::Invalid(InvalidTransaction {
                tx: transaction.clone(),
                // kind: kind.clone(),
                kind: InvalidPoolTransactionError::Underpriced,
                old_receiver,
                new_sender,
            }));
    }

    fn no_updates(&mut self) {
        let _ = self.commands_tx.send(BestTransactionsCommand::NoUpdates);
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::SkipBlobs(skip_blobs));
    }
}

/// Returns whether the candidate transaction is invalidated by the given invalid transaction.
fn is_invalidated_buffered_transaction(
    invalid: &BestTransaction,
    candidate: &BestTransaction,
) -> bool {
    // Skip invalidation for expiring nonce transactions - they are independent
    // and should not block other expiring nonce txs from the same sender
    if invalid.transaction.is_expiring_nonce() {
        return false;
    }

    if invalid.transaction.is_aa_2d() {
        candidate
            .transaction
            .aa_transaction_id()
            .zip(invalid.transaction.aa_transaction_id())
            .is_some_and(|(candidate_id, invalid_id)| candidate_id.seq_id() == invalid_id.seq_id())
    } else {
        candidate.transaction.sender() == invalid.transaction.sender()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256};
    use std::thread::{self};
    use tempo_transaction_pool::test_utils::{
        MockBestTransactions, MockBestTransactionsSender, tx_with_nonce_key,
    };

    fn start_prewarming_for_test() -> (
        BestTransactionsPrewarming,
        MockBestTransactionsSender<BestTransaction>,
    ) {
        let (best_txs, responses) = MockBestTransactions::channel();
        let (tx, rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        thread::spawn(move || {
            BestTransactionsPrewarming::start_prewarming(best_txs, tx, commands_rx);
        });

        (BestTransactionsPrewarming { rx, commands_tx }, responses)
    }

    fn test_tx(id: u8, nonce: u64) -> BestTransaction {
        tx_with_nonce_key(
            U256::ZERO,
            Address::with_last_byte(id.wrapping_add(32)),
            nonce,
            u128::from(id) + 1,
        )
    }

    fn observed_hash(tx: Option<BestTransaction>) -> Option<B256> {
        tx.map(|tx| *tx.hash())
    }

    fn send_response(
        responses: &MockBestTransactionsSender<BestTransaction>,
        response: Option<BestTransaction>,
    ) {
        MockBestTransactions::send_response(responses, response, 0);
    }

    fn collect_direct(sequence: &[Option<BestTransaction>]) -> Vec<Option<B256>> {
        let (mut best_txs, responses) = MockBestTransactions::channel();
        let mut observed = Vec::with_capacity(sequence.len());

        for response in sequence.iter().cloned() {
            send_response(&responses, response);
            observed.push(observed_hash(best_txs.next()));
        }

        observed
    }

    fn collect_prewarmed(sequence: &[Option<BestTransaction>]) -> Vec<Option<B256>> {
        let (mut prewarming, responses) = start_prewarming_for_test();
        let mut observed = Vec::with_capacity(sequence.len());

        for response in sequence.iter().cloned() {
            send_response(&responses, response);
            observed.push(observed_hash(prewarming.next()));
        }

        observed
    }

    #[test]
    fn prewarming_returns_none_without_fusing_iterator() {
        let tx0 = test_tx(0, 0);
        let tx1 = test_tx(1, 1);
        let tx0_hash = *tx0.hash();
        let tx1_hash = *tx1.hash();
        let (mut prewarming, responses) = start_prewarming_for_test();

        send_response(&responses, Some(tx0));
        assert_eq!(observed_hash(prewarming.next()), Some(tx0_hash));

        send_response(&responses, None);
        assert!(prewarming.next().is_none());

        send_response(&responses, None);
        assert!(prewarming.next().is_none());

        send_response(&responses, Some(tx1));
        assert_eq!(observed_hash(prewarming.next()), Some(tx1_hash));

        send_response(&responses, None);
        assert!(prewarming.next().is_none());
    }

    #[test]
    fn prewarming_matches_direct_best_transactions_none_sequence() {
        let tx0 = test_tx(0, 0);
        let tx1 = test_tx(1, 1);
        let sequence = vec![Some(tx0), None, None, Some(tx1), None];

        assert_eq!(collect_prewarmed(&sequence), collect_direct(&sequence));
    }
}
