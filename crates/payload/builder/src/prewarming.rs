use std::sync::mpsc::{self, Receiver, Sender};

use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_transaction_pool::best::BestTransaction;

/// Event returned by [`BestTransactionsStream`].
#[derive(Debug)]
pub(crate) enum BestTransactionsStreamEvent {
    /// A transaction is ready for sequential payload execution.
    Transaction(BestTransaction),
    /// No transaction is currently buffered.
    Empty,
}

enum BestTransactionsStreamCommand {
    Invalid(InvalidTransaction),
    NoUpdates,
    SkipBlobs(bool),
    Stop,
}

struct InvalidTransaction {
    tx: BestTransaction,
    kind: InvalidPoolTransactionError,
    old_receiver: Receiver<BestTransactionsStreamEvent>,
    new_sender: Sender<BestTransactionsStreamEvent>,
}

/// Drains a [`BestTransactions`] iterator into a channel while preserving delayed invalidation.
pub(crate) struct BestTransactionsPrewarming {
    rx: Receiver<BestTransactionsStreamEvent>,
    commands_tx: Sender<BestTransactionsStreamCommand>,
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
        mut sender: Sender<BestTransactionsStreamEvent>,
        command_receiver: Receiver<BestTransactionsStreamCommand>,
    ) where
        Txs: BestTransactions<Item = BestTransaction>,
    {
        loop {
            if let Some(tx) = best_txs.next() {
                if sender
                    .send(BestTransactionsStreamEvent::Transaction(tx))
                    .is_err()
                {
                    break;
                }

                // TODO: prewarm state by executing the transaction `tx` on top of latest state
            } else {
                // No more best transactions for now. We do not break the loop,
                // because there may be more transactions later.
                if sender.send(BestTransactionsStreamEvent::Empty).is_err() {
                    break;
                }
            }

            while let Ok(command) = command_receiver.try_recv() {
                match command {
                    // On invalid transaction, mark it as invalid, drain all pending
                    // transactions from the old receiver, filter out invalid ones,
                    // and redirect valid to the new sender.
                    BestTransactionsStreamCommand::Invalid(invalid) => {
                        best_txs.mark_invalid(&invalid.tx, &invalid.kind);

                        while let Ok(event) = invalid.old_receiver.try_recv() {
                            if let BestTransactionsStreamEvent::Transaction(tx) = &event
                                && !is_invalidated_buffered_transaction(&invalid.tx, tx)
                            {
                                let _ = invalid.new_sender.send(event);
                            }
                        }

                        sender = invalid.new_sender;
                    }
                    BestTransactionsStreamCommand::NoUpdates => best_txs.no_updates(),
                    BestTransactionsStreamCommand::SkipBlobs(skip_blobs) => {
                        best_txs.set_skip_blobs(skip_blobs)
                    }
                    BestTransactionsStreamCommand::Stop => break,
                }
            }
        }
    }
}

impl Drop for BestTransactionsPrewarming {
    fn drop(&mut self) {
        let _ = self.commands_tx.send(BestTransactionsStreamCommand::Stop);
    }
}

impl Iterator for BestTransactionsPrewarming {
    type Item = BestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        match self.rx.recv() {
            Ok(BestTransactionsStreamEvent::Transaction(tx)) => Some(tx),
            Ok(BestTransactionsStreamEvent::Empty) | Err(_) => None,
        }
    }
}

impl BestTransactions for BestTransactionsPrewarming {
    fn mark_invalid(&mut self, transaction: &Self::Item, _kind: &InvalidPoolTransactionError) {
        let (new_sender, new_receiver) = mpsc::channel();
        let old_receiver = std::mem::replace(&mut self.rx, new_receiver);
        let _ = self
            .commands_tx
            .send(BestTransactionsStreamCommand::Invalid(InvalidTransaction {
                tx: transaction.clone(),
                // kind: kind.clone(),
                kind: InvalidPoolTransactionError::Underpriced,
                old_receiver,
                new_sender,
            }));
    }

    fn no_updates(&mut self) {
        let _ = self
            .commands_tx
            .send(BestTransactionsStreamCommand::NoUpdates);
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        let _ = self
            .commands_tx
            .send(BestTransactionsStreamCommand::SkipBlobs(skip_blobs));
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
