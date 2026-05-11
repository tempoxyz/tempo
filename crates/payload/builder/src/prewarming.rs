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

/// Invalid transaction encountered during execution.
#[derive(Debug)]
struct InvalidTransaction {
    tx: BestTransaction,
    kind: InvalidPoolTransactionError,
    /// Transactions sent from prewarming to executor that needs to be revalidated
    /// against the invalid transaction.
    old_receiver: Receiver<BestTransactionsEvent>,
    /// Sender for existing transactions from `old_receiver` and new transactions.
    new_sender: Sender<BestTransactionsEvent>,
}

/// Prewarming orchestrator that consumes source [`BestTransactions`] ahead of time,
/// prewarmes transactions in parallel, and produces a new [`BestTransactions`] iterator
/// with the source order and invalidations triggered by [`Self::mark_invalid`] preserved.
pub(crate) struct BestTransactionsPrewarming {
    rx: Receiver<BestTransactionsEvent>,
    commands_tx: Sender<BestTransactionsCommand>,
}

impl BestTransactionsPrewarming {
    /// Spawns prewarming for `best_txs` and returns a new [`BestTransactions`] iterator.
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

    /// Runs the producer side of prewarming for a payload build.
    ///
    /// See [`BestTransactionsPrewarming`] for details.
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
                        sender = invalid.new_sender;

                        best_txs.mark_invalid(&invalid.tx, invalid.kind);
                        while let Ok(event) = invalid.old_receiver.try_recv() {
                            if let BestTransactionsEvent::Transaction(tx) = &event
                                && !is_invalidated_buffered_transaction(&invalid.tx, tx)
                            {
                                let _ = sender.send(event);
                            }
                        }
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
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        let (new_sender, new_receiver) = mpsc::channel();
        let old_receiver = std::mem::replace(&mut self.rx, new_receiver);
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::Invalid(InvalidTransaction {
                tx: transaction.clone(),
                kind,
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
