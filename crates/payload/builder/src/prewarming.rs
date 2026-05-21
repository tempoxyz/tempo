use std::sync::mpsc::{self, Receiver, Sender};

use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_transaction_pool::best::BestTransaction;

/// Prewarming orchestrator that consumes source [`BestTransactions`] ahead of time,
/// prewarmes transactions in parallel, and produces a new [`BestTransactions`] iterator
/// with the source order and invalidations triggered by [`Self::mark_invalid`] preserved.
pub(crate) struct BestTransactionsPrewarming {
    events_rx: Receiver<BestTransactionsEvent>,
    commands_tx: Sender<BestTransactionsCommand>,
}

impl BestTransactionsPrewarming {
    /// Spawns prewarming for `best_txs` and returns a new [`BestTransactions`] iterator.
    pub(crate) fn new<Txs>(executor: &TaskExecutor, best_txs: Txs) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
    {
        let (events_tx, events_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        executor.spawn_blocking_named("builder-prewarm", move || {
            Self::start_prewarming(BestTransactionsPrewarmingContext {
                best_txs,
                events_tx,
                commands_rx,
            });
        });

        Self {
            events_rx,
            commands_tx,
        }
    }

    /// Runs the producer side of prewarming for a payload build.
    ///
    /// See [`BestTransactionsPrewarming`] for details.
    fn start_prewarming<Txs>(mut ctx: BestTransactionsPrewarmingContext<Txs>)
    where
        Txs: BestTransactions<Item = BestTransaction>,
    {
        loop {
            if let Some(tx) = ctx.best_txs.next() {
                if ctx
                    .events_tx
                    .send(BestTransactionsEvent::Transaction(tx))
                    .is_err()
                {
                    break;
                }

                // TODO: prewarm state by executing the transaction `tx` on top of latest state
            } else {
                // No more best transactions for now. We do not break the loop,
                // because there may be more transactions later.
                if ctx.events_tx.send(BestTransactionsEvent::Empty).is_err() {
                    break;
                }
            }

            while let Ok(command) = ctx.commands_rx.try_recv() {
                match command {
                    // On invalid transaction, mark it as invalid, drain all pending
                    // transactions from the old receiver, filter out invalid ones,
                    // and redirect valid to the new sender.
                    BestTransactionsCommand::Invalid(invalid) => {
                        ctx.events_tx = invalid.new_events_tx;

                        ctx.best_txs.mark_invalid(&invalid.tx, invalid.kind);
                        while let Ok(event) = invalid.old_events_rx.try_recv() {
                            if let BestTransactionsEvent::Transaction(tx) = &event
                                && !is_invalidated_buffered_transaction(&invalid.tx, tx)
                            {
                                let _ = ctx.events_tx.send(event);
                            }
                        }
                    }
                    BestTransactionsCommand::NoUpdates => ctx.best_txs.no_updates(),
                    BestTransactionsCommand::SkipBlobs(skip_blobs) => {
                        ctx.best_txs.set_skip_blobs(skip_blobs)
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
        match self.events_rx.recv() {
            Ok(BestTransactionsEvent::Transaction(tx)) => Some(tx),
            Ok(BestTransactionsEvent::Empty) | Err(_) => None,
        }
    }
}

impl BestTransactions for BestTransactionsPrewarming {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        let (new_events_tx, new_events_rx) = mpsc::channel();
        let old_events_rx = std::mem::replace(&mut self.events_rx, new_events_rx);
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::Invalid(InvalidTransaction {
                tx: transaction.clone(),
                kind,
                old_events_rx,
                new_events_tx,
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

/// Context for prewarming best transactions for a payload build.
struct BestTransactionsPrewarmingContext<Txs> {
    best_txs: Txs,
    events_tx: Sender<BestTransactionsEvent>,
    commands_rx: Receiver<BestTransactionsCommand>,
}

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
    old_events_rx: Receiver<BestTransactionsEvent>,
    /// Sender for existing transactions from `old_events_rx` and new transactions.
    new_events_tx: Sender<BestTransactionsEvent>,
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
