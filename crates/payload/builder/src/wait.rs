//! Wake an idle builder when the pool or prewarming has more work.

use alloy_primitives::B256;
use crossbeam_channel::{Receiver, Sender, bounded};
use reth_tasks::TaskExecutor;
use std::time::Duration;
use tokio::{sync::mpsc, task::JoinHandle};

/// Cancellation is an atomic flag without a wakeup, so bound otherwise idle waits.
const CANCEL_CHECK_INTERVAL: Duration = Duration::from_millis(1);

pub(crate) struct TransactionWaiter {
    notifications: Receiver<()>,
    notifier: Sender<()>,
    pool_listener: JoinHandle<()>,
}

impl TransactionWaiter {
    pub(crate) fn new(executor: &TaskExecutor, mut pending: mpsc::Receiver<B256>) -> Self {
        // Coalesce notifications: they are hints to retry the iterator, not transactions to consume.
        let (notifier, notifications) = bounded(1);
        let pool_notifier = notifier.clone();
        let pool_listener = executor.spawn_task(async move {
            while pending.recv().await.is_some() {
                let _ = pool_notifier.try_send(());
            }
        });
        Self {
            notifications,
            notifier,
            pool_listener,
        }
    }

    pub(crate) fn notifier(&self) -> Sender<()> {
        self.notifier.clone()
    }

    /// A notification already queued before this call also wakes the builder immediately.
    pub(crate) fn wait(&self, remaining_budget: Duration) -> bool {
        self.notifications
            .recv_timeout(remaining_budget.min(CANCEL_CHECK_INTERVAL))
            .is_ok()
    }
}

impl Drop for TransactionWaiter {
    fn drop(&mut self) {
        self.pool_listener.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_transaction_wakes_builder() {
        let executor = TaskExecutor::test();
        let (pending, receiver) = mpsc::channel(1);
        let waiter = TransactionWaiter::new(&executor, receiver);
        pending.blocking_send(B256::ZERO).unwrap();
        waiter
            .notifications
            .recv_timeout(Duration::from_secs(5))
            .expect("pool notification must reach the builder");
    }

    #[test]
    fn notifications_before_wait_are_retained_and_coalesced() {
        let executor = TaskExecutor::test();
        let (_pending, receiver) = mpsc::channel(1);
        let waiter = TransactionWaiter::new(&executor, receiver);
        let notifier = waiter.notifier();
        notifier.try_send(()).unwrap();
        assert!(notifier.try_send(()).unwrap_err().is_full());
        assert!(waiter.wait(Duration::ZERO));
        assert!(!waiter.wait(Duration::ZERO));
    }

    #[test]
    fn dropping_waiter_closes_pool_listener() {
        let executor = TaskExecutor::test();
        let (pending, receiver) = mpsc::channel(1);
        drop(TransactionWaiter::new(&executor, receiver));
        executor.handle().block_on(async {
            tokio::time::timeout(Duration::from_secs(5), pending.closed())
                .await
                .expect("builder drop must release the pool subscription");
        });
    }
}
