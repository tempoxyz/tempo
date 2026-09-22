//! Idle waits share one deadline and consume pool notifications directly.

use alloy_primitives::B256;
use reth_tasks::TaskExecutor;
use std::{
    future::Future,
    time::{Duration, Instant},
};
use tokio::{runtime::Handle, sync::mpsc};

pub(crate) enum WaitResult<T> {
    Ready(T),
    PoolChanged,
    TimedOut,
}

pub(crate) struct TransactionWaiter {
    pending: Option<mpsc::Receiver<B256>>,
    runtime: Handle,
    deadline: Instant,
    idle_elapsed: Duration,
}

impl TransactionWaiter {
    pub(crate) fn new(executor: &TaskExecutor, pending: mpsc::Receiver<B256>) -> Self {
        Self {
            pending: Some(pending),
            runtime: executor.handle().clone(),
            deadline: Instant::now(),
            idle_elapsed: Duration::ZERO,
        }
    }

    pub(crate) fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }

    pub(crate) fn take_idle_elapsed(&mut self) -> Duration {
        std::mem::take(&mut self.idle_elapsed)
    }

    /// While the source is empty, a pool arrival requests another source poll.
    /// Otherwise only a result or the deadline can wake this wait.
    pub(crate) fn wait<T>(
        &mut self,
        ready: impl Future<Output = T>,
        pool_idle: bool,
    ) -> WaitResult<T> {
        let start = Instant::now();
        if start >= self.deadline {
            return WaitResult::TimedOut;
        }
        let result = self.runtime.block_on(async {
            tokio::select! {
                biased;
                result = ready => WaitResult::Ready(result),
                _ = tokio::time::sleep_until(self.deadline.into()) => WaitResult::TimedOut,
                () = pending_transactions_changed(&mut self.pending), if pool_idle => WaitResult::PoolChanged,
            }
        });
        if pool_idle {
            self.idle_elapsed += start.elapsed();
        }
        result
    }
}

async fn pending_transactions_changed(pending: &mut Option<mpsc::Receiver<B256>>) {
    let Some(receiver) = pending else {
        return std::future::pending().await;
    };
    if receiver.recv().await.is_none() {
        *pending = None;
        return std::future::pending().await;
    }
    // Bound the drain so continuous arrivals cannot postpone the deadline.
    for _ in 0..receiver.len() {
        let _ = receiver.try_recv();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{pending, ready};

    #[test]
    fn ready_work_wins_without_consuming_pool_notifications() {
        let executor = TaskExecutor::test();
        let (sender, receiver) = mpsc::channel(8);
        let mut waiter = TransactionWaiter::new(&executor, receiver);
        waiter.set_deadline(Instant::now() + Duration::from_secs(1));
        for _ in 0..8 {
            sender.try_send(B256::ZERO).unwrap();
        }
        assert!(matches!(
            waiter.wait(ready(42), false),
            WaitResult::Ready(42)
        ));
        assert_eq!(waiter.take_idle_elapsed(), Duration::ZERO);
        assert_eq!(waiter.pending.as_ref().unwrap().len(), 8);
        assert!(matches!(
            waiter.wait(pending::<()>(), true),
            WaitResult::PoolChanged
        ));
        assert!(waiter.pending.as_ref().unwrap().is_empty());
        drop(waiter);
        assert!(sender.is_closed());
    }

    #[test]
    fn pool_arrival_wakes_an_idle_wait() {
        let executor = TaskExecutor::test();
        let (sender, receiver) = mpsc::channel(1);
        let mut waiter = TransactionWaiter::new(&executor, receiver);
        waiter.set_deadline(Instant::now() + Duration::from_secs(5));
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            sender.try_send(B256::ZERO).unwrap();
        });
        assert!(matches!(
            waiter.wait(pending::<()>(), true),
            WaitResult::PoolChanged
        ));
        assert!(waiter.take_idle_elapsed() > Duration::ZERO);
        sender.join().unwrap();
    }

    #[test]
    fn closed_subscription_waits_until_deadline() {
        let executor = TaskExecutor::test();
        let (sender, receiver) = mpsc::channel(1);
        let mut waiter = TransactionWaiter::new(&executor, receiver);
        drop(sender);
        let deadline = Instant::now() + Duration::from_millis(10);
        waiter.set_deadline(deadline);
        assert!(matches!(
            waiter.wait(pending::<()>(), true),
            WaitResult::TimedOut
        ));
        assert!(waiter.pending.is_none());
        assert!(Instant::now() >= deadline);
        assert!(waiter.take_idle_elapsed() > Duration::ZERO);
    }

    #[test]
    fn elapsed_deadline_does_not_consume_ready_work() {
        let executor = TaskExecutor::test();
        let (_sender, receiver) = mpsc::channel(1);
        let mut waiter = TransactionWaiter::new(&executor, receiver);
        let (sender, mut ready) = mpsc::channel(1);
        sender.try_send(42).unwrap();
        assert!(matches!(
            waiter.wait(ready.recv(), false),
            WaitResult::TimedOut
        ));
        assert_eq!(ready.try_recv(), Ok(42));
    }
}
