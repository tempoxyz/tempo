//! Bound blocking receives and idle batching by one deadline.

use std::{
    sync::mpsc::Receiver,
    time::{Duration, Instant},
};

pub(crate) struct TransactionWaiter {
    deadline: Instant,
    idle_elapsed: Duration,
    /// Parallel results include EVM execution; ordinary iterator handoffs do not.
    waits_for_execution: bool,
}

impl TransactionWaiter {
    pub(crate) fn new(waits_for_execution: bool) -> Self {
        Self {
            deadline: Instant::now(),
            idle_elapsed: Duration::ZERO,
            waits_for_execution,
        }
    }

    pub(crate) fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }

    pub(crate) fn take_idle_elapsed(&mut self) -> Duration {
        std::mem::take(&mut self.idle_elapsed)
    }

    pub(crate) fn recv<T>(&mut self, receiver: &Receiver<T>) -> Option<T> {
        let start = Instant::now();
        let remaining = self.deadline.checked_duration_since(start)?;
        let result = receiver.recv_timeout(remaining).ok();
        if !self.waits_for_execution {
            self.idle_elapsed += start.elapsed();
        }
        result
    }

    pub(crate) fn wait_for_deadline(&mut self) {
        let start = Instant::now();
        if let Some(remaining) = self.deadline.checked_duration_since(start) {
            std::thread::sleep(remaining);
            self.idle_elapsed += start.elapsed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn elapsed_deadline_does_not_consume_ready_work() {
        let mut waiter = TransactionWaiter::new(false);
        let (sender, receiver) = mpsc::channel();
        sender.send(42).unwrap();
        assert!(waiter.recv(&receiver).is_none());
        assert_eq!(receiver.try_recv(), Ok(42));
    }

    #[test]
    fn only_execution_waits_are_charged_as_replayable_work() {
        for waits_for_execution in [false, true] {
            let mut waiter = TransactionWaiter::new(waits_for_execution);
            waiter.set_deadline(Instant::now() + Duration::from_secs(5));
            let (sender, receiver) = mpsc::channel();
            let producer = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                sender.send(42).unwrap();
            });
            assert_eq!(waiter.recv(&receiver), Some(42));
            assert_eq!(waiter.take_idle_elapsed().is_zero(), waits_for_execution);
            producer.join().unwrap();
        }
    }

    #[test]
    fn idle_wait_does_not_extend_a_receive_deadline() {
        let mut waiter = TransactionWaiter::new(true);
        let deadline = Instant::now() + Duration::from_millis(10);
        waiter.set_deadline(deadline);
        let (_sender, receiver) = mpsc::channel::<()>();
        assert!(waiter.recv(&receiver).is_none());
        assert!(Instant::now() >= deadline);
        waiter.wait_for_deadline();
        assert_eq!(waiter.take_idle_elapsed(), Duration::ZERO);
    }

    #[test]
    fn idle_wait_records_actual_elapsed_time() {
        let mut waiter = TransactionWaiter::new(false);
        let deadline = Instant::now() + Duration::from_millis(10);
        waiter.set_deadline(deadline);
        waiter.wait_for_deadline();
        assert!(Instant::now() >= deadline);
        assert!(waiter.take_idle_elapsed() > Duration::ZERO);
    }
}
