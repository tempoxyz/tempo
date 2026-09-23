//! Amortize root-worker channel operations without changing transaction order.

use crossbeam_channel::Sender;

const BATCH_SIZE: usize = 64;

pub(crate) struct BatchSender<T> {
    sender: Sender<Vec<T>>,
    pending: Vec<T>,
}

impl<T> BatchSender<T> {
    pub(crate) fn new(sender: Sender<Vec<T>>) -> Self {
        Self {
            sender,
            pending: Vec::with_capacity(BATCH_SIZE),
        }
    }

    pub(crate) fn push(&mut self, item: T) {
        self.pending.push(item);
        if self.pending.len() == BATCH_SIZE {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if !self.pending.is_empty() {
            let batch = std::mem::replace(&mut self.pending, Vec::with_capacity(BATCH_SIZE));
            // The result receiver reports a failed worker, as before batching.
            let _ = self.sender.send(batch);
        }
    }
}

impl<T> Drop for BatchSender<T> {
    fn drop(&mut self) {
        // A block can stop at any transaction cutoff. Send the final partial
        // batch before closing the channel and letting the worker finalize roots.
        if !self.pending.is_empty() {
            let _ = self.sender.send(std::mem::take(&mut self.pending));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_block_cutoff_preserves_order_and_closes_the_worker() {
        for len in [
            0,
            1,
            BATCH_SIZE - 1,
            BATCH_SIZE,
            BATCH_SIZE + 1,
            3 * BATCH_SIZE + 7,
        ] {
            let (tx, rx) = crossbeam_channel::unbounded();
            let mut sender = BatchSender::new(tx);
            for item in 0..len {
                sender.push(item);
            }
            drop(sender);
            let batches = rx.into_iter().collect::<Vec<_>>();
            assert!(
                batches
                    .iter()
                    .all(|batch| !batch.is_empty() && batch.len() <= BATCH_SIZE)
            );
            assert_eq!(
                batches.into_iter().flatten().collect::<Vec<_>>(),
                (0..len).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn failed_worker_does_not_panic_at_cutoff() {
        let (tx, rx) = crossbeam_channel::unbounded();
        drop(rx);
        let mut sender = BatchSender::new(tx);
        for item in 0..BATCH_SIZE + 1 {
            sender.push(item);
        }
        drop(sender);
    }
}
