//! Bounded admission validation workers. Queue ownership ends before a job runs.

use futures::future::BoxFuture;
use reth_primitives_traits::SealedBlock;
use reth_transaction_pool::{
    PoolTransaction, TransactionOrigin, TransactionValidationOutcome, TransactionValidator,
    metrics::TxPoolValidatorMetrics, validate::TransactionValidatorError,
};
use std::{future::Future, sync::Arc};
use tokio::sync::{Mutex, mpsc, oneshot};

type Job = BoxFuture<'static, ()>;

/// A cloneable worker sharing the bounded queue with the other workers.
#[derive(Clone)]
pub struct TempoValidationTask {
    jobs: Arc<Mutex<mpsc::Receiver<Job>>>,
}

impl std::fmt::Debug for TempoValidationTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempoValidationTask")
            .finish_non_exhaustive()
    }
}

impl TempoValidationTask {
    /// Run until all senders are dropped and queued jobs have completed.
    pub async fn run(self) {
        loop {
            // A `while let` scrutinee would retain this guard through `job.await`,
            // serializing all workers even though validation uses independent providers.
            let job = { self.jobs.lock().await.recv().await };
            let Some(job) = job else { break };
            job.await;
        }
    }
}

/// Runs the existing validator on a fixed number of externally spawned workers.
/// Batches remain single jobs, preserving the wrapped validator's batch behavior.
#[derive(Debug)]
pub struct TempoValidationTaskExecutor<V> {
    validator: Arc<V>,
    jobs: mpsc::Sender<Job>,
    metrics: Arc<TxPoolValidatorMetrics>,
}

impl<V> Clone for TempoValidationTaskExecutor<V> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
            jobs: self.jobs.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<V> TempoValidationTaskExecutor<V> {
    /// Create an executor and a cloneable worker. Capacity bounds queued jobs;
    /// the caller controls concurrency by spawning a fixed number of worker clones.
    pub fn new(validator: V, capacity: usize) -> (Self, TempoValidationTask) {
        let (jobs, receiver) = mpsc::channel(capacity.max(1));
        (
            Self {
                validator: Arc::new(validator),
                jobs,
                metrics: Default::default(),
            },
            TempoValidationTask {
                jobs: Arc::new(Mutex::new(receiver)),
            },
        )
    }

    /// Access the shared validator for head updates and Tempo pool state.
    pub fn validator(&self) -> &V {
        &self.validator
    }

    async fn execute<T: Send + 'static>(
        &self,
        job: impl Future<Output = T> + Send + 'static,
    ) -> Result<T, TransactionValidatorError> {
        let (sender, receiver) = oneshot::channel();
        self.metrics.inflight_validation_jobs.increment(1.0);
        let waiting = WaitingForCapacity(&self.metrics.inflight_validation_jobs);
        self.jobs
            .send(Box::pin(async move {
                let _ = sender.send(job.await);
            }))
            .await
            .map_err(|_| TransactionValidatorError::ValidationServiceUnreachable)?;
        drop(waiting);
        receiver
            .await
            .map_err(|_| TransactionValidatorError::ValidationServiceUnreachable)
    }
}

/// Keep the queue-pressure gauge correct even if the submitter is cancelled.
struct WaitingForCapacity<'a>(&'a metrics::Gauge);
impl Drop for WaitingForCapacity<'_> {
    fn drop(&mut self) {
        self.0.decrement(1.0);
    }
}

impl<V: TransactionValidator + 'static> TransactionValidator for TempoValidationTaskExecutor<V> {
    type Transaction = V::Transaction;
    type Block = V::Block;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        let hash = *transaction.hash();
        let validator = self.validator.clone();
        self.execute(async move { validator.validate_transaction(origin, transaction).await })
            .await
            .unwrap_or_else(|err| TransactionValidationOutcome::Error(hash, Box::new(err)))
    }

    async fn validate_transactions(
        &self,
        transactions: impl IntoIterator<Item = (TransactionOrigin, Self::Transaction), IntoIter: Send>
        + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        let transactions: Vec<_> = transactions.into_iter().collect();
        let hashes: Vec<_> = transactions.iter().map(|(_, tx)| *tx.hash()).collect();
        let validator = self.validator.clone();
        self.execute(async move { validator.validate_transactions(transactions).await })
            .await
            .unwrap_or_else(|_| {
                hashes
                    .into_iter()
                    .map(|hash| {
                        TransactionValidationOutcome::Error(
                            hash,
                            Box::new(TransactionValidatorError::ValidationServiceUnreachable),
                        )
                    })
                    .collect()
            })
    }

    fn on_new_head_block(&self, block: &SealedBlock<Self::Block>) {
        self.validator.on_new_head_block(block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use reth_transaction_pool::{test_utils::MockTransaction, validate::ValidTransaction};
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[tokio::test]
    async fn workers_release_queue_before_running_validation() {
        let (executor, task) = TempoValidationTaskExecutor::new((), 2);
        let first = tokio::spawn(task.clone().run());
        let second = tokio::spawn(task.run());
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut jobs = Vec::new();
        for _ in 0..2 {
            let barrier = barrier.clone();
            let executor = executor.clone();
            jobs.push(tokio::spawn(async move {
                executor
                    .execute(async move {
                        barrier.wait().await;
                    })
                    .await
                    .unwrap();
            }));
        }
        tokio::time::timeout(Duration::from_secs(1), barrier.wait())
            .await
            .expect("validation workers serialized while holding the job queue");
        for job in jobs {
            job.await.unwrap();
        }
        drop(executor);
        first.await.unwrap();
        second.await.unwrap();
    }

    #[tokio::test]
    async fn queue_capacity_does_not_increase_worker_concurrency() {
        let (executor, task) = TempoValidationTaskExecutor::new((), 1);
        let worker = tokio::spawn(task.run());
        let (started, ready) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let busy = executor.clone();
        let first = tokio::spawn(async move {
            busy.execute(async move {
                started.send(()).unwrap();
                resume.await.unwrap();
            })
            .await
            .unwrap();
        });
        ready.await.unwrap();
        executor.jobs.try_send(Box::pin(async {})).unwrap();
        assert!(matches!(
            executor.jobs.try_send(Box::pin(async {})),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        release.send(()).unwrap();
        first.await.unwrap();
        drop(executor);
        worker.await.unwrap();
    }

    #[derive(Debug, Default)]
    struct Validator {
        batches: AtomicUsize,
        heads: AtomicUsize,
    }

    impl TransactionValidator for Validator {
        type Transaction = MockTransaction;
        type Block = reth_ethereum_primitives::Block;

        async fn validate_transaction(
            &self,
            origin: TransactionOrigin,
            tx: MockTransaction,
        ) -> TransactionValidationOutcome<MockTransaction> {
            TransactionValidationOutcome::Valid {
                balance: U256::from(123),
                state_nonce: 7,
                bytecode_hash: None,
                transaction: ValidTransaction::Valid(tx),
                propagate: matches!(origin, TransactionOrigin::External),
                authorities: Some(vec![Address::ZERO]),
            }
        }

        async fn validate_transactions(
            &self,
            txs: impl IntoIterator<Item = (TransactionOrigin, MockTransaction), IntoIter: Send> + Send,
        ) -> Vec<TransactionValidationOutcome<MockTransaction>> {
            self.batches.fetch_add(1, Ordering::Relaxed);
            let mut out = Vec::new();
            for (origin, tx) in txs {
                out.push(self.validate_transaction(origin, tx).await);
            }
            out
        }

        fn on_new_head_block(&self, _: &SealedBlock<Self::Block>) {
            self.heads.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn batches_preserve_validator_snapshot_boundary_order_and_metadata() {
        let (executor, task) = TempoValidationTaskExecutor::new(Validator::default(), 2);
        let worker = tokio::spawn(task.run());
        let txs = (0..4)
            .map(|nonce| MockTransaction::legacy().with_nonce(nonce))
            .collect::<Vec<_>>();
        let hashes = txs.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let results = executor
            .validate_transactions_with_origin(TransactionOrigin::External, txs)
            .await;
        assert_eq!(
            results.iter().map(|out| out.tx_hash()).collect::<Vec<_>>(),
            hashes
        );
        for result in results {
            let TransactionValidationOutcome::Valid {
                balance,
                state_nonce,
                propagate,
                authorities,
                ..
            } = result
            else {
                panic!("unexpected validation outcome")
            };
            assert_eq!(balance, U256::from(123));
            assert_eq!(state_nonce, 7);
            assert!(propagate);
            assert_eq!(authorities, Some(vec![Address::ZERO]));
        }
        assert_eq!(executor.validator().batches.load(Ordering::Relaxed), 1);
        executor.on_new_head_block(&SealedBlock::seal_slow(Default::default()));
        assert_eq!(executor.validator().heads.load(Ordering::Relaxed), 1);
        drop(executor);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn closed_workers_return_errors_for_each_hash() {
        let (executor, task) = TempoValidationTaskExecutor::new(Validator::default(), 1);
        drop(task);
        let tx = MockTransaction::legacy();
        let hash = *tx.hash();
        let result = executor
            .validate_transaction(TransactionOrigin::External, tx.clone())
            .await;
        assert!(result.is_error());
        assert_eq!(result.tx_hash(), hash);
        let results = executor
            .validate_transactions_with_origin(TransactionOrigin::External, vec![tx])
            .await;
        assert_eq!(results.len(), 1);
        assert!(results[0].is_error());
        assert_eq!(results[0].tx_hash(), hash);
    }
}
