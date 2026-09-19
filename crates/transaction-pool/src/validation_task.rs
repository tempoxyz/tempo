//! Validation service that coalesces queued transaction validations into batches.
//!
//! [`TempoValidationTaskExecutor`] plays the same role as reth's
//! `TransactionValidationTaskExecutor`: callers hand validation jobs to a queue and a set of
//! worker tasks executes them off the async runtime. Unlike reth's executor, a worker that wakes
//! up also drains the jobs already waiting behind the one it received and validates all of their
//! transactions in one [`TransactionValidator::validate_transactions`] call. Concurrent
//! single-transaction submissions (`eth_sendRawTransaction`) therefore share one state provider
//! and one pool EVM instead of each building their own, and the queue is deep enough that
//! submitters rarely block on the hand-off to a worker.

use crate::{metrics::TempoValidationTaskMetrics, transaction::TempoPooledTransaction};
use reth_primitives_traits::SealedBlock;
use reth_tasks::Runtime;
use reth_transaction_pool::{
    PoolTransaction, TransactionOrigin, TransactionValidationOutcome, TransactionValidator,
    validate::TransactionValidatorError,
};
use std::{fmt, sync::Arc};
use tokio::sync::{Mutex, mpsc, oneshot};

/// Default capacity of the validation job queue.
///
/// Submissions only wait once this many jobs are queued ahead of them. Queued jobs are what
/// workers coalesce into batches, so the depth also determines how much batching is possible
/// under load.
pub const DEFAULT_VALIDATION_QUEUE_CAPACITY: usize = 1024;

/// Maximum number of transactions a worker validates in one batch.
///
/// Bounds the extra latency of the last transaction in a batch, which waits for the
/// transactions coalesced ahead of it to be validated by the same worker.
pub const MAX_VALIDATION_BATCH_SIZE: usize = 64;

type Outcome<T> = TransactionValidationOutcome<T>;

/// A unit of work submitted to the validation workers.
enum ValidationJob<T: PoolTransaction> {
    /// A single transaction with one waiting caller.
    Single {
        origin: TransactionOrigin,
        transaction: T,
        response: oneshot::Sender<Outcome<T>>,
    },
    /// A caller-provided batch whose outcomes are returned together.
    Batch {
        transactions: Vec<(TransactionOrigin, T)>,
        response: oneshot::Sender<Vec<Outcome<T>>>,
    },
}

impl<T: PoolTransaction> ValidationJob<T> {
    /// Number of transactions in this job.
    fn len(&self) -> usize {
        match self {
            Self::Single { .. } => 1,
            Self::Batch { transactions, .. } => transactions.len(),
        }
    }
}

/// Where the outcomes of a coalesced job are delivered.
enum ResponseSlot<T: PoolTransaction> {
    Single(oneshot::Sender<Outcome<T>>),
    Batch(usize, oneshot::Sender<Vec<Outcome<T>>>),
}

/// A worker that executes queued validation jobs.
///
/// Clones share one queue; each clone is driven by its own task via [`Self::run`].
///
/// `T` is the validator's transaction type; it is a separate parameter so the type can be named
/// without spelling out the validator's trait bounds.
pub struct TempoValidationTask<V, T: PoolTransaction = TempoPooledTransaction> {
    validator: Arc<V>,
    jobs: Arc<Mutex<mpsc::Receiver<ValidationJob<T>>>>,
    /// Number of workers sharing the queue, used to split queued work between them.
    workers: usize,
    metrics: TempoValidationTaskMetrics,
}

impl<V, T: PoolTransaction> Clone for TempoValidationTask<V, T> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
            jobs: self.jobs.clone(),
            workers: self.workers,
            metrics: self.metrics.clone(),
        }
    }
}

impl<V: fmt::Debug, T: PoolTransaction> fmt::Debug for TempoValidationTask<V, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempoValidationTask")
            .field("validator", &self.validator)
            .field("workers", &self.workers)
            .finish_non_exhaustive()
    }
}

impl<V, T> TempoValidationTask<V, T>
where
    V: TransactionValidator<Transaction = T> + 'static,
    T: PoolTransaction,
{
    /// Executes validation jobs until the queue is closed.
    ///
    /// Each iteration waits for the next job and then, without waiting any further, takes this
    /// worker's share of the jobs already queued behind it, validating all of them in one call.
    pub async fn run(self) {
        loop {
            let jobs = {
                // Hold the receiver only while dequeuing so other workers can pick up jobs while
                // this one validates.
                let mut queue = self.jobs.lock().await;
                let Some(first) = queue.recv().await else {
                    break;
                };
                self.drain(&mut queue, first)
            };
            self.validate(jobs).await;
        }
    }

    /// Takes up to this worker's share of the queued jobs behind `first`.
    fn drain(
        &self,
        queue: &mut mpsc::Receiver<ValidationJob<T>>,
        first: ValidationJob<T>,
    ) -> Vec<ValidationJob<T>> {
        let queued = queue.len();
        self.metrics.validation_queued_jobs.record(queued as f64);

        // Leave the other workers their share of the queue so a burst is still validated in
        // parallel instead of serially by whichever worker woke up first.
        let share = queued.div_ceil(self.workers);
        let mut transactions = first.len();
        let mut jobs = vec![first];
        while jobs.len() <= share && transactions < MAX_VALIDATION_BATCH_SIZE {
            let Ok(job) = queue.try_recv() else { break };
            transactions += job.len();
            jobs.push(job);
        }
        jobs
    }

    /// Validates the transactions of all `jobs` and delivers the outcomes to their callers.
    async fn validate(&self, mut jobs: Vec<ValidationJob<T>>) {
        let total = jobs.iter().map(ValidationJob::len).sum::<usize>();
        self.metrics.validation_batch_size.record(total as f64);

        if jobs.len() == 1 {
            // Nothing to coalesce: keep the shape of the caller's request.
            match jobs.pop().expect("one job") {
                ValidationJob::Single {
                    origin,
                    transaction,
                    response,
                } => {
                    let outcome = self
                        .validator
                        .validate_transaction(origin, transaction)
                        .await;
                    let _ = response.send(outcome);
                }
                ValidationJob::Batch {
                    transactions,
                    response,
                } => {
                    let outcomes = self.validator.validate_transactions(transactions).await;
                    let _ = response.send(outcomes);
                }
            }
            return;
        }

        let mut transactions = Vec::with_capacity(total);
        let mut responses = Vec::with_capacity(jobs.len());
        for job in jobs {
            match job {
                ValidationJob::Single {
                    origin,
                    transaction,
                    response,
                } => {
                    transactions.push((origin, transaction));
                    responses.push(ResponseSlot::Single(response));
                }
                ValidationJob::Batch {
                    transactions: batch,
                    response,
                } => {
                    responses.push(ResponseSlot::Batch(batch.len(), response));
                    transactions.extend(batch);
                }
            }
        }

        // Validators return one outcome per transaction in submission order. Should a validator
        // return fewer, the callers left without an outcome observe a dropped response and report
        // the validation service as unreachable.
        let mut outcomes = self
            .validator
            .validate_transactions(transactions)
            .await
            .into_iter();
        for response in responses {
            match response {
                ResponseSlot::Single(response) => {
                    if let Some(outcome) = outcomes.next() {
                        let _ = response.send(outcome);
                    }
                }
                ResponseSlot::Batch(len, response) => {
                    let _ = response.send(outcomes.by_ref().take(len).collect());
                }
            }
        }
    }
}

/// A [`TransactionValidator`] that runs validation on dedicated worker tasks and coalesces
/// concurrently submitted transactions into batches.
///
/// See the [module docs](self) for how batching works. `T` is the validator's transaction type;
/// it is a separate parameter so the type can be named without spelling out the validator's
/// trait bounds.
pub struct TempoValidationTaskExecutor<V, T: PoolTransaction = TempoPooledTransaction> {
    /// The validator executed by the worker tasks.
    validator: Arc<V>,
    /// Sender half of the job queue consumed by the workers.
    to_validation_task: mpsc::Sender<ValidationJob<T>>,
    metrics: TempoValidationTaskMetrics,
}

impl<V, T: PoolTransaction> Clone for TempoValidationTaskExecutor<V, T> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator.clone(),
            to_validation_task: self.to_validation_task.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<V: fmt::Debug, T: PoolTransaction> fmt::Debug for TempoValidationTaskExecutor<V, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempoValidationTaskExecutor")
            .field("validator", &self.validator)
            .finish_non_exhaustive()
    }
}

impl<V, T> TempoValidationTaskExecutor<V, T>
where
    V: TransactionValidator<Transaction = T> + 'static,
    T: PoolTransaction,
{
    /// Creates an executor and a single worker that the caller drives via
    /// [`TempoValidationTask::run`].
    pub fn new(validator: V) -> (Self, TempoValidationTask<V, T>) {
        Self::with_capacity(validator, DEFAULT_VALIDATION_QUEUE_CAPACITY, 1)
    }

    /// Creates an executor with a queue of the given capacity whose worker is going to be run by
    /// `workers` tasks.
    pub fn with_capacity(
        validator: V,
        capacity: usize,
        workers: usize,
    ) -> (Self, TempoValidationTask<V, T>) {
        let (to_validation_task, jobs) = mpsc::channel(capacity.max(1));
        let validator = Arc::new(validator);
        let metrics = TempoValidationTaskMetrics::default();
        let task = TempoValidationTask {
            validator: validator.clone(),
            jobs: Arc::new(Mutex::new(jobs)),
            workers: workers.max(1),
            metrics: metrics.clone(),
        };
        (
            Self {
                validator,
                to_validation_task,
                metrics,
            },
            task,
        )
    }

    /// Creates an executor and spawns its workers on the given runtime.
    ///
    /// Like reth's executor this spawns one critical blocking task for the validation service
    /// plus `additional_tasks` further blocking tasks.
    pub fn spawn(validator: V, tasks: &Runtime, additional_tasks: usize) -> Self {
        let (executor, task) = Self::with_capacity(
            validator,
            DEFAULT_VALIDATION_QUEUE_CAPACITY,
            additional_tasks + 1,
        );

        for _ in 0..additional_tasks {
            let task = task.clone();
            tasks.spawn_blocking_task(async move {
                task.run().await;
            });
        }

        tasks.spawn_critical_blocking_task("transaction-validation-service", async move {
            task.run().await;
        });

        executor
    }

    /// Returns the wrapped validator.
    pub fn validator(&self) -> &V {
        &self.validator
    }

    /// Queues a job for the workers.
    async fn submit(&self, job: ValidationJob<T>) -> Result<(), TransactionValidatorError> {
        self.metrics.inflight_validation_jobs.increment(1);
        let res = self
            .to_validation_task
            .send(job)
            .await
            .map_err(|_| TransactionValidatorError::ValidationServiceUnreachable);
        self.metrics.inflight_validation_jobs.decrement(1);
        res
    }
}

impl<V, T> TransactionValidator for TempoValidationTaskExecutor<V, T>
where
    V: TransactionValidator<Transaction = T> + 'static,
    T: PoolTransaction,
{
    type Transaction = T;
    type Block = V::Block;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        let hash = *transaction.hash();
        let (response, outcome) = oneshot::channel();
        let job = ValidationJob::Single {
            origin,
            transaction,
            response,
        };
        if self.submit(job).await.is_err() {
            return unreachable_outcome(hash);
        }
        outcome.await.unwrap_or_else(|_| unreachable_outcome(hash))
    }

    async fn validate_transactions(
        &self,
        transactions: impl IntoIterator<Item = (TransactionOrigin, Self::Transaction), IntoIter: Send>
        + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        let transactions = transactions.into_iter().collect::<Vec<_>>();
        if transactions.is_empty() {
            return Vec::new();
        }
        let hashes = transactions
            .iter()
            .map(|(_, tx)| *tx.hash())
            .collect::<Vec<_>>();
        let (response, outcomes) = oneshot::channel();
        let job = ValidationJob::Batch {
            transactions,
            response,
        };
        if self.submit(job).await.is_err() {
            return unreachable_outcomes(hashes);
        }
        outcomes
            .await
            .unwrap_or_else(|_| unreachable_outcomes(hashes))
    }

    async fn validate_transactions_with_origin(
        &self,
        origin: TransactionOrigin,
        transactions: impl IntoIterator<Item = Self::Transaction> + Send,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        // Collected up front: the caller's iterator is not required to be `Send`.
        let transactions = transactions
            .into_iter()
            .map(|tx| (origin, tx))
            .collect::<Vec<_>>();
        self.validate_transactions(transactions).await
    }

    fn on_new_head_block(&self, new_tip_block: &SealedBlock<Self::Block>) {
        self.validator.on_new_head_block(new_tip_block)
    }
}

fn unreachable_outcome<T: PoolTransaction>(hash: alloy_primitives::TxHash) -> Outcome<T> {
    TransactionValidationOutcome::Error(
        hash,
        Box::new(TransactionValidatorError::ValidationServiceUnreachable),
    )
}

fn unreachable_outcomes<T: PoolTransaction>(
    hashes: Vec<alloy_primitives::TxHash>,
) -> Vec<Outcome<T>> {
    hashes.into_iter().map(unreachable_outcome).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use parking_lot::Mutex as SyncMutex;
    use reth_transaction_pool::{test_utils::MockTransaction, validate::ValidTransaction};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Records how transactions reach the validator: one entry per batch call, and a count of
    /// single calls.
    #[derive(Debug, Default)]
    struct RecordingValidator {
        batches: SyncMutex<Vec<usize>>,
        singles: AtomicUsize,
    }

    fn valid(transaction: MockTransaction) -> Outcome<MockTransaction> {
        TransactionValidationOutcome::Valid {
            balance: U256::ZERO,
            state_nonce: 0,
            bytecode_hash: None,
            transaction: ValidTransaction::Valid(transaction),
            propagate: false,
            authorities: None,
        }
    }

    impl TransactionValidator for RecordingValidator {
        type Transaction = MockTransaction;
        type Block = reth_ethereum_primitives::Block;

        async fn validate_transaction(
            &self,
            _origin: TransactionOrigin,
            transaction: Self::Transaction,
        ) -> Outcome<Self::Transaction> {
            self.singles.fetch_add(1, Ordering::Relaxed);
            valid(transaction)
        }

        async fn validate_transactions(
            &self,
            transactions: impl IntoIterator<
                Item = (TransactionOrigin, Self::Transaction),
                IntoIter: Send,
            > + Send,
        ) -> Vec<Outcome<Self::Transaction>> {
            let transactions = transactions.into_iter().collect::<Vec<_>>();
            self.batches.lock().push(transactions.len());
            transactions
                .into_iter()
                .map(|(_, transaction)| valid(transaction))
                .collect()
        }
    }

    fn valid_hash(outcome: &Outcome<MockTransaction>) -> alloy_primitives::TxHash {
        match outcome {
            TransactionValidationOutcome::Valid { transaction, .. } => *transaction.hash(),
            other => panic!("expected valid outcome, got {other:?}"),
        }
    }

    /// Yields until `jobs` submissions have been queued.
    async fn wait_for_queued(
        executor: &TempoValidationTaskExecutor<RecordingValidator, MockTransaction>,
        jobs: usize,
    ) {
        let sender = &executor.to_validation_task;
        while sender.max_capacity() - sender.capacity() < jobs {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn coalesces_queued_single_submissions_into_one_batch() {
        let (executor, task) =
            TempoValidationTaskExecutor::with_capacity(RecordingValidator::default(), 64, 1);
        let executor = Arc::new(executor);

        let submissions = (0..8)
            .map(|_| {
                let executor = executor.clone();
                let transaction = MockTransaction::legacy();
                let hash = *transaction.hash();
                tokio::spawn(async move {
                    let outcome = executor
                        .validate_transaction(TransactionOrigin::External, transaction)
                        .await;
                    (hash, outcome)
                })
            })
            .collect::<Vec<_>>();
        wait_for_queued(&executor, 8).await;

        // The worker starts with all eight jobs already queued.
        tokio::spawn(task.run());
        for submission in submissions {
            let (hash, outcome) = submission.await.unwrap();
            assert_eq!(valid_hash(&outcome), hash);
        }

        let validator = executor.validator();
        assert_eq!(*validator.batches.lock(), vec![8]);
        assert_eq!(validator.singles.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn lone_submission_uses_single_validation() {
        let (executor, task) = TempoValidationTaskExecutor::new(RecordingValidator::default());
        tokio::spawn(task.run());

        let transaction = MockTransaction::eip1559();
        let hash = *transaction.hash();
        let outcome = executor
            .validate_transaction(TransactionOrigin::Local, transaction)
            .await;
        assert_eq!(valid_hash(&outcome), hash);

        let validator = executor.validator();
        assert_eq!(validator.singles.load(Ordering::Relaxed), 1);
        assert!(validator.batches.lock().is_empty());
    }

    #[tokio::test]
    async fn worker_leaves_other_workers_their_share_of_the_queue() {
        // Two workers are configured but only one runs, so it must take one job plus half of
        // the seven queued behind it (rounded up) and leave the rest for later iterations.
        let (executor, task) =
            TempoValidationTaskExecutor::with_capacity(RecordingValidator::default(), 64, 2);
        let executor = Arc::new(executor);

        let submissions = (0..8)
            .map(|_| {
                let executor = executor.clone();
                tokio::spawn(async move {
                    executor
                        .validate_transaction(
                            TransactionOrigin::External,
                            MockTransaction::legacy(),
                        )
                        .await
                })
            })
            .collect::<Vec<_>>();
        wait_for_queued(&executor, 8).await;

        tokio::spawn(task.run());
        for submission in submissions {
            valid_hash(&submission.await.unwrap());
        }

        let validator = executor.validator();
        let batches = validator.batches.lock().clone();
        assert_eq!(batches.first(), Some(&5), "batches: {batches:?}");
        assert_eq!(
            batches.iter().sum::<usize>() + validator.singles.load(Ordering::Relaxed),
            8
        );
    }

    #[tokio::test]
    async fn mixed_jobs_receive_their_own_outcomes_in_order() {
        let (executor, task) =
            TempoValidationTaskExecutor::with_capacity(RecordingValidator::default(), 64, 1);
        let executor = Arc::new(executor);

        let single_before = MockTransaction::legacy();
        let batch = vec![
            MockTransaction::eip1559(),
            MockTransaction::eip1559(),
            MockTransaction::legacy(),
        ];
        let single_after = MockTransaction::eip1559();
        let expected_batch_hashes = batch.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let expected_before = *single_before.hash();
        let expected_after = *single_after.hash();

        let before = {
            let executor = executor.clone();
            tokio::spawn(async move {
                executor
                    .validate_transaction(TransactionOrigin::External, single_before)
                    .await
            })
        };
        wait_for_queued(&executor, 1).await;
        let batch = {
            let executor = executor.clone();
            tokio::spawn(async move {
                executor
                    .validate_transactions_with_origin(TransactionOrigin::Private, batch)
                    .await
            })
        };
        wait_for_queued(&executor, 2).await;
        let after = {
            let executor = executor.clone();
            tokio::spawn(async move {
                executor
                    .validate_transaction(TransactionOrigin::Local, single_after)
                    .await
            })
        };
        wait_for_queued(&executor, 3).await;

        tokio::spawn(task.run());
        assert_eq!(valid_hash(&before.await.unwrap()), expected_before);
        let batch_outcomes = batch.await.unwrap();
        assert_eq!(
            batch_outcomes.iter().map(valid_hash).collect::<Vec<_>>(),
            expected_batch_hashes
        );
        assert_eq!(valid_hash(&after.await.unwrap()), expected_after);

        // All five transactions went through one coalesced batch call.
        assert_eq!(*executor.validator().batches.lock(), vec![5]);
    }

    #[tokio::test]
    async fn reports_unreachable_service_when_workers_are_gone() {
        let (executor, task) = TempoValidationTaskExecutor::new(RecordingValidator::default());
        drop(task);

        let transaction = MockTransaction::legacy();
        let hash = *transaction.hash();
        let outcome = executor
            .validate_transaction(TransactionOrigin::External, transaction)
            .await;
        assert!(
            matches!(outcome, TransactionValidationOutcome::Error(h, _) if h == hash),
            "got {outcome:?}"
        );

        let batch = vec![MockTransaction::legacy(), MockTransaction::eip1559()];
        let hashes = batch.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let outcomes = executor
            .validate_transactions_with_origin(TransactionOrigin::External, batch)
            .await;
        assert_eq!(outcomes.len(), 2);
        for (outcome, hash) in outcomes.iter().zip(hashes) {
            assert!(matches!(outcome, TransactionValidationOutcome::Error(h, _) if *h == hash));
        }
    }

    #[tokio::test]
    async fn empty_batch_returns_without_touching_the_queue() {
        let (executor, task) = TempoValidationTaskExecutor::new(RecordingValidator::default());
        drop(task);
        let outcomes = executor
            .validate_transactions(Vec::<(TransactionOrigin, MockTransaction)>::new())
            .await;
        assert!(outcomes.is_empty());
    }
}
