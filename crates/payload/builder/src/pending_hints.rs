use crate::{metrics::TempoPayloadBuilderMetrics, prewarming::prewarm_hint_for_pending_payment};
use alloy_primitives::TxHash;
use reth_chainspec::ChainSpecProvider;
use reth_storage_api::StateProviderFactory;
use reth_tasks::spawn_os_thread;
use reth_transaction_pool::{
    NewTransactionEvent, SubPool, TransactionListenerKind, TransactionPool,
};
use std::{
    collections::HashSet,
    fmt,
    sync::{
        Arc, Condvar, Mutex,
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
};
use tempo_chainspec::TempoChainSpec;
use tempo_transaction_pool::{TempoTransactionPool, best::BestTransaction};
use tracing::trace;

const PENDING_PAYMENT_PREWARM_HINT_WORKERS: usize = 2;
const PENDING_PAYMENT_PREWARM_HINT_QUEUE: usize = 256;

/// Background service that computes opportunistic prewarm hints for pending payment transactions.
#[derive(Clone)]
pub(crate) struct PendingPaymentPrewarmHints<Provider> {
    pool: TempoTransactionPool<Provider>,
    jobs_tx: SyncSender<BestTransaction>,
    state: Arc<PendingPaymentPrewarmHintState>,
    metrics: TempoPayloadBuilderMetrics,
}

impl<Provider> fmt::Debug for PendingPaymentPrewarmHints<Provider> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingPaymentPrewarmHints")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<Provider> PendingPaymentPrewarmHints<Provider>
where
    Provider: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Spawns the listener and worker threads.
    pub(crate) fn spawn(
        pool: TempoTransactionPool<Provider>,
        metrics: TempoPayloadBuilderMetrics,
    ) -> Self {
        let (jobs_tx, jobs_rx) = sync_channel(PENDING_PAYMENT_PREWARM_HINT_QUEUE);
        let jobs_rx = Arc::new(Mutex::new(jobs_rx));
        let state = Arc::new(PendingPaymentPrewarmHintState::default());

        for _ in 0..PENDING_PAYMENT_PREWARM_HINT_WORKERS {
            spawn_worker(jobs_rx.clone(), state.clone(), metrics.clone());
        }

        spawn_listener(
            pool.clone(),
            jobs_tx.clone(),
            state.clone(),
            metrics.clone(),
        );

        let this = Self {
            pool,
            jobs_tx,
            state,
            metrics,
        };
        this.scan_pending();
        this
    }

    /// Pauses new scheduling and waits for already active workers to finish.
    pub(crate) fn pause(&self) -> PendingPaymentPrewarmHintPauseGuard<Provider> {
        self.state.pause(&self.metrics);
        PendingPaymentPrewarmHintPauseGuard {
            service: self.clone(),
        }
    }

    fn resume(&self) {
        self.state.resume();
        self.scan_pending();
    }

    fn scan_pending(&self) {
        for tx in self.pool.pending_transactions() {
            self.schedule_transaction(tx);
        }
    }

    fn schedule_event(
        &self,
        event: NewTransactionEvent<tempo_transaction_pool::transaction::TempoPooledTransaction>,
    ) {
        let _ = schedule_new_transaction_event(event, &self.jobs_tx, &self.state, &self.metrics);
    }

    fn schedule_transaction(&self, tx: BestTransaction) {
        let _ = schedule_prewarm_hint_transaction(tx, &self.jobs_tx, &self.state, &self.metrics);
    }
}

/// RAII pause guard for pending prewarm hints.
pub(crate) struct PendingPaymentPrewarmHintPauseGuard<Provider>
where
    Provider: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + Clone
        + Send
        + Sync
        + 'static,
{
    service: PendingPaymentPrewarmHints<Provider>,
}

impl<Provider> Drop for PendingPaymentPrewarmHintPauseGuard<Provider>
where
    Provider: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + Clone
        + Send
        + Sync
        + 'static,
{
    fn drop(&mut self) {
        self.service.resume();
    }
}

#[derive(Debug, Default)]
struct PendingPaymentPrewarmHintState {
    inner: Mutex<PendingPaymentPrewarmHintStateInner>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct PendingPaymentPrewarmHintStateInner {
    paused: bool,
    active_workers: usize,
    in_flight: HashSet<TxHash>,
}

impl PendingPaymentPrewarmHintState {
    fn pause(&self, metrics: &TempoPayloadBuilderMetrics) {
        let mut inner = self
            .inner
            .lock()
            .expect("pending prewarm hint state poisoned");
        inner.paused = true;
        while inner.active_workers != 0 {
            inner = self
                .changed
                .wait(inner)
                .expect("pending prewarm hint state poisoned");
        }
        metrics.set_pending_prewarm_hint_active_workers(0);
    }

    fn resume(&self) {
        let mut inner = self
            .inner
            .lock()
            .expect("pending prewarm hint state poisoned");
        inner.paused = false;
        self.changed.notify_all();
    }

    fn try_mark_queued(&self, tx_hash: TxHash) -> Result<(), ScheduleSkip> {
        let mut inner = self
            .inner
            .lock()
            .expect("pending prewarm hint state poisoned");
        if inner.paused {
            return Err(ScheduleSkip::Paused);
        }
        if !inner.in_flight.insert(tx_hash) {
            return Err(ScheduleSkip::Duplicate);
        }
        Ok(())
    }

    fn wait_for_worker(&self, metrics: &TempoPayloadBuilderMetrics) -> ActiveWorkerGuard<'_> {
        let mut inner = self
            .inner
            .lock()
            .expect("pending prewarm hint state poisoned");
        while inner.paused {
            inner = self
                .changed
                .wait(inner)
                .expect("pending prewarm hint state poisoned");
        }
        inner.active_workers += 1;
        metrics.set_pending_prewarm_hint_active_workers(inner.active_workers);
        ActiveWorkerGuard {
            state: self,
            metrics: metrics.clone(),
        }
    }

    fn finish_job(&self, tx_hash: TxHash) {
        let mut inner = self
            .inner
            .lock()
            .expect("pending prewarm hint state poisoned");
        inner.in_flight.remove(&tx_hash);
    }
}

struct ActiveWorkerGuard<'a> {
    state: &'a PendingPaymentPrewarmHintState,
    metrics: TempoPayloadBuilderMetrics,
}

impl Drop for ActiveWorkerGuard<'_> {
    fn drop(&mut self) {
        let mut inner = self
            .state
            .inner
            .lock()
            .expect("pending prewarm hint state poisoned");
        inner.active_workers = inner.active_workers.saturating_sub(1);
        self.metrics
            .set_pending_prewarm_hint_active_workers(inner.active_workers);
        if inner.active_workers == 0 {
            self.state.changed.notify_all();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScheduleSkip {
    Paused,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScheduleOutcome {
    Queued,
    Skipped(&'static str),
    DroppedFullQueue,
    Disconnected,
}

fn schedule_new_transaction_event(
    event: NewTransactionEvent<tempo_transaction_pool::transaction::TempoPooledTransaction>,
    jobs_tx: &SyncSender<BestTransaction>,
    state: &PendingPaymentPrewarmHintState,
    metrics: &TempoPayloadBuilderMetrics,
) -> ScheduleOutcome {
    if event.subpool != SubPool::Pending {
        metrics.inc_pending_prewarm_hint_skipped("non_pending");
        return ScheduleOutcome::Skipped("non_pending");
    }

    schedule_prewarm_hint_transaction(event.transaction, jobs_tx, state, metrics)
}

fn schedule_prewarm_hint_transaction(
    tx: BestTransaction,
    jobs_tx: &SyncSender<BestTransaction>,
    state: &PendingPaymentPrewarmHintState,
    metrics: &TempoPayloadBuilderMetrics,
) -> ScheduleOutcome {
    if tx.transaction.prewarm_hint().is_some() {
        metrics.inc_pending_prewarm_hint_skipped("already_hinted");
        return ScheduleOutcome::Skipped("already_hinted");
    }

    if !tx.transaction.is_payment() {
        metrics.inc_pending_prewarm_hint_skipped("non_payment");
        return ScheduleOutcome::Skipped("non_payment");
    }

    let tx_hash = *tx.hash();
    match state.try_mark_queued(tx_hash) {
        Ok(()) => {}
        Err(ScheduleSkip::Paused) => {
            metrics.inc_pending_prewarm_hint_skipped("paused");
            return ScheduleOutcome::Skipped("paused");
        }
        Err(ScheduleSkip::Duplicate) => {
            metrics.inc_pending_prewarm_hint_skipped("duplicate");
            return ScheduleOutcome::Skipped("duplicate");
        }
    }

    match jobs_tx.try_send(tx) {
        Ok(()) => {
            metrics.inc_pending_prewarm_hint_queued();
            ScheduleOutcome::Queued
        }
        Err(TrySendError::Full(tx)) => {
            state.finish_job(*tx.hash());
            metrics.inc_pending_prewarm_hint_dropped_full_queue();
            ScheduleOutcome::DroppedFullQueue
        }
        Err(TrySendError::Disconnected(tx)) => {
            state.finish_job(*tx.hash());
            trace!(
                target: "payload_builder",
                tx_hash = ?tx.hash(),
                "pending prewarm hint worker queue disconnected"
            );
            ScheduleOutcome::Disconnected
        }
    }
}

fn spawn_listener<Provider>(
    pool: TempoTransactionPool<Provider>,
    jobs_tx: SyncSender<BestTransaction>,
    state: Arc<PendingPaymentPrewarmHintState>,
    metrics: TempoPayloadBuilderMetrics,
) where
    Provider: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + Clone
        + Send
        + Sync
        + 'static,
{
    spawn_os_thread("pending-prewarm-hint-listener", move || {
        let service = PendingPaymentPrewarmHints {
            pool: pool.clone(),
            jobs_tx,
            state,
            metrics,
        };
        let mut new_txs = pool.new_transactions_listener_for(TransactionListenerKind::All);
        while let Some(event) = new_txs.blocking_recv() {
            service.schedule_event(event);
        }
    });
}

fn spawn_worker(
    jobs_rx: Arc<Mutex<Receiver<BestTransaction>>>,
    state: Arc<PendingPaymentPrewarmHintState>,
    metrics: TempoPayloadBuilderMetrics,
) {
    spawn_os_thread("pending-prewarm-hint-worker", move || {
        loop {
            let tx = {
                let jobs_rx = jobs_rx
                    .lock()
                    .expect("pending prewarm hint worker queue poisoned");
                jobs_rx.recv()
            };
            let Ok(tx) = tx else {
                return;
            };

            let tx_hash = *tx.hash();
            let active_worker = state.wait_for_worker(&metrics);

            if tx.transaction.prewarm_hint().is_none()
                && let Some(hint) = prewarm_hint_for_pending_payment(&tx)
                && tx.transaction.set_prewarm_hint(hint)
            {
                metrics.inc_pending_prewarm_hint_computed();
            }

            drop(active_worker);
            state.finish_job(tx_hash);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use alloy_sol_types::SolCall;
    use reth_transaction_pool::{
        TransactionOrigin, ValidPoolTransaction, identifier::TransactionId,
    };
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };
    use tempo_precompiles::{DEFAULT_FEE_TOKEN, tip20::ITIP20};
    use tempo_primitives::TempoTxEnvelope;
    use tempo_transaction_pool::transaction::{PrewarmHint, PrewarmTouch, TempoPooledTransaction};

    fn payment_tx() -> BestTransaction {
        let tx = TxLegacy {
            chain_id: Some(42431),
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: TxKind::Call(DEFAULT_FEE_TOKEN),
            value: U256::ZERO,
            input: Bytes::from(
                ITIP20::transferCall {
                    to: Address::random(),
                    amount: U256::from(1),
                }
                .abi_encode(),
            ),
        };
        let envelope =
            TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()));
        let pooled = TempoPooledTransaction::new(reth_primitives_traits::Recovered::new_unchecked(
            envelope,
            Address::random(),
        ));
        Arc::new(ValidPoolTransaction {
            transaction_id: TransactionId::new(0u64.into(), 0),
            transaction: pooled,
            propagate: true,
            timestamp: Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    fn non_payment_tx() -> BestTransaction {
        let tx = TxLegacy {
            chain_id: Some(42431),
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope =
            TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()));
        let pooled = TempoPooledTransaction::new(reth_primitives_traits::Recovered::new_unchecked(
            envelope,
            Address::random(),
        ));
        Arc::new(ValidPoolTransaction {
            transaction_id: TransactionId::new(0u64.into(), 0),
            transaction: pooled,
            propagate: true,
            timestamp: Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    #[test]
    fn prewarm_hint_scheduling_filters_and_enqueues_pending_payments() {
        let (jobs_tx, jobs_rx) = sync_channel(1);
        let state = PendingPaymentPrewarmHintState::default();
        let metrics = TempoPayloadBuilderMetrics::default();

        let non_pending = NewTransactionEvent {
            subpool: SubPool::BaseFee,
            transaction: payment_tx(),
        };
        assert_eq!(
            schedule_new_transaction_event(non_pending, &jobs_tx, &state, &metrics),
            ScheduleOutcome::Skipped("non_pending")
        );
        assert!(jobs_rx.try_recv().is_err());

        assert_eq!(
            schedule_prewarm_hint_transaction(non_payment_tx(), &jobs_tx, &state, &metrics),
            ScheduleOutcome::Skipped("non_payment")
        );
        assert!(jobs_rx.try_recv().is_err());

        let hinted = payment_tx();
        assert!(hinted.transaction.set_prewarm_hint(PrewarmHint::new(vec![
            PrewarmTouch::Account(Address::random())
        ])));
        assert_eq!(
            schedule_prewarm_hint_transaction(hinted, &jobs_tx, &state, &metrics),
            ScheduleOutcome::Skipped("already_hinted")
        );
        assert!(jobs_rx.try_recv().is_err());

        let pending = payment_tx();
        let pending_hash = *pending.hash();
        assert_eq!(
            schedule_new_transaction_event(
                NewTransactionEvent::pending(pending),
                &jobs_tx,
                &state,
                &metrics
            ),
            ScheduleOutcome::Queued
        );
        assert_eq!(
            *jobs_rx.try_recv().expect("queued transaction").hash(),
            pending_hash
        );
    }

    #[test]
    fn prewarm_hint_state_rejects_duplicate_and_paused_work() {
        let state = PendingPaymentPrewarmHintState::default();
        let metrics = TempoPayloadBuilderMetrics::default();
        let tx_hash = *payment_tx().hash();

        assert_eq!(state.try_mark_queued(tx_hash), Ok(()));
        assert_eq!(state.try_mark_queued(tx_hash), Err(ScheduleSkip::Duplicate));

        state.finish_job(tx_hash);
        state.pause(&metrics);
        assert_eq!(state.try_mark_queued(tx_hash), Err(ScheduleSkip::Paused));
        state.resume();
        assert_eq!(state.try_mark_queued(tx_hash), Ok(()));
    }

    #[test]
    fn prewarm_hint_pause_waits_for_active_workers() {
        let state = Arc::new(PendingPaymentPrewarmHintState::default());
        let metrics = TempoPayloadBuilderMetrics::default();
        let active = state.wait_for_worker(&metrics);
        let paused = Arc::new(AtomicBool::new(false));

        let state_for_thread = state.clone();
        let paused_for_thread = paused.clone();
        let metrics_for_thread = metrics.clone();
        let handle = thread::spawn(move || {
            state_for_thread.pause(&metrics_for_thread);
            paused_for_thread.store(true, Ordering::Relaxed);
        });

        thread::sleep(Duration::from_millis(20));
        assert!(!paused.load(Ordering::Relaxed));

        drop(active);
        handle.join().unwrap();
        assert!(paused.load(Ordering::Relaxed));
    }
}
