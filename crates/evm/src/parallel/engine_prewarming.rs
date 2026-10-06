//! Bounded, advisory handoff from Engine prewarming to ordered execution.
//!
//! A hash locates a candidate; it never validates one. The recipient must still
//! check the complete transaction, environment, configuration and recorded reads.

use super::{EngineCaptureWindow, Env, PreexecutedTransaction, PrewarmingState, ReadValue};
use alloy_primitives::{B256, map::HashMap};
use std::{
    collections::BTreeMap,
    fmt,
    mem::size_of,
    sync::{
        Arc, Mutex, TryLockError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tempo_revm::{ExecutionContext, TempoTxEnv};

const MAX_TRANSACTIONS: usize = 65_536;
const MAX_ESTIMATED_BYTES: usize = 32 * 1024 * 1024;

// Allocated only for enabled diagnostic sessions. Padding separates distinct
// outcomes; relaxed counters are advisory and never control execution.
#[derive(Debug, Default)]
#[repr(align(64))]
struct CaptureCounter(AtomicU64);

macro_rules! capture_events {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Clone, Copy)]
        pub(crate) enum CaptureEvent { $($variant,)+ Count }
        const COUNTER_COUNT: usize = CaptureEvent::Count as usize;
        const COUNTER_NAMES: [&str; COUNTER_COUNT] = [$($name,)+];
    };
}

capture_events! {
    WorkerEntries => "worker_entries",
    WorkerFinished => "worker_finished",
    WorkerUnwound => "worker_unwound",
    GuardRejected => "guard_rejected",
    AdmissionSystem => "admission_system",
    AdmissionUnindexed => "admission_unindexed",
    AdmissionStale => "admission_stale",
    AdmissionFuture => "admission_future",
    Future128To255 => "future_128_255",
    Future256To511 => "future_256_511",
    Future512To1023 => "future_512_1023",
    Future1024Plus => "future_1024_plus",
    AdmissionInWindow => "admission_in_window",
    JournalRejected => "journal_rejected",
    StrictAttempts => "strict_attempts",
    StrictSucceeded => "strict_succeeded",
    StrictFailed => "strict_failed",
    PublishAttempts => "publish_attempts",
    PublishWrongEnv => "publish_wrong_env",
    PublishSystem => "publish_system",
    PublishUnindexed => "publish_unindexed",
    PublishStaleBefore => "publish_stale_before_lock",
    PublishFutureBefore => "publish_future_before_lock",
    PublishEstimateRejected => "publish_estimate_rejected",
    PublishContended => "publish_contended",
    PublishPoisoned => "publish_poisoned",
    PublishStaleAfter => "publish_stale_after_lock",
    PublishFutureAfter => "publish_future_after_lock",
    PublishDuplicate => "publish_duplicate",
    PublishCountLimit => "publish_count_limit",
    PublishOverflow => "publish_aggregate_overflow",
    PublishByteLimit => "publish_byte_limit",
    Published => "published",
    TakeUnindexed => "take_unindexed",
    Takes => "takes",
    TakeFound => "take_found",
    TakeMissing => "take_missing",
    TakePoisoned => "take_poisoned",
    Evicted => "evicted",
    PublishLateUnobserved => "publish_late_unobserved",
    PublishLateClockInvalid => "publish_late_clock_invalid",
    PublishLateUnder1us => "publish_late_under_1us",
    PublishLate1To2us => "publish_late_1_to_2us",
    PublishLate2To5us => "publish_late_2_to_5us",
    PublishLate5To10us => "publish_late_5_to_10us",
    PublishLate10To20us => "publish_late_10_to_20us",
    PublishLate20To50us => "publish_late_20_to_50us",
    PublishLate50To100us => "publish_late_50_to_100us",
    PublishLate100To250us => "publish_late_100_to_250us",
    PublishLateAtLeast250us => "publish_late_at_least_250us",
}

static NEXT_DIAGNOSTIC_SESSION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct CaptureDiagnostics {
    session_id: u64,
    payload_hash: B256,
    counters: [CaptureCounter; COUNTER_COUNT],
    started_at: Instant,
    // One timestamp per immutable transaction index, capped by MAX_TRANSACTIONS
    // (512 KiB). Zero means no observed first take; nonzero values are nanoseconds
    // since started_at plus one. Never consulted by scheduling or validation.
    take_started: Box<[AtomicU64]>,
}

impl CaptureDiagnostics {
    fn new(payload_hash: B256, transactions: usize) -> Self {
        Self {
            session_id: NEXT_DIAGNOSTIC_SESSION.fetch_add(1, Ordering::Relaxed),
            payload_hash,
            counters: std::array::from_fn(|_| CaptureCounter::default()),
            started_at: Instant::now(),
            take_started: (0..transactions).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    fn add(&self, event: CaptureEvent, value: u64) {
        self.counters[event as usize]
            .0
            .fetch_add(value, Ordering::Relaxed);
    }

    fn snapshot(&self) -> CaptureSnapshot {
        CaptureSnapshot(std::array::from_fn(|index| {
            self.counters[index].0.load(Ordering::Relaxed)
        }))
    }

    fn timestamp(&self, at: Instant) -> Option<u64> {
        u64::try_from(at.checked_duration_since(self.started_at)?.as_nanos())
            .ok()?
            .checked_add(1)
    }

    fn observe_take(&self, index: usize, at: Instant) {
        if let Some(started) = self.take_started.get(index) {
            started.store(self.timestamp(at).unwrap_or(0), Ordering::Release);
        }
    }

    fn observe_stale_publication(&self, index: usize, clock: impl FnOnce() -> Instant) {
        let started = self
            .take_started
            .get(index)
            .map_or(0, |value| value.load(Ordering::Acquire));
        let event = if started == 0 {
            // Includes publication between cursor advance and timestamp storage,
            // and indices skipped by a non-consecutive consumer. Do not invent a
            // zero-duration sample or infer a timestamp from another transaction.
            CaptureEvent::PublishLateUnobserved
        } else if let Some(elapsed) = self
            .timestamp(clock())
            .and_then(|at| at.checked_sub(started))
        {
            match elapsed {
                0..1_000 => CaptureEvent::PublishLateUnder1us,
                1_000..2_000 => CaptureEvent::PublishLate1To2us,
                2_000..5_000 => CaptureEvent::PublishLate2To5us,
                5_000..10_000 => CaptureEvent::PublishLate5To10us,
                10_000..20_000 => CaptureEvent::PublishLate10To20us,
                20_000..50_000 => CaptureEvent::PublishLate20To50us,
                50_000..100_000 => CaptureEvent::PublishLate50To100us,
                100_000..250_000 => CaptureEvent::PublishLate100To250us,
                _ => CaptureEvent::PublishLateAtLeast250us,
            }
        } else {
            CaptureEvent::PublishLateClockInvalid
        };
        self.add(event, 1);
    }
}

struct CaptureSnapshot([u64; COUNTER_COUNT]);

impl fmt::Debug for CaptureSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut fields = f.debug_struct("CaptureCounters");
        for (name, value) in COUNTER_NAMES.iter().zip(&self.0) {
            fields.field(name, value);
        }
        fields.finish()
    }
}

/// Tracks the capture hook, ending before any legacy relaxed fallback. It does
/// not measure Reth worker-job completion. Unwinding is explicit: outcome sums
/// need not close for an interrupted capture hook.
pub(crate) struct CaptureWorkerGuard<'a>(&'a CaptureDiagnostics);

impl Drop for CaptureWorkerGuard<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.add(CaptureEvent::WorkerUnwound, 1);
        }
        self.0.add(CaptureEvent::WorkerFinished, 1);
    }
}

/// Holds only the latest Engine session. Outstanding workers may finish an old
/// session, but cannot publish into its replacement.
#[derive(Clone, Debug, Default)]
pub(crate) struct EnginePrewarmingCache {
    current: Arc<Mutex<Option<Arc<EnginePrewarmingSession>>>>,
    capture_diagnostics: bool,
    window: EngineCaptureWindow,
}

impl EnginePrewarmingCache {
    pub(crate) fn new(capture_diagnostics: bool) -> Self {
        Self {
            capture_diagnostics,
            ..Self::default()
        }
    }

    pub(crate) fn with_window(mut self, window: EngineCaptureWindow) -> Self {
        self.window = window;
        self
    }

    /// Removes the lookup session for a payload that will not capture results.
    /// Existing worker handles remain isolated from future sessions.
    pub(crate) fn clear(&self) {
        if let Ok(mut current) = self.current.lock() {
            *current = None;
        }
    }

    /// Starts a new session. Invalid input clears the current session so that
    /// an earlier block with the same environment cannot supply its index map.
    pub(crate) fn begin_payload(
        &self,
        env: Env,
        payload_hash: B256,
        hashes: impl IntoIterator<Item = B256>,
    ) -> Option<Arc<EnginePrewarmingSession>> {
        let mut indices = HashMap::default();
        let mut valid = true;
        for hash in hashes {
            let index = indices.len();
            if index == MAX_TRANSACTIONS || indices.insert(hash, index).is_some() {
                valid = false;
                break;
            }
        }
        let session = valid.then(|| {
            let diagnostics = self
                .capture_diagnostics
                .then(|| Box::new(CaptureDiagnostics::new(payload_hash, indices.len())));
            Arc::new(EnginePrewarmingSession {
                env,
                window: self.window,
                indices,
                next: AtomicUsize::new(0),
                retained: Mutex::default(),
                prefix: PrewarmingState::default(),
                diagnostics,
            })
        });
        *self.current.lock().ok()? = session.clone();
        session
    }

    #[cfg(test)]
    pub(crate) fn begin(
        &self,
        env: Env,
        hashes: impl IntoIterator<Item = B256>,
    ) -> Option<Arc<EnginePrewarmingSession>> {
        self.begin_payload(env, B256::ZERO, hashes)
    }

    /// Finds only an exact canonical environment. The factory must normalize
    /// its explicitly authorized prewarming flags before this lookup.
    pub(crate) fn session(&self, env: &Env) -> Option<Arc<EnginePrewarmingSession>> {
        let current = self.current.lock().ok()?;
        current
            .as_ref()
            .filter(|session| session.env == *env)
            .cloned()
    }
}

/// A block's hash index, bounded completed results and accepted-prefix hints.
/// The prefix retains the block's published state footprint separately from the
/// completed-result byte estimate. Contains no provider or database reference.
#[derive(Debug)]
pub(crate) struct EnginePrewarmingSession {
    env: Env,
    window: EngineCaptureWindow,
    indices: HashMap<B256, usize>,
    next: AtomicUsize,
    retained: Mutex<Retained>,
    prefix: PrewarmingState,
    diagnostics: Option<Box<CaptureDiagnostics>>,
}

#[derive(Debug, Default)]
struct Retained {
    results: BTreeMap<usize, (Box<PreexecutedTransaction>, usize)>,
    estimated_bytes: usize,
}

impl Retained {
    fn take_through(
        &mut self,
        index: usize,
        previous: usize,
        is_system_tx: bool,
    ) -> Option<Box<PreexecutedTransaction>> {
        let mut result = None;
        while self
            .results
            .first_key_value()
            .is_some_and(|(&key, _)| key <= index)
        {
            let (key, (candidate, bytes)) = self.results.pop_first()?;
            self.estimated_bytes -= bytes;
            if key == index && index >= previous && !is_system_tx {
                result = Some(candidate);
            }
        }
        result
    }
}

impl EnginePrewarmingSession {
    #[inline]
    pub(crate) fn capture_event(&self, event: CaptureEvent) {
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.add(event, 1);
        }
    }

    pub(crate) fn worker_entry(&self) -> Option<CaptureWorkerGuard<'_>> {
        let diagnostics = self.diagnostics.as_deref()?;
        diagnostics.add(CaptureEvent::WorkerEntries, 1);
        Some(CaptureWorkerGuard(diagnostics))
    }

    /// Not an accepted-block or worker-completion barrier. Concurrent relaxed
    /// reads can span updates, so these totals must not be reconciled as final.
    pub(crate) fn log_loop_finish_snapshot(&self) {
        if let Some(diagnostics) = &self.diagnostics {
            self.log_snapshot(diagnostics, "loop_finish", false, None, None);
        }
    }

    fn log_snapshot(
        &self,
        diagnostics: &CaptureDiagnostics,
        phase: &'static str,
        final_counts: bool,
        retained_results: Option<usize>,
        retained_estimated_bytes: Option<usize>,
    ) {
        let counters = diagnostics.snapshot();
        let unfinished_worker_entries = counters.0[CaptureEvent::WorkerEntries as usize]
            .saturating_sub(counters.0[CaptureEvent::WorkerFinished as usize]);
        tracing::debug!(
            target: "tempo::execution",
            session_id = diagnostics.session_id,
            payload_hash = %diagnostics.payload_hash,
            block_number = %self.env.block_env.inner.number,
            transaction_count = self.indices.len(),
            capture_window = self.window.transactions(),
            cursor = self.next.load(Ordering::Relaxed),
            phase,
            final_counts,
            unfinished_worker_entries,
            ?retained_results,
            ?retained_estimated_bytes,
            ?counters,
            "Engine capture diagnostics"
        );
    }

    pub(crate) const fn env(&self) -> &Env {
        &self.env
    }

    pub(crate) fn prefix(&self) -> PrewarmingState {
        self.prefix.clone()
    }

    /// Called only for accepted state in the block executor's commit path.
    /// Never seed this prefix from a cache: Engine offsets remain relative to
    /// the worker's parent state. With no source offset, the nonce cursor stays
    /// absent and the recorder applies that original parent offset exactly once.
    pub(crate) fn record_commit(
        &self,
        state: &reth_revm::state::EvmState,
        is_expiring_nonce: bool,
    ) -> (Duration, Duration) {
        self.prefix.record_engine_timed(state, is_expiring_nonce)
    }

    fn index(&self, tx: &TempoTxEnv) -> Option<usize> {
        let ExecutionContext::Transaction { tx_hash } = tx.execution_context else {
            return None;
        };
        self.indices.get(&tx_hash).copied()
    }

    fn in_window(&self, index: usize, stale: CaptureEvent, future: CaptureEvent) -> bool {
        let next = self.next.load(Ordering::Acquire);
        if index < next {
            self.capture_event(stale);
            if let Some(diagnostics) = &self.diagnostics {
                // This is attempted publication, before or after the existing
                // retention checks. It is not proof of a recoverable candidate,
                // and does not measure CPU time or alter this fallback decision.
                // Load the published timestamp before reading the clock. Reading
                // the clock first could race a newer take timestamp and fabricate
                // a negative interval despite a valid monotonic clock.
                diagnostics.observe_stale_publication(index, Instant::now);
            }
            false
        } else if index >= next.saturating_add(self.window.transactions()) {
            self.capture_event(future);
            false
        } else {
            true
        }
    }

    /// Cheap admission only: publication checks the cursor again after work.
    pub(crate) fn can_capture(&self, tx: &TempoTxEnv) -> bool {
        if tx.is_system_tx {
            self.capture_event(CaptureEvent::AdmissionSystem);
            return false;
        }
        let Some(index) = self.index(tx) else {
            self.capture_event(CaptureEvent::AdmissionUnindexed);
            return false;
        };
        // Classify using the same single cursor read as the admission decision.
        let next = self.next.load(Ordering::Acquire);
        if index < next {
            self.capture_event(CaptureEvent::AdmissionStale);
            return false;
        }
        if index >= next.saturating_add(self.window.transactions()) {
            self.capture_event(CaptureEvent::AdmissionFuture);
            self.capture_event(match index - next {
                0..256 => CaptureEvent::Future128To255,
                256..512 => CaptureEvent::Future256To511,
                512..1024 => CaptureEvent::Future512To1023,
                _ => CaptureEvent::Future1024Plus,
            });
            return false;
        }
        self.capture_event(CaptureEvent::AdmissionInWindow);
        true
    }

    /// Keeps a completed strict result without waiting on the ordered executor.
    /// Contention, stale work, duplicate work and budget misses simply fall back.
    pub(crate) fn publish(&self, mut candidate: PreexecutedTransaction) -> bool {
        self.capture_event(CaptureEvent::PublishAttempts);
        if candidate.env != self.env {
            self.capture_event(CaptureEvent::PublishWrongEnv);
            return false;
        }
        if candidate.tx.is_system_tx {
            self.capture_event(CaptureEvent::PublishSystem);
            return false;
        }
        let Some(index) = self.index(&candidate.tx) else {
            self.capture_event(CaptureEvent::PublishUnindexed);
            return false;
        };
        if !self.in_window(
            index,
            CaptureEvent::PublishStaleBefore,
            CaptureEvent::PublishFutureBefore,
        ) {
            return false;
        }
        // Traverse owned data before taking the publication lock. Estimator
        // overflow and an individual result above the limit share this outcome.
        let Some(bytes) = candidate.estimated_retained_bytes() else {
            self.capture_event(CaptureEvent::PublishEstimateRejected);
            return false;
        };
        // Allocate before taking the lock so publication only moves a pointer.
        let candidate = Box::new(candidate);
        let mut retained = match self.retained.try_lock() {
            Ok(retained) => retained,
            Err(TryLockError::WouldBlock) => {
                self.capture_event(CaptureEvent::PublishContended);
                return false;
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                drop(poisoned);
                self.capture_event(CaptureEvent::PublishPoisoned);
                return false;
            }
        };
        if !self.in_window(
            index,
            CaptureEvent::PublishStaleAfter,
            CaptureEvent::PublishFutureAfter,
        ) {
            return false;
        }
        if retained.results.contains_key(&index) {
            drop(retained);
            self.capture_event(CaptureEvent::PublishDuplicate);
            return false;
        }
        if retained.results.len() >= self.window.transactions() {
            drop(retained);
            self.capture_event(CaptureEvent::PublishCountLimit);
            return false;
        }
        let Some(total) = retained.estimated_bytes.checked_add(bytes) else {
            drop(retained);
            self.capture_event(CaptureEvent::PublishOverflow);
            return false;
        };
        if total > MAX_ESTIMATED_BYTES {
            drop(retained);
            self.capture_event(CaptureEvent::PublishByteLimit);
            return false;
        }
        retained.results.insert(index, (candidate, bytes));
        retained.estimated_bytes = total;
        drop(retained);
        self.capture_event(CaptureEvent::Published);
        true
    }

    /// Advances even on a miss. Call for every canonical transaction, including
    /// transactions for which the ordinary scheduler already prepared a result.
    #[cfg(test)]
    pub(crate) fn take(&self, tx: &TempoTxEnv) -> Option<PreexecutedTransaction> {
        self.take_timed(tx).0
    }

    /// The same ordered take, with serial-consumer lock acquisition/hold wall time.
    /// Unindexed transactions acquire no lock and return no timing sample.
    pub(crate) fn take_timed(
        &self,
        tx: &TempoTxEnv,
    ) -> (Option<PreexecutedTransaction>, Option<(Duration, Duration)>) {
        let Some(index) = self.index(tx) else {
            self.capture_event(CaptureEvent::TakeUnindexed);
            return (None, None);
        };
        self.capture_event(CaptureEvent::Takes);
        let previous = self
            .next
            .fetch_max(index.saturating_add(1), Ordering::AcqRel);
        let waiting = Instant::now();
        if index >= previous
            && let Some(diagnostics) = &self.diagnostics
        {
            // Reuse the existing clock read. Repeated takes must not overwrite
            // the first timestamp; canonical progress and locking stay unchanged.
            diagnostics.observe_take(index, waiting);
        }
        // Poisoning still declines reuse. Drop the poisoned guard before returning
        // timings, preserving the original lock().ok()? behavior.
        let retained = self.retained.lock();
        let acquired = Instant::now();
        let (result, evicted, poisoned) = match retained {
            Ok(mut retained) => {
                let before = self.diagnostics.as_ref().map(|_| retained.results.len());
                let result = retained.take_through(index, previous, tx.is_system_tx);
                let evicted = before
                    .map(|before| before - retained.results.len() - usize::from(result.is_some()));
                (result, evicted, false)
            }
            Err(poisoned) => {
                drop(poisoned);
                (None, None, true)
            }
        };
        let held = acquired.elapsed();
        self.capture_event(if result.is_some() {
            CaptureEvent::TakeFound
        } else {
            CaptureEvent::TakeMissing
        });
        if poisoned {
            self.capture_event(CaptureEvent::TakePoisoned);
        }
        if let (Some(diagnostics), Some(evicted)) = (&self.diagnostics, evicted) {
            diagnostics.add(CaptureEvent::Evicted, evicted as u64);
        }
        // Move the payload and release its allocation after leaving the lock.
        let result = result.map(|candidate| *candidate);
        (result, Some((acquired.duration_since(waiting), held)))
    }
}

impl Drop for EnginePrewarmingSession {
    fn drop(&mut self) {
        if self.diagnostics.is_none() {
            return;
        }
        // Exclusive access: all session Arc owners are gone. Do not acquire a
        // mutex merely to report final retained totals, including poisoned data.
        let retained = self
            .retained
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        let (count, bytes) = (retained.results.len(), retained.estimated_bytes);
        if let Some(diagnostics) = &self.diagnostics {
            // This can be delayed until cache replacement/shutdown. Process exit
            // may omit the final retained session; it is not worker-finish time.
            self.log_snapshot(diagnostics, "session_drop", true, Some(count), Some(bytes));
        }
    }
}

impl PreexecutedTransaction {
    /// Checked estimate for retaining this completed result, returning `None`
    /// above 32 MiB or on overflow. This is not an allocator or process RSS bound.
    /// Shared code is charged per occurrence; hidden backing capacity, running
    /// worker state and committed-prefix hints are outside the estimate.
    /// The mutable receiver only exposes log-topic capacity; no values change.
    pub fn estimated_retained_bytes(&mut self) -> Option<usize> {
        estimated_bytes(self)
    }
}

/// Checked estimate of retained payload, not an allocator/RSS bound: Bytes and
/// bytecode jump tables can retain backing capacity their APIs do not expose.
/// Charge every occurrence of shared code, all exposed container capacities,
/// original account metadata and generous map/allocation overhead. Entries and
/// hash counts are hard bounded independently of this estimate.
fn estimated_bytes(candidate: &mut PreexecutedTransaction) -> Option<usize> {
    use reth_revm::context::result::ExecutionResult;
    let mut budget = ByteBudget(0);
    // Includes the outer result allocation, BTreeMap node allowance and the
    // environment's shared 256-word gas table, counted afresh for each candidate.
    budget.add(size_of::<PreexecutedTransaction>().checked_add(4096)?)?;
    budget.transaction(&candidate.tx)?;
    budget.vector(&candidate.reads)?;
    for (_, value) in &candidate.reads {
        match value {
            ReadValue::Account(Some(info)) => budget.account_info(info)?,
            ReadValue::Code(code) => budget.code(code)?,
            ReadValue::Account(None) | ReadValue::Storage(_) | ReadValue::BlockHash(_) => {}
        }
    }
    budget.map::<alloy_primitives::Address, reth_revm::state::Account>(
        candidate.result.state.capacity(),
    )?;
    for account in candidate.result.state.values() {
        budget.account_info(&account.info)?;
        // This API clones only inline metadata and shared code. Charge the box
        // even when no original account info was allocated (a deliberate overcount).
        budget.add(size_of::<reth_revm::state::AccountInfo>() + 64)?;
        budget.account_info(&account.original_info())?;
        budget.map::<alloy_primitives::U256, reth_revm::state::EvmStorageSlot>(
            account.storage.capacity(),
        )?;
    }
    let (logs, output) = match &mut candidate.result.result {
        ExecutionResult::Success { logs, output, .. } => (logs, Some(output.data())),
        ExecutionResult::Revert { logs, output, .. } => (logs, Some(&*output)),
        ExecutionResult::Halt { logs, reason, .. } => {
            budget.halt_reason(reason)?;
            (logs, None)
        }
    };
    budget.vector(logs)?;
    for log in logs {
        // This accessor exposes the allocation capacity; no topics are changed.
        budget.vector(log.data.topics_mut_unchecked())?;
        budget.bytes(log.data.data.len())?;
    }
    if let Some(output) = output {
        budget.bytes(output.len())?;
    }
    budget.vector(&candidate.fee_updates)?;
    for update in &candidate.fee_updates {
        budget.add(update.estimated_heap_size().checked_add(64)?)?;
    }
    Some(budget.0)
}

struct ByteBudget(usize);

impl ByteBudget {
    fn add(&mut self, bytes: usize) -> Option<()> {
        self.0 = self.0.checked_add(bytes)?;
        (self.0 <= MAX_ESTIMATED_BYTES).then_some(())
    }

    fn bytes(&mut self, len: usize) -> Option<()> {
        self.add(len.checked_add(64)?)
    }

    fn vector<T>(&mut self, values: &Vec<T>) -> Option<()> {
        self.add(
            values
                .capacity()
                .checked_mul(size_of::<T>())?
                .checked_add(64)?,
        )
    }

    fn map<K, V>(&mut self, capacity: usize) -> Option<()> {
        // Covers the table's load factor, control bytes and allocation headers.
        self.add(
            capacity
                .checked_mul(size_of::<(K, V)>().checked_add(1)?)?
                .checked_mul(2)?
                .checked_add(128)?,
        )
    }

    fn code(&mut self, code: &reth_revm::state::Bytecode) -> Option<()> {
        self.add(256)?;
        self.bytes(code.bytes_slice().len())?;
        if let Some(table) = code.legacy_jump_table() {
            self.bytes(table.as_slice().len())?;
        }
        Some(())
    }

    fn account_info(&mut self, info: &reth_revm::state::AccountInfo) -> Option<()> {
        // Exhaustive destructuring forces review if this dependency gains an
        // account extension or another owned field.
        let reth_revm::state::AccountInfo {
            balance: _,
            nonce: _,
            code_hash: _,
            account_id: _,
            code,
        } = info;
        if let Some(code) = code {
            self.code(code)?;
        }
        Some(())
    }

    fn signature(&mut self, signature: &tempo_primitives::TempoSignature) -> Option<()> {
        use tempo_primitives::TempoSignature;
        match signature {
            TempoSignature::Primitive(signature) => self.primitive_signature(signature),
            TempoSignature::Keychain(signature) => self.primitive_signature(&signature.signature),
        }
    }

    fn primitive_signature(
        &mut self,
        signature: &tempo_primitives::transaction::PrimitiveSignature,
    ) -> Option<()> {
        use tempo_primitives::transaction::PrimitiveSignature;
        match signature {
            PrimitiveSignature::Secp256k1(_) | PrimitiveSignature::P256(_) => Some(()),
            PrimitiveSignature::WebAuthn(signature) => self.bytes(signature.webauthn_data.len()),
        }
    }

    fn halt_reason(&mut self, reason: &reth_revm::context::result::HaltReason) -> Option<()> {
        use reth_revm::context::result::HaltReason;
        match reason {
            HaltReason::PrecompileErrorWithContext(message) => self.bytes(message.capacity()),
            HaltReason::OutOfGas(_)
            | HaltReason::OpcodeNotFound
            | HaltReason::InvalidFEOpcode
            | HaltReason::InvalidJump
            | HaltReason::NotActivated
            | HaltReason::StackUnderflow
            | HaltReason::StackOverflow
            | HaltReason::OutOfOffset
            | HaltReason::CreateCollision
            | HaltReason::PrecompileError
            | HaltReason::NonceOverflow
            | HaltReason::CreateContractSizeLimit
            | HaltReason::CreateContractStartingWithEF
            | HaltReason::CreateInitCodeSizeLimit
            | HaltReason::OverflowPayment
            | HaltReason::StateChangeDuringStaticCall
            | HaltReason::CallNotAllowedInsideStatic
            | HaltReason::OutOfFunds
            | HaltReason::CallTooDeep => Some(()),
        }
    }

    fn transaction(&mut self, tx: &TempoTxEnv) -> Option<()> {
        self.bytes(tx.inner.data.len())?;
        self.vector(&tx.inner.access_list.0)?;
        for item in &tx.inner.access_list.0 {
            self.vector(&item.storage_keys)?;
        }
        self.vector(&tx.inner.blob_hashes)?;
        // Ethereum authorizations contain only inline values.
        self.vector(&tx.inner.authorization_list)?;
        if let Some(aa) = &tx.tempo_tx_env {
            self.add(size_of::<tempo_revm::TempoBatchCallEnv>() + 64)?;
            self.signature(&aa.signature)?;
            self.vector(&aa.aa_calls)?;
            for call in &aa.aa_calls {
                self.bytes(call.input.len())?;
            }
            self.vector(&aa.tempo_authorization_list)?;
            for authorization in &aa.tempo_authorization_list {
                self.signature(authorization.signature())?;
            }
            if let Some(key) = &aa.key_authorization {
                self.primitive_signature(&key.signature)?;
                if let Some(limits) = &key.authorization.limits {
                    self.vector(limits)?;
                }
                if let Some(scopes) = &key.authorization.allowed_calls {
                    self.vector(scopes)?;
                    for scope in scopes {
                        self.vector(&scope.selector_rules)?;
                        for selector in &scope.selector_rules {
                            self.vector(&selector.recipients)?;
                        }
                    }
                }
            }
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parallel::PrewarmingExecutor;
    use alloy_evm::Evm;
    use alloy_primitives::{Address, Bytes, TxKind};
    use revm::{context::TxEnv, database::EmptyDB};

    const LOOKAHEAD: usize = EngineCaptureWindow::Transactions128.transactions();

    fn hash(index: usize) -> B256 {
        B256::from(alloy_primitives::U256::from(index).to_be_bytes::<32>())
    }

    fn tx(index: usize) -> TempoTxEnv {
        TempoTxEnv {
            inner: TxEnv {
                caller: Address::with_last_byte(201),
                kind: TxKind::Call(Address::with_last_byte(202)),
                gas_limit: 1_000_000,
                ..Default::default()
            },
            execution_context: ExecutionContext::Transaction {
                tx_hash: hash(index),
            },
            ..Default::default()
        }
    }

    fn env() -> Env {
        crate::test_utils::test_evm_with_basefee(EmptyDB::default(), 0)
            .finish()
            .1
    }

    fn candidate(index: usize) -> PreexecutedTransaction {
        PrewarmingExecutor::new(EmptyDB::default(), env())
            .execute(tx(index), None)
            .unwrap()
    }

    fn diagnostic_session(count: usize) -> Arc<EnginePrewarmingSession> {
        EnginePrewarmingCache::new(true)
            .begin_payload(env(), hash(9999), (0..count).map(hash))
            .unwrap()
    }

    fn counts(session: &EnginePrewarmingSession) -> impl Fn(CaptureEvent) -> u64 + use<> {
        let snapshot = session.diagnostics.as_ref().unwrap().snapshot();
        move |event| snapshot.0[event as usize]
    }

    #[test]
    fn selected_windows_enforce_admission_count_and_byte_limits() {
        assert_eq!(EnginePrewarmingCache::default().window.transactions(), 128);
        for window in [
            EngineCaptureWindow::Transactions128,
            EngineCaptureWindow::Transactions256,
            EngineCaptureWindow::Transactions512,
        ] {
            let limit = window.transactions();
            let cache = EnginePrewarmingCache::new(true).with_window(window);
            let session = cache.begin(env(), (0..=limit).map(hash)).unwrap();
            assert!(session.can_capture(&tx(limit - 1)));
            assert!(!session.can_capture(&tx(limit)));
            assert!(!session.publish(candidate(limit)));
            for index in 0..limit {
                assert!(session.publish(candidate(index)));
            }
            // The cursor may advance before take obtains the retention lock.
            session.next.store(1, Ordering::Release);
            assert!(!session.can_capture(&tx(0)));
            assert!(session.can_capture(&tx(limit)));
            assert!(!session.publish(candidate(limit)));
            assert_eq!(counts(&session)(CaptureEvent::PublishCountLimit), 1);
            assert!(session.take(&tx(limit - 1)).is_some());
            assert!(session.publish(candidate(limit)));
            assert!(session.take(&tx(limit)).is_some());
            let retained = session.retained.lock().unwrap();
            assert!(retained.results.is_empty());
            assert_eq!(retained.estimated_bytes, 0);
            drop(retained);

            let session = cache.begin(env(), [hash(0), hash(1)]).unwrap();
            for index in 0..2 {
                let mut large = candidate(index);
                large.tx.inner.data = Bytes::from(vec![0; MAX_ESTIMATED_BYTES / 2]);
                assert_eq!(session.publish(large), index == 0);
            }
            assert_eq!(counts(&session)(CaptureEvent::PublishByteLimit), 1);
            assert!(session.take(&tx(0)).is_some());
            assert!(session.publish(candidate(1)));
        }
    }

    #[test]
    fn replacement_sessions_keep_their_selected_window() {
        let cache =
            EnginePrewarmingCache::default().with_window(EngineCaptureWindow::Transactions256);
        let old = cache.begin(env(), (0..1024).map(hash)).unwrap();
        let cache = cache.with_window(EngineCaptureWindow::Transactions512);
        let new = cache.begin(env(), (0..1024).map(hash)).unwrap();
        assert!(!old.can_capture(&tx(256)));
        assert!(new.can_capture(&tx(256)));
        assert!(old.publish(candidate(255)));
        assert!(new.take(&tx(255)).is_none());
        assert!(old.take(&tx(255)).is_some());
        assert!(Arc::ptr_eq(&cache.session(&env()).unwrap(), &new));
    }

    #[test]
    fn enlarged_windows_keep_absolute_future_distance_buckets() {
        for (window, expected) in [
            (EngineCaptureWindow::Transactions256, [0, 2, 2, 2]),
            (EngineCaptureWindow::Transactions512, [0, 0, 2, 2]),
        ] {
            let session = EnginePrewarmingCache::new(true)
                .with_window(window)
                .begin(env(), (0..2048).map(hash))
                .unwrap();
            for index in [128, 255, 256, 511, 512, 1023, 1024, 2047] {
                assert_eq!(
                    session.can_capture(&tx(index)),
                    index < window.transactions()
                );
            }
            let count = counts(&session);
            for (bucket, expected) in [
                CaptureEvent::Future128To255,
                CaptureEvent::Future256To511,
                CaptureEvent::Future512To1023,
                CaptureEvent::Future1024Plus,
            ]
            .into_iter()
            .zip(expected)
            {
                assert_eq!(count(bucket), expected);
            }
            assert_eq!(
                count(CaptureEvent::AdmissionFuture),
                expected.iter().sum::<u64>()
            );
            assert_eq!(
                count(CaptureEvent::AdmissionInWindow),
                8 - expected.iter().sum::<u64>()
            );
        }
    }

    #[test]
    fn diagnostics_default_off_and_classify_one_admission_read() {
        let ordinary = EnginePrewarmingCache::default()
            .begin(env(), [hash(0)])
            .unwrap();
        assert!(ordinary.diagnostics.is_none());
        assert!(ordinary.worker_entry().is_none());
        assert!(ordinary.can_capture(&tx(0)));
        assert!(ordinary.publish(candidate(0)));
        assert!(ordinary.take(&tx(0)).is_some());

        let session = diagnostic_session(2048);
        assert!(session.can_capture(&tx(127)));
        for index in [128, 255, 256, 511, 512, 1023, 1024, 2047] {
            assert!(!session.can_capture(&tx(index)));
        }
        assert!(session.take(&tx(0)).is_none());
        assert!(!session.can_capture(&tx(0)));
        assert!(session.can_capture(&tx(128)));
        let mut system = tx(1);
        system.is_system_tx = true;
        assert!(!session.can_capture(&system));
        assert!(!session.can_capture(&tx(2048)));
        assert!(session.take(&tx(2048)).is_none());
        let count = counts(&session);
        assert_eq!(count(CaptureEvent::AdmissionInWindow), 2);
        assert_eq!(count(CaptureEvent::AdmissionStale), 1);
        assert_eq!(count(CaptureEvent::AdmissionFuture), 8);
        for bucket in [
            CaptureEvent::Future128To255,
            CaptureEvent::Future256To511,
            CaptureEvent::Future512To1023,
            CaptureEvent::Future1024Plus,
        ] {
            assert_eq!(count(bucket), 2);
        }
        assert_eq!(count(CaptureEvent::AdmissionSystem), 1);
        assert_eq!(count(CaptureEvent::AdmissionUnindexed), 1);
        assert_eq!(count(CaptureEvent::Takes), 1);
        assert_eq!(count(CaptureEvent::TakeMissing), 1);
        assert_eq!(count(CaptureEvent::TakeUnindexed), 1);
    }

    #[test]
    fn diagnostic_publication_terminal_reasons_and_evictions_reconcile() {
        let session = diagnostic_session(129);
        let mut changed = candidate(0);
        changed.env.block_env.inner.basefee += 1;
        assert!(!session.publish(changed));
        let mut system = candidate(0);
        system.tx.is_system_tx = true;
        assert!(!session.publish(system));
        assert!(!session.publish(candidate(129)));
        assert!(!session.publish(candidate(128)));
        let mut oversized = candidate(0);
        oversized.tx.inner.data = Bytes::from(vec![0; MAX_ESTIMATED_BYTES]);
        assert!(!session.publish(oversized));
        {
            let _guard = session.retained.lock().unwrap();
            assert!(!session.publish(candidate(0)));
        }
        assert!(session.publish(candidate(0)));
        assert!(!session.publish(candidate(0)));
        assert!(session.publish(candidate(1)));
        assert!(session.take(&tx(1)).is_some()); // Evicts the unconsumed zero.
        assert!(!session.publish(candidate(0)));
        assert!(session.take(&tx(1)).is_none()); // Duplicate take.
        assert!(session.take(&tx(0)).is_none()); // Stale take cannot rewind the cursor.
        assert!(session.take(&tx(2)).is_none());
        let count = counts(&session);
        for event in [
            CaptureEvent::PublishWrongEnv,
            CaptureEvent::PublishSystem,
            CaptureEvent::PublishUnindexed,
            CaptureEvent::PublishFutureBefore,
            CaptureEvent::PublishEstimateRejected,
            CaptureEvent::PublishContended,
            CaptureEvent::PublishDuplicate,
            CaptureEvent::PublishStaleBefore,
        ] {
            assert_eq!(count(event), 1);
        }
        assert_eq!(count(CaptureEvent::PublishAttempts), 10);
        assert_eq!(count(CaptureEvent::Published), 2);
        assert_eq!(count(CaptureEvent::Takes), 4);
        assert_eq!(count(CaptureEvent::TakeFound), 1);
        assert_eq!(count(CaptureEvent::TakeMissing), 3);
        assert_eq!(count(CaptureEvent::Evicted), 1);
        assert_eq!(
            count(CaptureEvent::Published),
            count(CaptureEvent::TakeFound) + count(CaptureEvent::Evicted)
        );
    }

    #[test]
    fn publication_arrival_buckets_preserve_boundaries_and_unknowns() {
        let diagnostics = CaptureDiagnostics::new(B256::ZERO, 1);
        let origin = diagnostics.started_at;
        diagnostics.observe_stale_publication(0, || origin);
        diagnostics.observe_stale_publication(1, || origin);
        assert_eq!(
            diagnostics.snapshot().0[CaptureEvent::PublishLateUnobserved as usize],
            2
        );
        // Zero elapsed is a valid sample, distinct from an absent timestamp.
        diagnostics.observe_take(0, origin);
        for (nanos, event) in [
            (0, CaptureEvent::PublishLateUnder1us),
            (999, CaptureEvent::PublishLateUnder1us),
            (1_000, CaptureEvent::PublishLate1To2us),
            (1_999, CaptureEvent::PublishLate1To2us),
            (2_000, CaptureEvent::PublishLate2To5us),
            (4_999, CaptureEvent::PublishLate2To5us),
            (5_000, CaptureEvent::PublishLate5To10us),
            (9_999, CaptureEvent::PublishLate5To10us),
            (10_000, CaptureEvent::PublishLate10To20us),
            (19_999, CaptureEvent::PublishLate10To20us),
            (20_000, CaptureEvent::PublishLate20To50us),
            (49_999, CaptureEvent::PublishLate20To50us),
            (50_000, CaptureEvent::PublishLate50To100us),
            (99_999, CaptureEvent::PublishLate50To100us),
            (100_000, CaptureEvent::PublishLate100To250us),
            (249_999, CaptureEvent::PublishLate100To250us),
            (250_000, CaptureEvent::PublishLateAtLeast250us),
            (1_000_000, CaptureEvent::PublishLateAtLeast250us),
        ] {
            let before = diagnostics.snapshot().0;
            diagnostics.observe_stale_publication(0, || origin + Duration::from_nanos(nanos));
            let after = diagnostics.snapshot().0;
            for index in 0..COUNTER_COUNT {
                assert_eq!(
                    after[index] - before[index],
                    u64::from(index == event as usize)
                );
            }
        }
        diagnostics.observe_take(0, origin + Duration::from_nanos(1));
        diagnostics.observe_stale_publication(0, || origin);
        assert_eq!(
            diagnostics.snapshot().0[CaptureEvent::PublishLateClockInvalid as usize],
            1
        );
    }

    #[test]
    fn publication_arrival_is_session_scoped_and_concurrent() {
        let diagnostics = CaptureDiagnostics::new(B256::ZERO, 2);
        let separate = CaptureDiagnostics::new(B256::ZERO, 2);
        let at = diagnostics.started_at;
        diagnostics.observe_take(1, at);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..100 {
                        diagnostics.observe_stale_publication(1, || at + Duration::from_nanos(500));
                    }
                });
            }
        });
        assert_eq!(diagnostics.snapshot().0.iter().sum::<u64>(), 800);
        assert_eq!(
            diagnostics.snapshot().0[CaptureEvent::PublishLateUnder1us as usize],
            800
        );
        assert_eq!(separate.snapshot().0.iter().sum::<u64>(), 0);
        assert_eq!(separate.take_started[1].load(Ordering::Acquire), 0);
    }

    #[test]
    fn publication_arrival_keeps_first_take_and_unchanged_stale_fallback() {
        for enabled in [false, true] {
            let cache = EnginePrewarmingCache::new(enabled);
            let session = cache.begin(env(), [hash(0), hash(1)]).unwrap();
            assert_eq!(session.diagnostics.is_some(), enabled);
            assert!(session.take(&tx(0)).is_none());
            let first = session
                .diagnostics
                .as_ref()
                .map(|d| d.take_started[0].load(Ordering::Acquire));
            assert!(session.take(&tx(0)).is_none());
            if let Some(diagnostics) = &session.diagnostics {
                assert_ne!(first, Some(0));
                assert_eq!(
                    Some(diagnostics.take_started[0].load(Ordering::Acquire)),
                    first
                );
            }
            assert!(!session.publish(candidate(0)));
            assert!(session.publish(candidate(1)));
            assert!(session.take(&tx(1)).is_some());
            if enabled {
                let count = counts(&session);
                assert_eq!(count(CaptureEvent::PublishStaleBefore), 1);
                assert_eq!(count(CaptureEvent::Published), 1);
                assert_eq!(count(CaptureEvent::TakeFound), 1);
                assert_eq!(count(CaptureEvent::TakeMissing), 2);
                let snapshot = session.diagnostics.as_ref().unwrap().snapshot();
                let late = &snapshot.0[CaptureEvent::PublishLateUnobserved as usize..];
                assert_eq!(late.iter().sum::<u64>(), 1);
                assert_eq!(count(CaptureEvent::PublishLateClockInvalid), 0);
                assert_eq!(count(CaptureEvent::PublishLateUnobserved), 0);
            }
        }
    }

    #[test]
    fn diagnostic_count_and_byte_limits_keep_original_fallbacks() {
        let session = diagnostic_session(129);
        for index in 0..LOOKAHEAD {
            assert!(session.publish(candidate(index)));
        }
        // Model the existing gap between take's cursor advance and lock acquisition.
        session.next.store(1, Ordering::Release);
        assert!(!session.publish(candidate(128)));
        assert_eq!(counts(&session)(CaptureEvent::PublishCountLimit), 1);
        assert!(session.take(&tx(128)).is_none());
        assert_eq!(counts(&session)(CaptureEvent::Evicted), LOOKAHEAD as u64);

        let session = diagnostic_session(2);
        for index in 0..2 {
            let mut large = candidate(index);
            large.tx.inner.data = Bytes::from(vec![0; MAX_ESTIMATED_BYTES / 2]);
            assert_eq!(session.publish(large), index == 0);
        }
        assert_eq!(counts(&session)(CaptureEvent::Published), 1);
        assert_eq!(counts(&session)(CaptureEvent::PublishByteLimit), 1);
        assert!(session.take(&tx(0)).is_some());
        assert!(session.publish(candidate(1)));
    }

    #[derive(Clone, Default)]
    struct SnapshotLog(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

    impl tracing::Subscriber for SnapshotLog {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.fields().field("session_id").is_some()
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            #[derive(Default)]
            struct Fields(BTreeMap<String, String>);
            impl tracing::field::Visit for Fields {
                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
                    self.0
                        .insert(field.name().to_string(), format!("{value:?}"));
                }
            }
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
    }

    #[test]
    fn diagnostic_snapshots_distinguish_concurrent_finish_and_final_session_drop() {
        let captured = SnapshotLog::default();
        let _subscriber = tracing::subscriber::set_default(captured.clone());
        let cache =
            EnginePrewarmingCache::new(true).with_window(EngineCaptureWindow::Transactions512);
        let payload = hash(9999);
        let old = cache.begin_payload(env(), payload, [hash(0)]).unwrap();
        let old_id = old.diagnostics.as_ref().unwrap().session_id;
        let worker = old.worker_entry().unwrap();
        old.log_loop_finish_snapshot();
        let new = cache.begin_payload(env(), payload, [hash(0)]).unwrap();
        assert_ne!(old_id, new.diagnostics.as_ref().unwrap().session_id);
        assert_eq!(counts(&new)(CaptureEvent::WorkerEntries), 0);
        assert!(old.publish(candidate(0)));
        assert!(new.take(&tx(0)).is_none());
        drop(worker);
        // The last worker/canonical Arc, not cache replacement, owns final logging.
        assert_eq!(captured.0.lock().unwrap().len(), 1);
        drop(old);
        let rows = captured.0.lock().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["session_id"], old_id.to_string());
        assert_eq!(rows[0]["phase"], "\"loop_finish\"");
        assert_eq!(rows[0]["final_counts"], "false");
        assert_eq!(rows[0]["capture_window"], "512");
        assert_eq!(rows[0]["unfinished_worker_entries"], "1");
        assert_eq!(rows[1]["phase"], "\"session_drop\"");
        assert_eq!(rows[1]["final_counts"], "true");
        assert_eq!(rows[1]["capture_window"], "512");
        assert_eq!(rows[1]["session_id"], old_id.to_string());
        assert_eq!(rows[1]["payload_hash"], payload.to_string());
        assert_eq!(rows[1]["retained_results"], "Some(1)");
        assert_eq!(rows[1]["unfinished_worker_entries"], "0");
        assert!(rows[1]["counters"].contains("published: 1"));
        drop(rows);
    }

    #[test]
    fn diagnostic_unwind_and_poison_are_counted_without_changing_fallback() {
        let session = diagnostic_session(2);
        assert!(session.publish(candidate(0)));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _worker = session.worker_entry().unwrap();
            let _retained = session.retained.lock().unwrap();
            panic!("diagnostic fixture");
        }));
        assert!(panic.is_err());
        assert!(!session.publish(candidate(1)));
        assert!(session.take(&tx(1)).is_none());
        let count = counts(&session);
        assert_eq!(count(CaptureEvent::WorkerEntries), 1);
        assert_eq!(count(CaptureEvent::WorkerFinished), 1);
        assert_eq!(count(CaptureEvent::WorkerUnwound), 1);
        assert_eq!(count(CaptureEvent::PublishPoisoned), 1);
        assert_eq!(count(CaptureEvent::TakePoisoned), 1);
        assert_eq!(count(CaptureEvent::TakeMissing), 1);
        drop(session); // Drop reports poisoned retained data using exclusive access.
    }

    #[test]
    fn duplicate_and_oversized_blocks_clear_the_current_session() {
        let cache = EnginePrewarmingCache::default();
        let original = cache.begin(env(), [hash(0)]).unwrap();
        assert!(Arc::ptr_eq(&cache.session(&env()).unwrap(), &original));
        assert!(cache.begin(env(), [hash(0), hash(0)]).is_none());
        assert!(cache.session(&env()).is_none());
        assert!(
            cache
                .begin(env(), (0..MAX_TRANSACTIONS).map(hash))
                .is_some()
        );
        assert!(
            cache
                .begin(env(), (0..=MAX_TRANSACTIONS).map(hash))
                .is_none()
        );
        assert!(cache.session(&env()).is_none());
        cache.begin(env(), [hash(0)]).unwrap();
        #[expect(
            clippy::redundant_clone,
            reason = "verify clones share the current session"
        )]
        cache.clone().clear();
        assert!(cache.session(&env()).is_none());
    }

    #[test]
    fn environment_and_transaction_context_must_match() {
        let cache = EnginePrewarmingCache::default();
        let session = cache.begin(env(), [hash(0)]).unwrap();
        let mut changed = env();
        changed.block_env.inner.basefee += 1;
        assert!(cache.session(&changed).is_none());
        let mut simulation = tx(0);
        simulation.execution_context = ExecutionContext::Simulation;
        assert!(!session.can_capture(&simulation));
        assert!(session.take(&simulation).is_none());
        let mut system = tx(0);
        system.is_system_tx = true;
        assert!(!session.can_capture(&system));
        assert!(!session.can_capture(&tx(1)));
        let mut wrong_env = candidate(0);
        wrong_env.env = changed;
        assert!(!session.publish(wrong_env));
        assert!(session.publish(candidate(0)));
        assert!(session.take(&tx(0)).is_some());
        assert!(session.take(&tx(0)).is_none());
    }

    #[test]
    fn ordered_misses_discard_late_work_and_open_the_next_window() {
        let session = EnginePrewarmingCache::default()
            .begin(env(), (0..=LOOKAHEAD).map(hash))
            .unwrap();
        assert!(session.can_capture(&tx(LOOKAHEAD - 1)));
        assert!(!session.can_capture(&tx(LOOKAHEAD)));
        assert!(!session.publish(candidate(LOOKAHEAD)));
        assert!(session.take(&tx(0)).is_none());
        assert!(!session.publish(candidate(0)));
        assert!(session.can_capture(&tx(LOOKAHEAD)));
        assert!(session.publish(candidate(LOOKAHEAD)));
        assert!(session.take(&tx(LOOKAHEAD)).is_some());
        assert!(!session.can_capture(&tx(LOOKAHEAD - 1)));
        assert_eq!(session.retained.lock().unwrap().estimated_bytes, 0);
    }

    #[test]
    fn publication_never_waits_and_retains_only_one_full_window() {
        let session = EnginePrewarmingCache::default()
            .begin(env(), (0..=LOOKAHEAD).map(hash))
            .unwrap();
        let guard = session.retained.lock().unwrap();
        assert!(!session.publish(candidate(0)));
        drop(guard);
        for index in 0..LOOKAHEAD {
            assert!(session.publish(candidate(index)));
        }
        assert!(!session.publish(candidate(0)));
        assert!(!session.publish(candidate(LOOKAHEAD)));
        assert_eq!(session.retained.lock().unwrap().results.len(), LOOKAHEAD);
        assert!(session.take(&tx(LOOKAHEAD - 1)).is_some());
        let retained = session.retained.lock().unwrap();
        assert!(retained.results.is_empty());
        assert_eq!(retained.estimated_bytes, 0);
    }

    #[test]
    fn replacement_sessions_do_not_receive_old_workers_results() {
        let cache = EnginePrewarmingCache::default();
        let old = cache.begin(env(), [hash(0)]).unwrap();
        let new = cache.begin(env(), [hash(0)]).unwrap();
        assert!(old.publish(candidate(0)));
        assert!(new.take(&tx(0)).is_none());
        assert!(Arc::ptr_eq(&cache.session(&env()).unwrap(), &new));
    }

    #[test]
    fn oversized_payloads_and_aggregate_budget_fail_closed() {
        let session = EnginePrewarmingCache::default()
            .begin(env(), [hash(0), hash(1)])
            .unwrap();
        let mut oversized = candidate(0);
        oversized.tx.inner.data = Bytes::from(vec![0; MAX_ESTIMATED_BYTES]);
        assert!(!session.publish(oversized));
        for index in 0..2 {
            let mut large = candidate(index);
            large.tx.inner.data = Bytes::from(vec![0; MAX_ESTIMATED_BYTES / 2]);
            assert_eq!(session.publish(large), index == 0);
        }
        assert!(session.take(&tx(0)).is_some());
        assert_eq!(session.retained.lock().unwrap().estimated_bytes, 0);
        assert!(session.publish(candidate(1)));
        assert!(ByteBudget(0).add(usize::MAX).is_none());
        assert!(ByteBudget(1).add(usize::MAX).is_none());
    }

    #[test]
    fn nested_payloads_and_retained_capacity_are_charged() {
        use alloy_primitives::Log;
        use reth_revm::context::result::{ExecutionResult, HaltReason, ResultGas};
        use tempo_primitives::transaction::Call;

        let mut nested = candidate(0);
        let baseline = estimated_bytes(&mut nested).unwrap();
        nested.tx.tempo_tx_env = Some(Box::new(tempo_revm::TempoBatchCallEnv {
            aa_calls: vec![Call {
                to: TxKind::Call(Address::with_last_byte(202)),
                value: Default::default(),
                input: Bytes::from(vec![0; 8192]),
            }],
            ..Default::default()
        }));
        assert!(estimated_bytes(&mut nested).unwrap() >= baseline + 8192);

        let mut message = String::with_capacity(8192);
        message.push('x');
        let mut log: Log = Log::default();
        log.data.topics_mut_unchecked().reserve(256);
        let topic_bytes = log.data.topics_mut_unchecked().capacity() * size_of::<B256>();
        nested.result.result = ExecutionResult::Halt {
            reason: HaltReason::PrecompileErrorWithContext(message),
            gas: ResultGas::default(),
            logs: vec![log],
        };
        assert!(estimated_bytes(&mut nested).unwrap() >= baseline + 16_384 + topic_bytes);
    }

    #[test]
    fn hash_lookup_does_not_replace_complete_transaction_validation() {
        let session = EnginePrewarmingCache::default()
            .begin(env(), [hash(0)])
            .unwrap();
        assert!(session.publish(candidate(0)));
        let mut changed = tx(0);
        changed.inner.caller = Address::with_last_byte(203);
        let result = session.take(&changed).unwrap();
        assert!(
            result
                .into_candidate::<std::convert::Infallible>(&changed)
                .is_none()
        );
    }
}

#[cfg(test)]
#[path = "engine_prewarming_tests.rs"]
mod capture_tests;
