//! Temporary per-build accounting for the lane prewarming benchmark.
//!
//! Worker time is summed across threads, not wall time. Records are retained until all
//! workers and the builder release the build, so rejected and never-consumed work is counted.

use alloy_primitives::B256;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

static NEXT_BUILD_ID: AtomicU64 = AtomicU64::new(0);

/// An observation shared by the builder and the worker for one scheduling attempt.
#[derive(Debug, Default)]
pub(crate) struct PrewarmObservation {
    payment: bool,
    scheduled: u64,
    gas_limit: u64,
    pub(crate) nonfitting_at_start: AtomicU64,
    pub(crate) started: AtomicU64,
    pub(crate) finished: AtomicU64,
    /// 0: not executed, 1: EVM error, 2: reverted, 3: successful.
    pub(crate) worker_result: AtomicU64,
    /// 0: not consumed/rejected elsewhere, 1: included success, 2: included revert,
    /// 3: general cap, 4: other builder rejection, 5: execution error.
    pub(crate) outcome: AtomicU64,
    readiness: AtomicU64,
    pub(crate) execution_ns: AtomicU64,
}

impl PrewarmObservation {
    /// Snapshot completion before execution; completion does not prove every access is a cache hit.
    pub(crate) fn observe_execution(&self) {
        let state = if self.finished.load(Ordering::Acquire) != 0 {
            match self.worker_result.load(Ordering::Relaxed) {
                3 => 3,
                2 => 4,
                1 => 5,
                _ => 6,
            }
        } else if self.started.load(Ordering::Relaxed) != 0 {
            2
        } else {
            1
        };
        self.readiness.store(state, Ordering::Relaxed);
    }
}

/// Instrumentation only: none of these observations affect scheduling or execution.
#[derive(Debug)]
pub(crate) struct PrewarmDiagnostics {
    pub(crate) id: u64,
    origin: Instant,
    block: u64,
    parent: B256,
    parallel: bool,
    general_limit: u64,
    pub(crate) general_used: AtomicU64,
    pub(crate) worker_threads: AtomicU64,
    records: Mutex<Vec<Arc<PrewarmObservation>>>,
    pub(crate) first_general_skip: AtomicU64,
    pub(crate) cutoff: AtomicU64,
    pub(crate) next_ns: AtomicU64,
    pub(crate) invalidation_ns: AtomicU64,
    pub(crate) invalidations: AtomicU64,
    pub(crate) drained: AtomicU64,
}

impl PrewarmDiagnostics {
    pub(crate) fn new(block: u64, parent: B256, parallel: bool, general_limit: u64) -> Self {
        Self {
            id: NEXT_BUILD_ID.fetch_add(1, Ordering::Relaxed),
            origin: Instant::now(),
            block,
            parent,
            parallel,
            general_limit,
            general_used: AtomicU64::new(0),
            worker_threads: AtomicU64::new(0),
            records: Mutex::new(Vec::new()),
            first_general_skip: AtomicU64::new(0),
            cutoff: AtomicU64::new(0),
            next_ns: AtomicU64::new(0),
            invalidation_ns: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
            drained: AtomicU64::new(0),
        }
    }

    pub(crate) fn now(&self) -> u64 {
        self.origin.elapsed().as_nanos() as u64 + 1
    }

    pub(crate) fn schedule(&self, payment: bool, gas_limit: u64) -> Arc<PrewarmObservation> {
        let record = Arc::new(PrewarmObservation {
            payment,
            scheduled: self.now(),
            gas_limit,
            ..Default::default()
        });
        self.records.lock().unwrap().push(record.clone());
        record
    }

    pub(crate) fn start(&self, observation: &PrewarmObservation) {
        observation.started.store(self.now(), Ordering::Relaxed);
        observation.nonfitting_at_start.store(
            u64::from(
                !observation.payment
                    && observation.gas_limit
                        > self
                            .general_limit
                            .saturating_sub(self.general_used.load(Ordering::Relaxed)),
            ),
            Ordering::Relaxed,
        );
    }
}

impl Drop for PrewarmDiagnostics {
    fn drop(&mut self) {
        let cutoff = self.cutoff.load(Ordering::Relaxed);
        let cap = self.first_general_skip.load(Ordering::Relaxed);
        let mut groups = BTreeMap::<_, Counts>::new();
        for r in self.records.get_mut().unwrap().iter() {
            let started = r.started.load(Ordering::Relaxed);
            let finished = r.finished.load(Ordering::Relaxed);
            let result = r.worker_result.load(Ordering::Relaxed);
            let key = (
                r.payment,
                r.outcome.load(Ordering::Relaxed),
                r.readiness.load(Ordering::Relaxed),
                cap != 0 && started >= cap,
                r.nonfitting_at_start.load(Ordering::Relaxed),
            );
            let c = groups.entry(key).or_default();
            c.count += 1;
            c.worker_started += u64::from(started != 0);
            c.worker_finished += u64::from(finished != 0);
            c.worker_success += u64::from(result == 3);
            c.worker_revert += u64::from(result == 2);
            c.worker_error += u64::from(result == 1);
            if started != 0 && finished != 0 {
                c.worker_ns += finished.saturating_sub(started);
                c.worker_before_cutoff_ns += overlap(started, finished, 0, cutoff);
                if cap != 0 {
                    c.worker_after_cap_ns += overlap(started, finished, cap, cutoff);
                }
                c.queue_ns += started.saturating_sub(r.scheduled);
            }
            c.execution_ns += r.execution_ns.load(Ordering::Relaxed);
        }
        tracing::info!(target: "prewarm_diagnostics", build_id = self.id, block = self.block, parent = %self.parent,
            parallel = self.parallel, cutoff_ns = cutoff, first_general_skip_ns = cap,
            worker_threads = self.worker_threads.load(Ordering::Relaxed),
            next_ns = self.next_ns.load(Ordering::Relaxed),
            invalidation_ns = self.invalidation_ns.load(Ordering::Relaxed),
            invalidations = self.invalidations.load(Ordering::Relaxed),
            drained = self.drained.load(Ordering::Relaxed), "prewarm_build");
        for ((payment, outcome, readiness, after_cap, nonfitting_at_start), c) in groups {
            tracing::info!(target: "prewarm_diagnostics", build_id = self.id, block = self.block, parent = %self.parent,
                payment, outcome, readiness, after_cap, nonfitting_at_start,
                count = c.count, worker_started = c.worker_started, worker_finished = c.worker_finished,
                worker_success = c.worker_success, worker_revert = c.worker_revert,
                worker_error = c.worker_error, worker_ns = c.worker_ns,
                worker_before_cutoff_ns = c.worker_before_cutoff_ns,
                worker_after_cap_ns = c.worker_after_cap_ns, queue_ns = c.queue_ns,
                execution_ns = c.execution_ns, "prewarm_lane");
        }
    }
}

#[derive(Default)]
struct Counts {
    count: u64,
    worker_started: u64,
    worker_finished: u64,
    worker_success: u64,
    worker_revert: u64,
    worker_error: u64,
    worker_ns: u64,
    worker_before_cutoff_ns: u64,
    worker_after_cap_ns: u64,
    queue_ns: u64,
    execution_ns: u64,
}

fn overlap(start: u64, end: u64, from: u64, to: u64) -> u64 {
    end.min(to).saturating_sub(start.max(from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_worker_time_to_build_and_cap() {
        assert_eq!(overlap(10, 100, 0, 50), 40);
        assert_eq!(overlap(10, 100, 30, 50), 20);
        assert_eq!(overlap(60, 100, 30, 50), 0);
        assert_eq!(overlap(10, 20, 30, 50), 0);
    }

    #[test]
    fn distinguish_pending_running_and_failed_prewarming() {
        let r = PrewarmObservation::default();
        r.observe_execution();
        assert_eq!(r.readiness.load(Ordering::Relaxed), 1);
        r.started.store(1, Ordering::Relaxed);
        r.observe_execution();
        assert_eq!(r.readiness.load(Ordering::Relaxed), 2);
        r.worker_result.store(1, Ordering::Relaxed);
        r.finished.store(2, Ordering::Release);
        r.observe_execution();
        assert_eq!(r.readiness.load(Ordering::Relaxed), 5);
        r.worker_result.store(3, Ordering::Relaxed);
        r.observe_execution();
        assert_eq!(r.readiness.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn classify_fit_using_remaining_general_capacity_at_worker_start() {
        let d = PrewarmDiagnostics::new(1, B256::ZERO, false, 30_000_000);
        let large = d.schedule(false, 5_000_000);
        let small = d.schedule(false, 100_000);
        let payment = d.schedule(true, 5_000_000);
        d.general_used.store(25_100_000, Ordering::Relaxed);
        d.start(&large);
        d.start(&small);
        d.start(&payment);
        assert_eq!(large.nonfitting_at_start.load(Ordering::Relaxed), 1);
        assert_eq!(small.nonfitting_at_start.load(Ordering::Relaxed), 0);
        assert_eq!(payment.nonfitting_at_start.load(Ordering::Relaxed), 0);
    }
}
