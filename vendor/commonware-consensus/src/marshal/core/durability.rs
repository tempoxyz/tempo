//! Durability helpers for marshal's deferred syncs: the fatal policy for
//! awaiting durable syncs, and the gate that defers application dispatch
//! until finalized-archive writes are durable.
//!
//! A marshal write starts its fsync eagerly: the archive spawns the sync and returns a
//! [`Handle`] that only observes completion. The storage layer already makes those handles
//! safe to share and drop: every observer of a sync sees the same result, later operations
//! on the same store wait for (and re-surface the failure of) an in-flight sync, and a
//! duplicate put returns a handle that still covers the original write. What remains for
//! marshal is the failure policy: a sync failure is fatal to local storage state and must
//! never become a recoverable verdict.

use crate::types::{Height, Round};
use commonware_runtime::{Error, Handle};
use std::{collections::BTreeMap, future::Future};
use tracing::debug;

/// Applies marshal's fatal policy when awaiting a durable-sync [`Handle`].
pub(crate) trait Durable {
    /// Resolves `true` once the sync is durable. A real sync failure panics (annotated
    /// with `name` and `round`) rather than resolving: converting it into a `false`
    /// verdict would let consensus treat lost local state as a live rejection. Resolves
    /// `false` only when the runtime is shutting down (the handle was closed or aborted
    /// before the sync resolved), so the caller reports "not durable" and abandons the
    /// work.
    fn durable(self, round: Round, name: &'static str) -> impl Future<Output = bool> + Send;
}

impl Durable for Handle<()> {
    #[tracing::instrument(
        name = "marshal.durable",
        level = "info",
        skip_all,
        fields(round = %round, name = name)
    )]
    async fn durable(self, round: Round, name: &'static str) -> bool {
        match self.await {
            Ok(()) => true,
            Err(Error::Closed | Error::Aborted) => {
                debug!(name, "runtime shutdown before sync completed");
                false
            }
            Err(e) => panic!("failed to sync {name} at {round}: {e}"),
        }
    }
}

/// Defers application dispatch of finalized-archive writes until a sync
/// covering them completes.
///
/// Buffered archive writes are readable before they are durable, so every
/// write is tracked from the moment it is buffered until a sync covers it:
/// [`Self::defer`] holds a write while no started sync covers it,
/// [`Self::adopt`] moves the held writes into an in-flight batch when a
/// pooled sync starts, and [`Self::release`] (pooled) or [`Self::clear`]
/// (blocking) drops batches once they are durable. [`Self::barrier`] reports
/// the lowest tracked height, below which dispatch must stay.
#[derive(Default)]
pub(super) struct DispatchGate {
    /// Lowest deferred write no started sync covers.
    unsynced: Option<Height>,
    /// Lowest deferred write per in-flight pooled sync, keyed by start order.
    inflight: BTreeMap<u64, Height>,
    /// Sequence assigned to the next adopted batch. Monotonic across
    /// [`Self::clear`] so a stale completion can never release a batch
    /// adopted later.
    next_seq: u64,
}

impl DispatchGate {
    /// Defers dispatch at or above `height` until a sync covering this write
    /// completes.
    pub(super) fn defer(&mut self, height: Height) {
        self.unsynced = Some(self.unsynced.map_or(height, |lowest| lowest.min(height)));
    }

    /// Adopts every deferred write no sync covers into a new in-flight batch,
    /// returning the sequence its sync must [`Self::release`]. Returns `None`
    /// if every deferred write is already covered: no sync needs to start.
    pub(super) fn adopt(&mut self) -> Option<u64> {
        let lowest = self.unsynced.take()?;
        let seq = self.next_seq;
        self.next_seq += 1;
        self.inflight.insert(seq, lowest);
        Some(seq)
    }

    /// Releases every batch covered by the completed pooled sync `seq`. A
    /// sync makes durable every write accepted before it started, so all
    /// batches with an equal or lower sequence are released, regardless of
    /// the order in which pooled syncs complete.
    pub(super) fn release(&mut self, seq: u64) {
        self.inflight = self.inflight.split_off(&(seq + 1));
    }

    /// Releases everything. A blocking sync waits on (and covers) every
    /// previously accepted write, including writes adopted by in-flight
    /// pooled syncs and writes no sync has adopted yet.
    pub(super) fn clear(&mut self) {
        self.unsynced = None;
        self.inflight.clear();
    }

    /// Lowest height whose write may not be durable yet. Dispatch must not
    /// send blocks at or above it.
    pub(super) fn barrier(&self) -> Option<Height> {
        self.inflight.values().copied().chain(self.unsynced).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner as _};

    #[test]
    fn test_durable_resolves_true_on_success() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            assert!(Handle::ready(Ok(())).durable(Round::zero(), "test").await);
        });
    }

    #[test]
    fn test_durable_reports_shutdown_as_not_durable() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            assert!(
                !Handle::ready(Err(Error::Closed))
                    .durable(Round::zero(), "test")
                    .await
            );
            assert!(
                !Handle::ready(Err(Error::Aborted))
                    .durable(Round::zero(), "test")
                    .await
            );
        });
    }

    #[test]
    #[should_panic(expected = "failed to sync test")]
    fn test_durable_panics_on_sync_failure() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let failure = Handle::<()>::ready(Err(Error::WriteFailed));
            let _ = failure.durable(Round::zero(), "test").await;
        });
    }

    #[test]
    fn test_gate_defer_keeps_lowest_write() {
        let mut gate = DispatchGate::default();
        assert_eq!(gate.barrier(), None);
        gate.defer(Height::new(5));
        gate.defer(Height::new(3));
        gate.defer(Height::new(7));
        assert_eq!(gate.barrier(), Some(Height::new(3)));
    }

    #[test]
    fn test_gate_adopt_moves_writes_to_one_batch() {
        let mut gate = DispatchGate::default();
        assert_eq!(gate.adopt(), None);
        gate.defer(Height::new(5));
        let seq = gate.adopt().expect("deferred write must adopt");
        assert_eq!(gate.barrier(), Some(Height::new(5)));
        assert_eq!(gate.adopt(), None);
        gate.release(seq);
        assert_eq!(gate.barrier(), None);
    }

    #[test]
    fn test_gate_release_covers_earlier_batches_only() {
        let mut gate = DispatchGate::default();
        gate.defer(Height::new(5));
        let first = gate.adopt().expect("first batch");
        gate.defer(Height::new(8));
        let second = gate.adopt().expect("second batch");

        // A completed sync covers every earlier batch, so releasing the
        // second releases both, while releasing only the first must keep
        // the second's write gated.
        let mut out_of_order = DispatchGate::default();
        out_of_order.defer(Height::new(5));
        out_of_order.adopt().expect("first batch");
        out_of_order.defer(Height::new(8));
        let newest = out_of_order.adopt().expect("second batch");
        out_of_order.release(newest);
        assert_eq!(out_of_order.barrier(), None);

        gate.release(first);
        assert_eq!(gate.barrier(), Some(Height::new(8)));
        gate.release(second);
        assert_eq!(gate.barrier(), None);
    }

    #[test]
    fn test_gate_clear_is_not_release_for_later_batches() {
        let mut gate = DispatchGate::default();
        gate.defer(Height::new(5));
        let stale = gate.adopt().expect("first batch");
        gate.defer(Height::new(3));
        gate.clear();
        assert_eq!(gate.barrier(), None);

        // A batch adopted after the clear must not be released by a stale
        // completion from before it.
        gate.defer(Height::new(9));
        gate.adopt().expect("post-clear batch");
        gate.release(stale);
        assert_eq!(gate.barrier(), Some(Height::new(9)));
    }
}
