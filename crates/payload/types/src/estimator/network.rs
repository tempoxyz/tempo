//! Network reservation learned from finalized successors of own proposals.

use super::{Config, ProposalKey};
use std::{
    collections::VecDeque,
    ops::{Add, Sub},
    time::{Duration, Instant},
};

/// Number of own proposals the network reservation is derived from.
const NETWORK_SAMPLE_WINDOW: usize = 16;
/// Network samples older than this are dropped, so that a node that stopped
/// proposing does not keep stale ones. With N validators and 550 ms blocks an
/// own proposal completes every ~0.55 N s, so ten minutes hold the full 16
/// samples for committees of up to ~68 validators.
const NETWORK_SAMPLE_TTL: Duration = Duration::from_secs(10 * 60);
/// Network samples longer than this, from the window's close to the child's
/// header, are discarded as clock skew or a stall unrelated to propagation.
const MAX_NETWORK_SAMPLE: Duration = Duration::from_secs(5);
/// Largest change of the network reservation between consecutive own proposals,
/// however the window's percentile moved in between (sparse window, expiry,
/// outlier, fast rise). One bad sample costs the next proposal at most this
/// much of its window.
const NETWORK_RESERVE_MAX_STEP: Duration = Duration::from_millis(100);
/// An own proposal whose child block has not arrived after this long is no
/// longer a usable network sample: its view was most likely nullified, or
/// the next leader built on an ancestor.
const PENDING_PROPOSAL_TTL: Duration = Duration::from_secs(10);
/// Upper bound on own proposals awaiting the block built on top of them.
const MAX_PENDING_PROPOSALS: usize = 8;

/// Bounded, age-limited window of samples with percentile reads. Samples are
/// kept in insertion order and expire by the `Instant` they were pushed with,
/// which may be slightly older than the previous one's: callers read the clock
/// before they take the estimator's lock.
#[derive(Clone, Debug)]
struct SampleWindow<T> {
    samples: VecDeque<(Instant, T)>,
    capacity: usize,
    ttl: Duration,
}

impl<T: Copy + Ord> SampleWindow<T> {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
            ttl,
        }
    }

    /// Adds a sample, evicting the oldest one at capacity. Owners prune first.
    fn push(&mut self, now: Instant, value: T) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back((now, value));
    }

    fn prune(&mut self, now: Instant) {
        self.samples
            .retain(|(at, _)| now.saturating_duration_since(*at) <= self.ttl);
    }

    fn len(&self) -> usize {
        self.samples.len()
    }

    fn newest(&self) -> impl Iterator<Item = T> + '_ {
        self.samples.iter().rev().map(|(_, value)| *value)
    }

    /// Returns the `percent`th percentile, rounding the rank up so that a
    /// single sample is returned as is.
    fn percentile(&self, percent: u8) -> Option<T> {
        if self.samples.is_empty() {
            return None;
        }
        let mut values: Vec<T> = self.samples.iter().map(|(_, value)| *value).collect();
        values.sort_unstable();
        let rank = (values.len() * usize::from(percent)).div_ceil(100).max(1);
        values.get(rank - 1).copied()
    }
}

/// Moves `current` toward `target` by at most `max_step`, in either direction.
/// Both learned estimates follow their percentile through this because the
/// percentile can jump: that of a sparse window is its maximum, and samples
/// aging out can leave an outlier behind.
fn step_toward<T>(current: T, target: T, max_step: T) -> T
where
    T: Copy + Ord + Add<Output = T> + Sub<Output = T>,
{
    if target >= current {
        current + (target - current).min(max_step)
    } else {
        current - (current - target).min(max_step)
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Bounded network reservation learned from finalized successors.
#[derive(Clone, Debug)]
pub(super) struct NetworkTracker {
    samples: SampleWindow<u64>,
    pending: VecDeque<PendingProposal>,
    floor: Duration,
    cap: Duration,
    percentile: u8,
    fast_rise: bool,
    applied: Duration,
}

impl NetworkTracker {
    pub(super) fn new(config: &Config) -> Self {
        Self {
            samples: SampleWindow::new(NETWORK_SAMPLE_WINDOW, NETWORK_SAMPLE_TTL),
            pending: VecDeque::with_capacity(MAX_PENDING_PROPOSALS),
            floor: config.network_budget,
            cap: config.network_budget_max,
            percentile: config.network_reserve_percentile,
            fast_rise: config.network_reserve_fast_rise,
            applied: config.network_budget,
        }
    }

    pub(super) fn prune(&mut self, now: Instant) {
        self.samples.prune(now);
        self.pending.retain(|pending| {
            now.saturating_duration_since(pending.returned_at) <= PENDING_PROPOSAL_TTL
        });
    }

    pub(super) fn proposal_returned(&mut self, now: Instant, proposal: PendingProposal) {
        self.prune(now);
        self.pending.retain(|pending| pending.key != proposal.key);
        if self.pending.len() == MAX_PENDING_PROPOSALS {
            self.pending.pop_front();
        }
        self.pending.push_back(proposal);
    }

    pub(super) fn child_built(
        &mut self,
        now: Instant,
        parent: ProposalKey,
        child_view: u64,
        child_timestamp_ms: u64,
    ) -> Option<Duration> {
        self.prune(now);
        let index = self
            .pending
            .iter()
            .position(|pending| pending.key == parent)?;
        let pending = self.pending.remove(index)?;
        if child_view != parent.1.saturating_add(1) {
            return None;
        }
        if child_timestamp_ms < pending.returned_unix_ms {
            return None;
        }
        let network =
            Duration::from_millis(child_timestamp_ms.saturating_sub(pending.window_opened_unix_ms))
                .saturating_sub(pending.return_budget);
        if network > MAX_NETWORK_SAMPLE {
            return None;
        }
        self.samples.push(now, nanos(network));
        Some(network)
    }

    fn observed(&self) -> Option<Duration> {
        let window = self.samples.percentile(self.percentile)?;
        let mut newest = self.samples.newest();
        let observed = match (newest.next(), newest.next()) {
            (Some(last), Some(previous)) if self.fast_rise => window.max(last.min(previous)),
            _ => window,
        };
        Some(Duration::from_nanos(observed))
    }

    fn target(&self) -> Duration {
        self.observed()
            .map_or(self.floor, |observed| observed.clamp(self.floor, self.cap))
    }

    pub(super) fn sample_count(&self) -> usize {
        self.samples.len()
    }

    pub(super) fn reserve_for_proposal(&mut self, now: Instant) -> Duration {
        self.prune(now);
        self.applied = step_toward(self.applied, self.target(), NETWORK_RESERVE_MAX_STEP);
        self.applied
    }
}

/// An own proposal waiting for the block built on top of it.
#[derive(Clone, Copy, Debug)]
pub(super) struct PendingProposal {
    pub(super) key: ProposalKey,
    pub(super) returned_at: Instant,
    pub(super) window_opened_unix_ms: u64,
    pub(super) returned_unix_ms: u64,
    pub(super) return_budget: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(now: Instant, view: u64) -> PendingProposal {
        PendingProposal {
            key: (1, view),
            returned_at: now,
            window_opened_unix_ms: 1_000,
            returned_unix_ms: 1_502,
            return_budget: Duration::from_millis(500),
        }
    }

    #[test]
    fn successor_samples_from_window_close_and_reservation_moves_in_bounded_steps() {
        let now = Instant::now();
        let mut tracker = NetworkTracker::new(&Config::default());
        tracker.proposal_returned(now, proposal(now, 1));
        assert_eq!(tracker.sample_count(), 0);
        assert_eq!(
            tracker.child_built(now, (1, 1), 2, 1_900),
            Some(Duration::from_millis(400))
        );
        for reserve in [150, 250, 300] {
            assert_eq!(
                tracker.reserve_for_proposal(now),
                Duration::from_millis(reserve)
            );
        }
        assert_eq!(tracker.child_built(now, (1, 1), 2, 1_900), None);
        assert_eq!(tracker.sample_count(), 1);
        let expired = now + NETWORK_SAMPLE_TTL + Duration::from_nanos(1);
        for reserve in [200, 100, 50] {
            assert_eq!(
                tracker.reserve_for_proposal(expired),
                Duration::from_millis(reserve)
            );
        }
        assert_eq!(tracker.sample_count(), 0);
    }

    #[test]
    fn skipped_views_clock_skew_stalls_and_expired_proposals_do_not_teach_network() {
        let now = Instant::now();
        for (child_view, timestamp, elapsed) in [
            (3, 1_900, Duration::ZERO),
            (2, 1_501, Duration::ZERO),
            (2, 6_501, Duration::ZERO),
            (2, 1_900, PENDING_PROPOSAL_TTL + Duration::from_nanos(1)),
        ] {
            let mut tracker = NetworkTracker::new(&Config::default());
            tracker.proposal_returned(now, proposal(now, 1));
            assert_eq!(
                tracker.child_built(now + elapsed, (1, 1), child_view, timestamp),
                None
            );
            assert_eq!(tracker.sample_count(), 0);
            assert!(tracker.pending.is_empty());
        }
    }

    #[test]
    fn two_slow_samples_raise_target_only_when_fast_rise_enabled() {
        let now = Instant::now();
        for fast_rise in [false, true] {
            let mut tracker = NetworkTracker::new(&Config {
                network_reserve_percentile: 50,
                network_reserve_fast_rise: fast_rise,
                ..Config::default()
            });
            for view in 1..=8 {
                tracker.proposal_returned(now, proposal(now, view));
                let sample = if view <= 6 { 50 } else { 250 };
                assert_eq!(
                    tracker.child_built(now, (1, view), view + 1, 1_500 + sample),
                    Some(Duration::from_millis(sample))
                );
            }
            assert_eq!(
                tracker.target(),
                Duration::from_millis(if fast_rise { 250 } else { 50 })
            );
        }
    }

    #[test]
    fn pending_and_completed_windows_are_bounded_and_duplicate_returns_replace() {
        let now = Instant::now();
        let mut tracker = NetworkTracker::new(&Config::default());
        for view in 1..=MAX_PENDING_PROPOSALS as u64 + 1 {
            tracker.proposal_returned(now, proposal(now, view));
        }
        assert_eq!(tracker.pending.len(), MAX_PENDING_PROPOSALS);
        assert_eq!(tracker.pending.front().unwrap().key, (1, 2));
        tracker.proposal_returned(now, proposal(now, 2));
        assert_eq!(tracker.pending.len(), MAX_PENDING_PROPOSALS);
        for view in 20..=20 + NETWORK_SAMPLE_WINDOW as u64 {
            tracker.proposal_returned(now, proposal(now, view));
            assert_eq!(
                tracker.child_built(now, (1, view), view + 1, 1_550),
                Some(Duration::from_millis(50))
            );
        }
        assert_eq!(tracker.sample_count(), NETWORK_SAMPLE_WINDOW);
    }
}
