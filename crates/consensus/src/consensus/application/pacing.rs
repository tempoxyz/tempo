//! Local feedback for proposal pacing, independent of consensus safety rules.
//!
//! Each validator learns from its own successful proposal-to-notarization latency.
//! This includes replay and voting as well as propagation: it is a pacing
//! correction, not a measurement of network RTT. Each proposal snapshots its
//! budget so updates cannot change a build already in flight.

use std::time::{Duration, Instant};

use commonware_consensus::types::{Round, View};

use crate::consensus::Digest;

const MAX_STEP: Duration = Duration::from_millis(10);
const DEADBAND: Duration = Duration::from_millis(5);
const RETURN_TOLERANCE: Duration = Duration::from_millis(10);

pub(super) struct Pacing {
    target: Duration,
    budget: Duration,
    minimum: Duration,
    pending: Option<Pending>,
    latest_round: Option<Round>,
}

struct Pending {
    round: Round,
    started_at: Instant,
    budget: Duration,
    digest: Option<Digest>,
}

impl Pacing {
    pub(super) fn new(target: Duration, initial_budget: Duration) -> Self {
        Self {
            target,
            budget: initial_budget.min(target),
            // Retain at least a quarter of the target for useful local work,
            // without increasing an explicitly configured smaller initial budget.
            minimum: (target / 4).min(initial_budget),
            pending: None,
            latest_round: None,
        }
    }

    pub(super) fn begin(&mut self, round: Round, parent: View, now: Instant) -> Duration {
        if self.latest_round.is_some_and(|latest| round <= latest) {
            return self.budget;
        }
        self.latest_round = Some(round);
        // After a skipped view, recovery work must not reduce the normal budget.
        self.pending =
            (parent.get().checked_add(1) == Some(round.view().get())).then_some(Pending {
                round,
                started_at: now,
                budget: self.budget,
                digest: None,
            });
        self.budget
    }

    pub(super) fn ready(&mut self, round: Round, digest: Digest, now: Instant) {
        let Some(pending) = self.pending.as_mut().filter(|p| p.round == round) else {
            return;
        };
        // Do not interpret a local build/storage overrun as a pacing error.
        if now.saturating_duration_since(pending.started_at)
            > pending.budget.saturating_add(RETURN_TOLERANCE)
        {
            self.pending = None;
            return;
        }
        pending.digest = Some(digest);
    }

    pub(super) fn cancel(&mut self, round: Round) {
        if self.pending.as_ref().is_some_and(|p| p.round <= round) {
            self.pending = None;
        }
    }

    /// Returns the accepted sample and new budget, once per matching proposal.
    pub(super) fn notarized(
        &mut self,
        round: Round,
        digest: Digest,
        now: Instant,
    ) -> Option<(Duration, Duration)> {
        let pending = self.pending.as_ref()?;
        if pending.round != round || pending.digest != Some(digest) {
            return None;
        }
        let pending = self.pending.take()?;
        let elapsed = now.checked_duration_since(pending.started_at)?;
        // Reject long recovery/stall samples even when they eventually notarize.
        if elapsed.is_zero() || elapsed > self.target.saturating_mul(2) {
            return None;
        }
        let error = elapsed.abs_diff(self.target);
        if error > DEADBAND {
            // Integral feedback with gain 1/8, bounded movement and anti-windup:
            // there is no hidden error accumulator beyond the clamped budget.
            let step = (error / 8).min(MAX_STEP);
            self.budget = if elapsed > self.target {
                pending.budget.saturating_sub(step)
            } else {
                pending.budget.saturating_add(step)
            }
            .clamp(self.minimum, self.target);
        }
        Some((elapsed, self.budget))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use commonware_consensus::types::Epoch;

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn digest() -> Digest {
        Digest(B256::with_last_byte(1))
    }

    fn sample(pacing: &mut Pacing, view: u64, overhead: Duration) -> Duration {
        let now = Instant::now();
        let budget = pacing.begin(round(view), View::new(view - 1), now);
        pacing.ready(round(view), digest(), now + budget);
        pacing.notarized(round(view), digest(), now + budget + overhead);
        pacing.budget
    }

    #[test]
    fn converges_and_recovers_after_network_change() {
        let mut pacing = Pacing::new(Duration::from_millis(550), Duration::from_millis(500));
        for view in 1..80 {
            sample(&mut pacing, view, Duration::from_millis(210));
        }
        assert!(pacing.budget.abs_diff(Duration::from_millis(340)) <= DEADBAND);
        for view in 80..160 {
            sample(&mut pacing, view, Duration::from_millis(50));
        }
        assert!(pacing.budget.abs_diff(Duration::from_millis(500)) <= DEADBAND);
    }

    #[test]
    fn bounds_adjustments_and_does_not_wind_up_at_floor() {
        let mut pacing = Pacing::new(Duration::from_millis(550), Duration::from_millis(500));
        assert_eq!(
            sample(&mut pacing, 1, Duration::from_millis(500)),
            Duration::from_millis(490)
        );
        for view in 2..100 {
            sample(&mut pacing, view, Duration::from_millis(500));
        }
        assert_eq!(pacing.budget, pacing.minimum);
        let minimum = pacing.minimum;
        assert_eq!(sample(&mut pacing, 100, Duration::ZERO), minimum + MAX_STEP);
        for view in 101..200 {
            sample(&mut pacing, view, Duration::ZERO);
        }
        assert!(pacing.budget <= pacing.target);
        assert!(pacing.target - pacing.budget <= DEADBAND);
    }

    #[test]
    fn ignores_skips_overruns_nullifications_and_duplicate_certificates() {
        let mut pacing = Pacing::new(Duration::from_millis(550), Duration::from_millis(500));
        let now = Instant::now();
        pacing.begin(round(3), View::new(1), now);
        pacing.ready(round(3), digest(), now + Duration::from_millis(300));
        assert!(
            pacing
                .notarized(round(3), digest(), now + Duration::from_millis(700))
                .is_none()
        );
        pacing.begin(round(4), View::new(3), now);
        pacing.ready(round(4), digest(), now + Duration::from_millis(600));
        assert!(
            pacing
                .notarized(round(4), digest(), now + Duration::from_millis(700))
                .is_none()
        );
        pacing.begin(round(5), View::new(4), now);
        pacing.ready(round(5), digest(), now + Duration::from_millis(300));
        pacing.cancel(round(5));
        assert!(
            pacing
                .notarized(round(5), digest(), now + Duration::from_millis(700))
                .is_none()
        );
        assert_eq!(pacing.budget, Duration::from_millis(500));
        sample(&mut pacing, 6, Duration::from_millis(210));
        assert!(
            pacing
                .notarized(round(6), digest(), now + Duration::from_millis(700))
                .is_none()
        );
        assert_eq!(pacing.budget, Duration::from_millis(490));
    }

    #[test]
    fn ignores_stale_or_wrong_proposals_and_long_stalls() {
        let mut pacing = Pacing::new(Duration::from_millis(550), Duration::from_millis(500));
        let now = Instant::now();
        pacing.begin(round(2), View::new(1), now);
        pacing.begin(round(1), View::zero(), now);
        pacing.ready(round(1), digest(), now + Duration::from_millis(300));
        pacing.ready(round(2), digest(), now + Duration::from_millis(300));
        assert!(
            pacing
                .notarized(round(1), digest(), now + Duration::from_millis(700))
                .is_none()
        );
        assert!(
            pacing
                .notarized(
                    round(2),
                    Digest(B256::ZERO),
                    now + Duration::from_millis(700)
                )
                .is_none()
        );
        assert!(
            pacing
                .notarized(round(2), digest(), now + Duration::from_secs(2))
                .is_none()
        );
        assert_eq!(pacing.budget, Duration::from_millis(500));
    }

    #[test]
    fn accepts_timer_jitter_and_preserves_small_configured_budget() {
        let mut pacing = Pacing::new(Duration::from_millis(550), Duration::from_millis(20));
        let now = Instant::now();
        pacing.begin(round(1), View::zero(), now);
        pacing.ready(round(1), digest(), now + Duration::from_millis(21));
        assert!(
            pacing
                .notarized(round(1), digest(), now + Duration::from_millis(710))
                .is_some()
        );
        assert_eq!(pacing.budget, Duration::from_millis(20));
    }
}
