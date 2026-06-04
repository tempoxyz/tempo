//! Budget helpers for deciding when to stop executing pool transactions.
//!
//! The builder can stop transaction execution, but it still has to finish
//! non-interruptible finalization work like state hashing, state root updates,
//! block assembly, and marshal persistence. These helpers learn the relation
//! between tx execution cutoff time, total replayable build work, and the
//! size-dependent cost of persisting large blocks through consensus.
//!
//! The decision model reserves proposer work that can still delay proposal
//! return, validator replay work, and marshal persistence for both sides.
//! Before `handle_propose`, completed builder work is already paid locally and
//! only the remaining builder tail affects proposal return. Validator BAL
//! replay is cheaper than proposer-side block filling, so we reserve a measured
//! fraction of builder work instead of charging a second full builder pass.

use std::time::Duration;

use tempo_payload_types::MarshalPersistEstimator;

/// Fixed-point scale for build time multipliers.
pub(crate) const BUILD_TIME_MULTIPLIER_SCALE: u64 = 1_000_000;
#[cfg(test)]
const DEFAULT_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_350_000;
pub(crate) const SPECULATIVE_BAL_BUILD_TIME_MULTIPLIER: u64 =
    BUILD_TIME_MULTIPLIER_SCALE + BUILD_TIME_MULTIPLIER_SCALE / 10;
const MAX_BUILD_TIME_MULTIPLIER: u64 = 1_700_000;
/// How quickly the multiplier decays when observed builds get cheaper.
const BUILD_TIME_MULTIPLIER_DECAY: u64 = 8;
const VALIDATOR_REPLAY_WORK_SCALE: u64 = 350_000;

/// Initial estimate of total replayable build work divided by work at tx cutoff.
///
/// For example, `1.35` means "when cutoff work is 100 ms, expect the completed
/// replayable build work to be about 135 ms".
pub const DEFAULT_BUILD_TIME_MULTIPLIER: f64 = 1.35;

/// Converts a human-readable build-work multiplier into the fixed-point representation.
pub(crate) fn scaled_build_time_multiplier(multiplier: f64) -> u64 {
    assert!(
        multiplier.is_finite() && multiplier >= 1.0,
        "build time multiplier must be finite and >= 1.0"
    );

    (multiplier * BUILD_TIME_MULTIPLIER_SCALE as f64).round() as u64
}

fn scaled_duration(elapsed: Duration, multiplier: u64) -> Duration {
    Duration::from_nanos(
        (elapsed.as_nanos().saturating_mul(u128::from(multiplier))
            / u128::from(BUILD_TIME_MULTIPLIER_SCALE))
        .min(u128::from(u64::MAX)) as u64,
    )
}

pub(crate) fn estimated_validator_replay_work(predicted_work: Duration) -> Duration {
    scaled_duration(predicted_work, VALIDATOR_REPLAY_WORK_SCALE)
}

/// Predicted proposal-return work for a payload budget check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PayloadBudgetEstimate {
    pub(crate) work_elapsed: Duration,
    pub(crate) predicted_work: Duration,
    pub(crate) proposer_work: Duration,
    pub(crate) validator_replay_work: Duration,
    pub(crate) marshal_persist: Duration,
    pub(crate) total_budgeted_work: Duration,
}

fn payload_budget_estimate(
    elapsed: Duration,
    idle_elapsed: Duration,
    proposal_timing_attached_elapsed: Option<Duration>,
    multiplier: u64,
    marshal_persist: MarshalPersistEstimator,
    block_size_bytes: usize,
) -> PayloadBudgetEstimate {
    let work_elapsed = elapsed.saturating_sub(idle_elapsed);
    let predicted_work = scaled_duration(work_elapsed, multiplier);
    let predicted_remaining_work = predicted_work.saturating_sub(work_elapsed);
    let proposer_work =
        proposal_timing_attached_elapsed.map_or(predicted_remaining_work, |attached_elapsed| {
            elapsed
                .saturating_sub(attached_elapsed)
                .saturating_add(predicted_remaining_work)
        });
    let validator_replay_work = estimated_validator_replay_work(predicted_work);
    let marshal_persist = marshal_persist.estimate(block_size_bytes);
    let total_budgeted_work = proposer_work
        .saturating_add(validator_replay_work)
        .saturating_add(marshal_persist)
        .saturating_add(marshal_persist);

    PayloadBudgetEstimate {
        work_elapsed,
        predicted_work,
        proposer_work,
        validator_replay_work,
        marshal_persist,
        total_budgeted_work,
    }
}

/// Returns the budget estimate when the shared proposer/validator budget is exhausted.
///
/// `elapsed` is wall-clock time spent in the builder so far. `idle_elapsed` is
/// the proposer-only time spent waiting for more transactions, which is not
/// replayed by validators.
/// `proposal_timing_attached_elapsed` is `None` before `handle_propose`
/// attaches timing. In that mode, already completed builder work does not delay
/// proposal return, but the remaining builder tail and validator replay still
/// reserve budget.
/// `budget` is the remaining consensus payload build budget. `block_size_bytes`
/// is the current encoded-size estimate used for marshal persistence.
///
/// The budget is not split into fixed leader/validator buckets. Instead, we
/// charge projected proposer work that can still delay proposal return, a
/// smaller validator replay reservation, and marshal persistence once for each
/// side.
pub(crate) fn payload_budget_exhausted(
    elapsed: Duration,
    idle_elapsed: Duration,
    proposal_timing_attached_elapsed: Option<Duration>,
    multiplier: u64,
    budget: Duration,
    marshal_persist: MarshalPersistEstimator,
    block_size_bytes: usize,
) -> Option<PayloadBudgetEstimate> {
    let estimate = payload_budget_estimate(
        elapsed,
        idle_elapsed,
        proposal_timing_attached_elapsed,
        multiplier,
        marshal_persist,
        block_size_bytes,
    );
    (estimate.total_budgeted_work >= budget).then_some(estimate)
}

/// Computes the observed total-work to tx-cutoff-work multiplier.
///
/// `work_at_tx_cutoff` is measured when pool transaction execution stops.
/// `total_work` is measured after finalization finishes. Their ratio captures
/// `builder_finish` without needing a separate fixed reserve.
pub(crate) fn observed_build_time_multiplier(
    total_work: Duration,
    work_at_tx_cutoff: Duration,
) -> Option<u64> {
    if work_at_tx_cutoff == Duration::ZERO {
        return None;
    }

    let multiplier = total_work
        .as_nanos()
        .saturating_mul(u128::from(BUILD_TIME_MULTIPLIER_SCALE))
        / work_at_tx_cutoff.as_nanos();
    Some(multiplier.min(u128::from(MAX_BUILD_TIME_MULTIPLIER)) as u64)
}

/// Updates the multiplier, immediately rising but slowly decaying.
pub(crate) fn decay_build_time_multiplier(current: u64, observed: u64) -> u64 {
    if observed >= current {
        observed
    } else {
        let decay = ((current - observed) / BUILD_TIME_MULTIPLIER_DECAY).max(1);
        current.saturating_sub(decay).max(observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_build_multiplier_tracks_tail_cost() {
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(135), Duration::from_millis(100)),
            Some(DEFAULT_BUILD_TIME_MULTIPLIER_SCALED)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(100), Duration::from_millis(100)),
            Some(1_000_000)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(250), Duration::from_millis(100)),
            Some(MAX_BUILD_TIME_MULTIPLIER)
        );
        assert_eq!(decay_build_time_multiplier(1_500_000, 1_300_000), 1_475_000);
    }

    #[test]
    fn payload_budget_accounts_for_leader_idle_once() {
        assert!(
            payload_budget_exhausted(
                Duration::from_millis(100),
                Duration::ZERO,
                Some(Duration::ZERO),
                1_350_000,
                Duration::from_millis(182),
                MarshalPersistEstimator::default(),
                0
            )
            .is_some()
        );
        assert!(
            payload_budget_exhausted(
                Duration::from_millis(100),
                Duration::ZERO,
                Some(Duration::ZERO),
                1_350_000,
                Duration::from_millis(183),
                MarshalPersistEstimator::default(),
                0
            )
            .is_none()
        );
        assert!(
            payload_budget_exhausted(
                Duration::from_millis(350),
                Duration::from_millis(250),
                Some(Duration::ZERO),
                1_350_000,
                Duration::from_millis(432),
                MarshalPersistEstimator::default(),
                0
            )
            .is_some()
        );
        assert!(
            payload_budget_exhausted(
                Duration::from_millis(350),
                Duration::from_millis(250),
                Some(Duration::ZERO),
                1_350_000,
                Duration::from_millis(433),
                MarshalPersistEstimator::default(),
                0
            )
            .is_none()
        );
    }

    #[test]
    fn payload_budget_accounts_for_marshal_persist_twice() {
        let marshal_persist = MarshalPersistEstimator::from_ns_per_byte(1_000);

        assert!(
            payload_budget_exhausted(
                Duration::from_millis(100),
                Duration::ZERO,
                Some(Duration::ZERO),
                1_350_000,
                Duration::from_millis(212),
                marshal_persist,
                15_000
            )
            .is_some()
        );
        assert!(
            payload_budget_exhausted(
                Duration::from_millis(100),
                Duration::ZERO,
                Some(Duration::ZERO),
                1_350_000,
                Duration::from_millis(212),
                marshal_persist,
                14_874
            )
            .is_none()
        );
    }

    #[test]
    fn payload_budget_before_propose_only_charges_remaining_builder_work() {
        let estimate = payload_budget_exhausted(
            Duration::from_millis(100),
            Duration::ZERO,
            None,
            1_350_000,
            Duration::from_millis(82),
            MarshalPersistEstimator::default(),
            0,
        )
        .expect("remaining builder tail plus validator replay exceeds budget");

        assert_eq!(estimate.work_elapsed, Duration::from_millis(100));
        assert_eq!(estimate.predicted_work, Duration::from_millis(135));
        assert_eq!(estimate.proposer_work, Duration::from_millis(35));
        assert_eq!(
            estimate.validator_replay_work,
            Duration::from_micros(47_250)
        );
        assert_eq!(estimate.total_budgeted_work, Duration::from_micros(82_250));

        assert!(
            payload_budget_exhausted(
                Duration::from_millis(100),
                Duration::ZERO,
                None,
                1_350_000,
                Duration::from_millis(83),
                MarshalPersistEstimator::default(),
                0,
            )
            .is_none()
        );
    }

    #[test]
    fn payload_budget_after_propose_charges_post_propose_elapsed() {
        let estimate = payload_budget_exhausted(
            Duration::from_millis(120),
            Duration::ZERO,
            Some(Duration::from_millis(100)),
            1_000_000,
            Duration::from_millis(62),
            MarshalPersistEstimator::default(),
            0,
        )
        .expect("post-propose work plus validator replay reaches budget");

        assert_eq!(estimate.predicted_work, Duration::from_millis(120));
        assert_eq!(estimate.proposer_work, Duration::from_millis(20));
        assert_eq!(estimate.validator_replay_work, Duration::from_millis(42));
        assert_eq!(estimate.total_budgeted_work, Duration::from_millis(62));

        assert!(
            payload_budget_exhausted(
                Duration::from_millis(120),
                Duration::ZERO,
                Some(Duration::from_millis(100)),
                1_000_000,
                Duration::from_millis(63),
                MarshalPersistEstimator::default(),
                0,
            )
            .is_none()
        );
    }

    #[test]
    fn build_multiplier_scales_decimal_values() {
        assert_eq!(
            scaled_build_time_multiplier(DEFAULT_BUILD_TIME_MULTIPLIER),
            DEFAULT_BUILD_TIME_MULTIPLIER_SCALED
        );
        assert_eq!(SPECULATIVE_BAL_BUILD_TIME_MULTIPLIER, 1_100_000);
    }
}
