//! Budget helpers for deciding when to stop executing pool transactions.
//!
//! The builder can stop transaction execution, but it still has to finish
//! non-interruptible finalization work like state hashing, state root updates,
//! block assembly, and marshal persistence. These helpers learn the relation
//! between tx execution cutoff time, total replayable build work, validator
//! validation feedback, and the size-dependent cost of persisting large blocks
//! through consensus.
//!
//! The decision model is:
//! `leader_idle + predicted_builder_work + predicted_validator_work + 2 * marshal_persist >= budget`.
//! Idle waiting only happens on the proposer. Builder work is projected from the
//! current build, while validator work uses feedback from previously validated
//! blocks when available and otherwise falls back to the builder projection.

use std::time::Duration;

#[cfg(test)]
use tempo_payload_types::ValidatorValidationEstimator;
use tempo_payload_types::{
    MarshalPersistEstimator, ValidatorValidationEstimate, ValidatorValidationShape,
};

/// Fixed-point scale for build time multipliers.
pub(crate) const BUILD_TIME_MULTIPLIER_SCALE: u64 = 1_000_000;
#[cfg(test)]
const DEFAULT_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_350_000;
const MAX_BUILD_TIME_MULTIPLIER: u64 = 1_700_000;
/// How quickly the multiplier decays when observed builds get cheaper.
const BUILD_TIME_MULTIPLIER_DECAY: u64 = 8;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValidatorValidationSource {
    Feedback,
    Fallback,
}

impl ValidatorValidationSource {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Feedback => "feedback",
            Self::Fallback => "fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PayloadBudgetDecision {
    pub(crate) elapsed: Duration,
    pub(crate) idle_elapsed: Duration,
    pub(crate) work_elapsed: Duration,
    pub(crate) predicted_builder_work: Duration,
    pub(crate) predicted_validator_work: Duration,
    pub(crate) validator_validation_source: ValidatorValidationSource,
    pub(crate) marshal_persist: Duration,
    pub(crate) total_reserved: Duration,
    pub(crate) budget: Duration,
}

impl PayloadBudgetDecision {
    pub(crate) fn exhausted(self) -> bool {
        self.total_reserved >= self.budget
    }
}

/// Builds the shared proposer/validator budget decision for the current payload.
///
/// `elapsed` is wall-clock time spent in the builder so far. `idle_elapsed` is
/// the proposer-only time spent waiting for more transactions, which is not
/// replayed by validators and therefore counts once.
/// `budget` is the remaining consensus payload build budget.
/// `validator_validation` is an estimate of validator-side replay work from
/// previously validated proposals. If absent, or if it cannot estimate the
/// current block shape, the conservative builder-work projection is reused for
/// the validator side.
/// `current_validation_shape` describes the block currently being assembled.
///
/// The budget is not split into fixed leader/validator buckets. Instead, we
/// charge proposer idle once, projected builder work once, learned validator
/// work once, and marshal persistence once for each side.
pub(crate) fn payload_budget_decision(
    elapsed: Duration,
    idle_elapsed: Duration,
    multiplier: u64,
    budget: Duration,
    marshal_persist: MarshalPersistEstimator,
    validator_validation: Option<ValidatorValidationEstimate>,
    current_validation_shape: ValidatorValidationShape,
) -> PayloadBudgetDecision {
    let work_elapsed = elapsed.saturating_sub(idle_elapsed);
    let predicted_builder_work = scaled_duration(work_elapsed, multiplier);
    let validator_validation_estimate =
        validator_validation.and_then(|estimate| estimate.estimate(current_validation_shape));
    let (predicted_validator_work, validator_validation_source) =
        if let Some(validator_validation_estimate) = validator_validation_estimate {
            (
                validator_validation_estimate,
                ValidatorValidationSource::Feedback,
            )
        } else {
            (predicted_builder_work, ValidatorValidationSource::Fallback)
        };
    let marshal_persist = marshal_persist.estimate(current_validation_shape.block_size_bytes());
    let total_reserved = idle_elapsed
        .saturating_add(predicted_builder_work)
        .saturating_add(predicted_validator_work)
        .saturating_add(marshal_persist)
        .saturating_add(marshal_persist);
    PayloadBudgetDecision {
        elapsed,
        idle_elapsed,
        work_elapsed,
        predicted_builder_work,
        predicted_validator_work,
        validator_validation_source,
        marshal_persist,
        total_reserved,
        budget,
    }
}

#[cfg(test)]
fn payload_budget_exhausted(
    elapsed: Duration,
    idle_elapsed: Duration,
    multiplier: u64,
    budget: Duration,
    marshal_persist: MarshalPersistEstimator,
    validator_validation: Option<ValidatorValidationEstimate>,
    current_validation_shape: ValidatorValidationShape,
) -> bool {
    payload_budget_decision(
        elapsed,
        idle_elapsed,
        multiplier,
        budget,
        marshal_persist,
        validator_validation,
        current_validation_shape,
    )
    .exhausted()
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

    fn validator_validation_estimate(
        shape: ValidatorValidationShape,
        elapsed: Duration,
    ) -> Option<ValidatorValidationEstimate> {
        let mut estimator = ValidatorValidationEstimator::default();
        estimator.observe(1, shape, elapsed);
        estimator.estimate()
    }

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
        assert!(payload_budget_exhausted(
            Duration::from_millis(100),
            Duration::ZERO,
            1_350_000,
            Duration::from_millis(270),
            MarshalPersistEstimator::default(),
            None,
            ValidatorValidationShape::default(),
        ));
        assert!(!payload_budget_exhausted(
            Duration::from_millis(100),
            Duration::ZERO,
            1_350_000,
            Duration::from_millis(271),
            MarshalPersistEstimator::default(),
            None,
            ValidatorValidationShape::default(),
        ));
        assert!(payload_budget_exhausted(
            Duration::from_millis(350),
            Duration::from_millis(250),
            1_350_000,
            Duration::from_millis(520),
            MarshalPersistEstimator::default(),
            None,
            ValidatorValidationShape::default(),
        ));
        assert!(!payload_budget_exhausted(
            Duration::from_millis(350),
            Duration::from_millis(250),
            1_350_000,
            Duration::from_millis(521),
            MarshalPersistEstimator::default(),
            None,
            ValidatorValidationShape::default(),
        ));
    }

    #[test]
    fn payload_budget_uses_validator_feedback_when_available() {
        let shape = ValidatorValidationShape::new(0, 100, 0);
        let validator_validation = validator_validation_estimate(shape, Duration::from_millis(80));
        let decision = payload_budget_decision(
            Duration::from_millis(100),
            Duration::ZERO,
            1_350_000,
            Duration::from_millis(215),
            MarshalPersistEstimator::default(),
            validator_validation,
            shape,
        );

        assert_eq!(
            decision.validator_validation_source,
            ValidatorValidationSource::Feedback
        );
        assert_eq!(decision.predicted_builder_work, Duration::from_millis(135));
        assert_eq!(decision.predicted_validator_work, Duration::from_millis(80));
        assert_eq!(decision.total_reserved, Duration::from_millis(215));

        assert!(payload_budget_exhausted(
            Duration::from_millis(100),
            Duration::ZERO,
            1_350_000,
            Duration::from_millis(215),
            MarshalPersistEstimator::default(),
            validator_validation,
            shape,
        ));
        assert!(!payload_budget_exhausted(
            Duration::from_millis(100),
            Duration::ZERO,
            1_350_000,
            Duration::from_millis(216),
            MarshalPersistEstimator::default(),
            validator_validation,
            shape,
        ));
    }

    #[test]
    fn payload_budget_uses_absolute_validator_feedback_for_current_block() {
        let validator_validation = validator_validation_estimate(
            ValidatorValidationShape::new(0, 100, 0),
            Duration::from_millis(100),
        );

        assert!(payload_budget_exhausted(
            Duration::from_millis(100),
            Duration::ZERO,
            1_350_000,
            Duration::from_millis(235),
            MarshalPersistEstimator::default(),
            validator_validation,
            ValidatorValidationShape::new(0, 50, 0),
        ));
        assert!(!payload_budget_exhausted(
            Duration::from_millis(100),
            Duration::ZERO,
            1_350_000,
            Duration::from_millis(236),
            MarshalPersistEstimator::default(),
            validator_validation,
            ValidatorValidationShape::new(0, 50, 0),
        ));
    }

    #[test]
    fn payload_budget_scales_validator_feedback_for_larger_current_block() {
        let validator_validation = validator_validation_estimate(
            ValidatorValidationShape::new(0, 100, 10),
            Duration::from_millis(100),
        );
        let decision = payload_budget_decision(
            Duration::from_millis(100),
            Duration::ZERO,
            1_350_000,
            Duration::from_millis(335),
            MarshalPersistEstimator::default(),
            validator_validation,
            ValidatorValidationShape::new(0, 200, 10),
        );

        assert_eq!(
            decision.validator_validation_source,
            ValidatorValidationSource::Feedback
        );
        assert_eq!(
            decision.predicted_validator_work,
            Duration::from_millis(200)
        );
        assert_eq!(decision.total_reserved, Duration::from_millis(335));
        assert!(decision.exhausted());
    }

    #[test]
    fn payload_budget_accounts_for_marshal_persist_twice() {
        let marshal_persist = MarshalPersistEstimator::from_ns_per_byte(1_000);

        assert!(payload_budget_exhausted(
            Duration::from_millis(100),
            Duration::ZERO,
            1_350_000,
            Duration::from_millis(300),
            marshal_persist,
            None,
            ValidatorValidationShape::new(15_000, 0, 0),
        ));
        assert!(!payload_budget_exhausted(
            Duration::from_millis(100),
            Duration::ZERO,
            1_350_000,
            Duration::from_millis(300),
            marshal_persist,
            None,
            ValidatorValidationShape::new(14_999, 0, 0),
        ));
    }

    #[test]
    fn build_multiplier_scales_decimal_values() {
        assert_eq!(
            scaled_build_time_multiplier(DEFAULT_BUILD_TIME_MULTIPLIER),
            DEFAULT_BUILD_TIME_MULTIPLIER_SCALED
        );
    }
}
