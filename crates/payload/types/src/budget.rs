use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tracing::debug;

/// How quickly the learned marshal persistence rate decays when blocks get cheaper.
const RATE_DECAY: u64 = 8;
/// Ignore tiny blocks so fixed archive overhead does not become a large-block byte cost.
const MIN_SAMPLE_BYTES: usize = 128 * 1024;
/// Number of recent successful EL validation timings to retain.
const VALIDATOR_VALIDATION_SAMPLE_WINDOW: usize = 64;
/// Fixed-point scale for validation shape multipliers.
const VALIDATOR_VALIDATION_SHAPE_SCALE: u128 = 1_000_000;
/// Minimum share of recent P90 validation time to reserve for builder pacing.
const VALIDATOR_VALIDATION_P90_FLOOR_SCALE: u128 = 900_000;

static MARSHAL_PERSIST_NS_PER_BYTE: AtomicU64 = AtomicU64::new(0);

/// Returns the current estimate of consensus marshal persistence cost.
///
/// This is a point-in-time snapshot. Callers use it before building or
/// returning a proposal so the same estimate is applied consistently to that
/// decision.
pub fn marshal_persist_estimate() -> MarshalPersistEstimator {
    MarshalPersistEstimator::from_ns_per_byte(MARSHAL_PERSIST_NS_PER_BYTE.load(Ordering::Relaxed))
}

/// Records time spent persisting an encoded block through consensus marshal.
///
/// The observation is stored as nanoseconds per encoded block byte. Large
/// blocks teach future build and return budgets how much size-dependent
/// persistence time to reserve for both proposers and validators.
/// Consensus records this from local `marshal.proposed` time after persisting a
/// proposal.
pub fn observe_marshal_persist(block_size_bytes: usize, elapsed: Duration) {
    if block_size_bytes < MIN_SAMPLE_BYTES || elapsed == Duration::ZERO {
        return;
    }

    let block_size = block_size_bytes as u128;
    let observed = elapsed
        .as_nanos()
        .saturating_add(block_size.saturating_sub(1))
        / block_size;
    let observed = observed.min(u128::from(u64::MAX)) as u64;

    let _ =
        MARSHAL_PERSIST_NS_PER_BYTE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(if current == 0 || observed >= current {
                observed
            } else {
                let decay = ((current - observed) / RATE_DECAY).max(1);
                current.saturating_sub(decay).max(observed)
            })
        });
    debug!(
        block_size_bytes,
        elapsed = ?elapsed,
        observed_ns_per_byte = observed,
        estimated_ns_per_byte = MARSHAL_PERSIST_NS_PER_BYTE.load(Ordering::Relaxed),
        "updated marshal persistence estimate"
    );
}

/// Point-in-time marshal persistence cost per encoded block byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MarshalPersistEstimator {
    ns_per_byte: u64,
}

impl MarshalPersistEstimator {
    /// Creates an estimator from a raw nanoseconds-per-byte rate.
    pub fn from_ns_per_byte(ns_per_byte: u64) -> Self {
        Self { ns_per_byte }
    }

    /// Estimates marshal persistence time for an encoded block size.
    pub fn estimate(self, block_size_bytes: usize) -> Duration {
        let nanos = u128::from(self.ns_per_byte).saturating_mul(block_size_bytes as u128);
        Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
    }
}

/// Current or observed block shape used to estimate validator validation cost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidatorValidationShape {
    gas_used: u64,
    transaction_count: usize,
}

impl ValidatorValidationShape {
    /// Creates a validation shape from gas and transaction count.
    pub fn new(gas_used: u64, transaction_count: usize) -> Self {
        Self {
            gas_used,
            transaction_count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValidatorValidationSample {
    shape: ValidatorValidationShape,
    elapsed: Duration,
}

fn percentile<T: Copy + Ord>(
    values: impl Iterator<Item = T>,
    numerator: usize,
    denominator: usize,
) -> Option<T> {
    debug_assert!(numerator > 0);
    debug_assert!(denominator > 0);
    debug_assert!(numerator <= denominator);

    let mut sorted = values.collect::<Vec<_>>();
    if sorted.is_empty() {
        return None;
    }

    sorted.sort_unstable();
    let index = ((sorted.len() * numerator).div_ceil(denominator)).saturating_sub(1);
    Some(sorted[index])
}

fn p50<T: Copy + Ord>(values: impl Iterator<Item = T>) -> Option<T> {
    percentile(values, 1, 2)
}

fn p90<T: Copy + Ord>(values: impl Iterator<Item = T>) -> Option<T> {
    percentile(values, 9, 10)
}

fn scale_above_baseline(current: u128, baseline: u128) -> Option<u128> {
    if current == 0 {
        return Some(VALIDATOR_VALIDATION_SHAPE_SCALE);
    }
    if baseline == 0 {
        return None;
    }
    if current <= baseline {
        return Some(VALIDATOR_VALIDATION_SHAPE_SCALE);
    }

    Some(current.saturating_mul(VALIDATOR_VALIDATION_SHAPE_SCALE) / baseline)
}

fn scale_duration(elapsed: Duration, scale: u128) -> Duration {
    let nanos = elapsed
        .as_nanos()
        .saturating_mul(scale)
        .saturating_add(VALIDATOR_VALIDATION_SHAPE_SCALE.saturating_sub(1))
        / VALIDATOR_VALIDATION_SHAPE_SCALE;
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

/// Point-in-time validation cost estimate from recent proposal validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidatorValidationEstimate {
    elapsed: Duration,
    p90_gas_used: u64,
    p90_transaction_count: usize,
}

impl ValidatorValidationEstimate {
    /// Estimates validator-side validation time for the supplied block shape.
    ///
    /// Recent elapsed validation feedback is the floor so faster replay feedback
    /// still reclaims budget without shrinking smaller current blocks. If the
    /// current block carries more gas or transactions than the recent P90 shape,
    /// the estimate scales up by that excess. Encoded bytes are intentionally
    /// not used here because BAL sidecar bytes are charged through marshal
    /// persistence, not execution-layer validation work.
    pub fn estimate(self, shape: ValidatorValidationShape) -> Option<Duration> {
        if self.elapsed == Duration::ZERO {
            return None;
        }

        let scale = [
            scale_above_baseline(u128::from(shape.gas_used), u128::from(self.p90_gas_used)),
            scale_above_baseline(
                shape.transaction_count as u128,
                self.p90_transaction_count as u128,
            ),
        ]
        .into_iter()
        .flatten()
        .max()?;
        Some(scale_duration(self.elapsed, scale))
    }
}

/// Tracks recent local execution-layer block validation durations.
///
/// The estimate uses recent successful proposal validations as an absolute
/// floor, then scales that floor up when the current block exceeds the recent
/// P90 gas or transaction count. This avoids combining independent per-unit
/// rates from differently shaped blocks while still reserving validator
/// headroom when the builder grows beyond the shapes that produced the feedback.
#[derive(Clone, Debug, Default)]
pub struct ValidatorValidationEstimator {
    samples: BTreeMap<u64, ValidatorValidationSample>,
}

impl ValidatorValidationEstimator {
    /// Records local time spent validating a block through the execution layer.
    pub fn observe(&mut self, sample_id: u64, shape: ValidatorValidationShape, elapsed: Duration) {
        if elapsed == Duration::ZERO {
            return;
        }

        self.samples
            .insert(sample_id, ValidatorValidationSample { shape, elapsed });
        while self.samples.len() > VALIDATOR_VALIDATION_SAMPLE_WINDOW {
            self.samples.pop_first();
        }

        debug!(
            sample_id,
            shape = ?shape,
            elapsed = ?elapsed,
            estimate = ?self.estimate(),
            samples = self.samples.len(),
            "updated validator validation estimate"
        );
    }

    /// Returns the current estimate for execution-layer block validation work.
    ///
    /// `None` means this node has not yet observed any successful validations.
    /// Callers should fall back to their conservative validator-work estimate in
    /// that case.
    pub fn estimate(&self) -> Option<ValidatorValidationEstimate> {
        let p50_elapsed = p50(self.samples.values().map(|sample| sample.elapsed))?;
        let p90_elapsed = p90(self.samples.values().map(|sample| sample.elapsed))?;
        let p90_floor = scale_duration(p90_elapsed, VALIDATOR_VALIDATION_P90_FLOOR_SCALE);
        Some(ValidatorValidationEstimate {
            elapsed: p50_elapsed.max(p90_floor),
            p90_gas_used: p90(self.samples.values().map(|sample| sample.shape.gas_used))
                .unwrap_or_default(),
            p90_transaction_count: p90(self
                .samples
                .values()
                .map(|sample| sample.shape.transaction_count))
            .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn estimate_with_sample(
        sample_shape: ValidatorValidationShape,
        current_shape: ValidatorValidationShape,
    ) -> Option<Duration> {
        let mut estimator = ValidatorValidationEstimator::default();
        estimator.observe(1, sample_shape, Duration::from_millis(100));
        estimator
            .estimate()
            .and_then(|estimate| estimate.estimate(current_shape))
    }

    #[test]
    fn observes_large_blocks_and_ignores_tiny_samples() {
        MARSHAL_PERSIST_NS_PER_BYTE.store(0, Ordering::Relaxed);
        observe_marshal_persist(MIN_SAMPLE_BYTES, Duration::from_millis(13));

        assert_eq!(
            marshal_persist_estimate().estimate(MIN_SAMPLE_BYTES),
            Duration::from_nanos(13_107_200)
        );

        observe_marshal_persist(MIN_SAMPLE_BYTES - 1, Duration::from_millis(1));
        observe_marshal_persist(1_000_000, Duration::ZERO);

        assert_eq!(
            marshal_persist_estimate().estimate(MIN_SAMPLE_BYTES),
            Duration::from_nanos(13_107_200)
        );
    }

    #[test]
    fn validator_validation_estimate_uses_tail_discounted_recent_elapsed() {
        let mut estimator = ValidatorValidationEstimator::default();
        let sample_shape = ValidatorValidationShape::new(100, 0);
        let current_shape = ValidatorValidationShape::new(100, 0);
        for (sample_id, elapsed) in [(1, 10), (2, 20), (3, 30), (4, 40)] {
            estimator.observe(sample_id, sample_shape, Duration::from_nanos(elapsed));
        }
        assert_eq!(
            estimator
                .estimate()
                .and_then(|estimate| estimate.estimate(current_shape)),
            Some(Duration::from_nanos(36))
        );

        estimator = ValidatorValidationEstimator::default();
        for elapsed in 1..=VALIDATOR_VALIDATION_SAMPLE_WINDOW as u64 {
            estimator.observe(
                elapsed,
                ValidatorValidationShape::new(1, 0),
                Duration::from_nanos(elapsed),
            );
        }
        estimator.observe(
            10_000,
            ValidatorValidationShape::new(1, 0),
            Duration::from_nanos(10_000),
        );
        assert_eq!(
            estimator
                .estimate()
                .and_then(|estimate| estimate.estimate(ValidatorValidationShape::new(1, 0))),
            Some(Duration::from_nanos(54))
        );
    }

    #[test]
    fn validator_validation_estimate_does_not_scale_down() {
        assert_eq!(
            estimate_with_sample(
                ValidatorValidationShape::new(1_000, 10),
                ValidatorValidationShape::new(400, 4)
            ),
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn validator_validation_estimate_scales_up_by_gas_or_transactions() {
        let sample = ValidatorValidationShape::new(1_000, 10);

        assert_eq!(
            estimate_with_sample(sample, ValidatorValidationShape::new(1_500, 10)),
            Some(Duration::from_millis(150))
        );
        assert_eq!(
            estimate_with_sample(sample, ValidatorValidationShape::new(1_000, 15)),
            Some(Duration::from_millis(150))
        );
    }

    #[test]
    fn validator_validation_estimate_requires_non_empty_shape_feedback() {
        let empty = ValidatorValidationShape::new(0, 0);

        assert_eq!(
            estimate_with_sample(empty, ValidatorValidationShape::new(0, 0)),
            Some(Duration::from_millis(100))
        );
        assert_eq!(
            estimate_with_sample(empty, ValidatorValidationShape::new(1_000, 10)),
            None
        );
    }
}
