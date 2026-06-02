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
/// Number of recent successful EL validation timings to retain for the P90 estimate.
const VALIDATOR_VALIDATION_SAMPLE_WINDOW: usize = 64;

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
    block_size_bytes: usize,
    gas_used: u64,
    transaction_count: usize,
}

impl ValidatorValidationShape {
    /// Creates a validation shape from encoded size, gas, and transaction count.
    pub fn new(block_size_bytes: usize, gas_used: u64, transaction_count: usize) -> Self {
        Self {
            block_size_bytes,
            gas_used,
            transaction_count,
        }
    }

    /// Returns the encoded block size in bytes.
    pub fn block_size_bytes(self) -> usize {
        self.block_size_bytes
    }

    /// Returns gas used by the block.
    pub fn gas_used(self) -> u64 {
        self.gas_used
    }

    /// Returns the number of transactions in the block.
    pub fn transaction_count(self) -> usize {
        self.transaction_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValidatorValidationSample {
    elapsed: Duration,
}

fn p90_duration(durations: impl Iterator<Item = Duration>) -> Option<Duration> {
    let mut sorted = durations.collect::<Vec<_>>();
    if sorted.is_empty() {
        return None;
    }

    sorted.sort_unstable();
    let index = ((sorted.len() * 9).div_ceil(10)).saturating_sub(1);
    Some(sorted[index])
}

/// Point-in-time validation cost estimate from recent proposal validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidatorValidationEstimate {
    p90_elapsed: Duration,
}

impl ValidatorValidationEstimate {
    /// Estimates validator-side validation time for the supplied block shape.
    ///
    /// Recent e2e payloads are built from the same saturated workload, so the
    /// absolute local proposal-validation P90 is a better budget input than the
    /// max of independent per-byte, per-gas, and per-transaction P90 rates. The
    /// caller still passes shape for API symmetry and observability, but the
    /// estimate intentionally does not scale down or up by shape.
    pub fn estimate(self, _shape: ValidatorValidationShape) -> Option<Duration> {
        (self.p90_elapsed > Duration::ZERO).then_some(self.p90_elapsed)
    }
}

/// Tracks recent local execution-layer block validation durations.
///
/// The estimate intentionally uses the absolute P90 of recent successful
/// proposal validations. This still reclaims budget from faster validator replay
/// paths while reserving more headroom for tail validation costs than a
/// median-like estimate. It avoids inflating current-block validation via the max
/// of independent per-unit rates from differently shaped historical blocks.
#[derive(Clone, Debug)]
pub struct ValidatorValidationEstimator {
    samples: BTreeMap<u64, ValidatorValidationSample>,
}

impl Default for ValidatorValidationEstimator {
    fn default() -> Self {
        Self {
            samples: BTreeMap::new(),
        }
    }
}

impl ValidatorValidationEstimator {
    /// Records local time spent validating a block through the execution layer.
    pub fn observe(&mut self, sample_id: u64, shape: ValidatorValidationShape, elapsed: Duration) {
        if elapsed == Duration::ZERO {
            return;
        }

        self.samples
            .insert(sample_id, ValidatorValidationSample { elapsed });
        while self.samples.len() > VALIDATOR_VALIDATION_SAMPLE_WINDOW {
            self.samples.pop_first();
        }

        debug!(
            sample_id,
            shape = ?shape,
            elapsed = ?elapsed,
            estimated_p90 = ?self.estimate(),
            samples = self.samples.len(),
            "updated validator validation estimate"
        );
    }

    /// Returns the current P90 estimate for execution-layer block validation work.
    ///
    /// `None` means this node has not yet observed any successful validations.
    /// Callers should fall back to their conservative validator-work estimate in
    /// that case.
    pub fn estimate(&self) -> Option<ValidatorValidationEstimate> {
        p90_duration(self.samples.values().map(|sample| sample.elapsed))
            .map(|p90_elapsed| ValidatorValidationEstimate { p90_elapsed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn validator_validation_estimate_uses_recent_p90() {
        let mut estimator = ValidatorValidationEstimator::default();
        let sample_shape = ValidatorValidationShape::new(0, 100, 0);
        let current_shape = ValidatorValidationShape::new(0, 100, 0);
        for (sample_id, elapsed) in [(1, 10), (2, 20), (3, 30), (4, 40)] {
            estimator.observe(sample_id, sample_shape, Duration::from_nanos(elapsed));
        }
        assert_eq!(
            estimator
                .estimate()
                .and_then(|estimate| estimate.estimate(current_shape)),
            Some(Duration::from_nanos(40))
        );

        estimator = ValidatorValidationEstimator::default();
        for elapsed in 1..=VALIDATOR_VALIDATION_SAMPLE_WINDOW as u64 {
            estimator.observe(
                elapsed,
                ValidatorValidationShape::new(0, 1, 0),
                Duration::from_nanos(elapsed),
            );
        }
        estimator.observe(
            10_000,
            ValidatorValidationShape::new(0, 1, 0),
            Duration::from_nanos(10_000),
        );
        assert_eq!(
            estimator
                .estimate()
                .and_then(|estimate| estimate.estimate(ValidatorValidationShape::new(0, 1, 0))),
            Some(Duration::from_nanos(59))
        );
    }

    #[test]
    fn validator_validation_estimate_uses_absolute_recent_validation_time() {
        let mut estimator = ValidatorValidationEstimator::default();
        estimator.observe(
            1,
            ValidatorValidationShape::new(0, 1_000, 0),
            Duration::from_millis(100),
        );

        assert_eq!(
            estimator
                .estimate()
                .and_then(|estimate| estimate.estimate(ValidatorValidationShape::new(0, 400, 0))),
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn validator_validation_estimate_replaces_duplicate_sample_ids() {
        let mut estimator = ValidatorValidationEstimator::default();
        estimator.observe(
            10,
            ValidatorValidationShape::new(0, 1, 0),
            Duration::from_nanos(100),
        );
        estimator.observe(
            10,
            ValidatorValidationShape::new(0, 1, 0),
            Duration::from_nanos(200),
        );

        assert_eq!(estimator.samples.len(), 1);
        assert_eq!(
            estimator
                .estimate()
                .and_then(|estimate| estimate.estimate(ValidatorValidationShape::new(0, 1, 0))),
            Some(Duration::from_nanos(200))
        );
    }
}
