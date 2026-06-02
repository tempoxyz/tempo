use std::{
    collections::VecDeque,
    sync::{
        LazyLock, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tracing::debug;

/// How quickly the learned marshal persistence rate decays when blocks get cheaper.
const RATE_DECAY: u64 = 8;
/// Ignore tiny blocks so fixed archive overhead does not become a large-block byte cost.
const MIN_SAMPLE_BYTES: usize = 128 * 1024;
/// Number of recent successful EL validation timings to retain for the P75 estimate.
const VALIDATOR_VALIDATION_SAMPLE_WINDOW: usize = 64;

static MARSHAL_PERSIST_NS_PER_BYTE: AtomicU64 = AtomicU64::new(0);
static VALIDATOR_VALIDATION_SAMPLES: LazyLock<Mutex<VecDeque<u64>>> =
    LazyLock::new(|| Mutex::new(VecDeque::with_capacity(VALIDATOR_VALIDATION_SAMPLE_WINDOW)));

/// Returns the current estimate of consensus marshal persistence cost.
///
/// This is a point-in-time snapshot. Callers use it before building or
/// returning a proposal so the same estimate is applied consistently to that
/// decision.
pub fn marshal_persist_estimate() -> MarshalPersistEstimator {
    MarshalPersistEstimator::from_ns_per_byte(MARSHAL_PERSIST_NS_PER_BYTE.load(Ordering::Relaxed))
}

/// Returns the current P75 estimate for execution-layer block validation work.
///
/// `None` means this node has not yet observed any successful validations. Callers
/// should fall back to their conservative validator-work estimate in that case.
pub fn validator_validation_estimate() -> Option<Duration> {
    let samples = VALIDATOR_VALIDATION_SAMPLES.lock().ok()?;
    validator_validation_estimate_from_samples(&samples)
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

/// Records local time spent validating a block through the execution layer.
///
/// The estimate intentionally uses the P75 of recent successful validations. This
/// is aggressive enough to reclaim budget from faster validator replay paths while
/// avoiding a single best-case block dominating the next build.
pub fn observe_validator_validation(elapsed: Duration) {
    if elapsed == Duration::ZERO {
        return;
    }

    let elapsed_nanos = elapsed.as_nanos().min(u128::from(u64::MAX)) as u64;
    let Ok(mut samples) = VALIDATOR_VALIDATION_SAMPLES.lock() else {
        return;
    };

    if samples.len() == VALIDATOR_VALIDATION_SAMPLE_WINDOW {
        samples.pop_front();
    }
    samples.push_back(elapsed_nanos);

    debug!(
        elapsed = ?elapsed,
        estimated_p75 = ?validator_validation_estimate_from_samples(&samples),
        samples = samples.len(),
        "updated validator validation estimate"
    );
}

fn validator_validation_estimate_from_samples(samples: &VecDeque<u64>) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }

    let mut sorted = samples.iter().copied().collect::<Vec<_>>();
    sorted.sort_unstable();
    let index = ((sorted.len() * 3).div_ceil(4)).saturating_sub(1);
    Some(Duration::from_nanos(sorted[index]))
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
    fn validator_validation_estimate_uses_recent_p75() {
        let mut samples = VecDeque::from([10, 20, 30, 40]);
        assert_eq!(
            validator_validation_estimate_from_samples(&samples),
            Some(Duration::from_nanos(30))
        );

        samples = (1..=VALIDATOR_VALIDATION_SAMPLE_WINDOW as u64).collect();
        samples.pop_front();
        samples.push_back(10_000);
        assert_eq!(
            validator_validation_estimate_from_samples(&samples),
            Some(Duration::from_nanos(49))
        );
    }
}
