//! Budget helpers for deciding when to stop executing pool transactions.
//!
//! The builder can stop transaction execution, but it still has to finish
//! non-interruptible finalization work like state hashing, state root updates,
//! and block assembly. These helpers learn the relation between tx execution
//! cutoff time and total builder time.

use std::time::Duration;

/// Fixed-point scale for build time multipliers.
pub(crate) const BUILD_TIME_MULTIPLIER_SCALE: u64 = 1_000_000;
#[cfg(test)]
const DEFAULT_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_350_000;
const MAX_BUILD_TIME_MULTIPLIER: u64 = 1_700_000;
/// How quickly the multiplier decays when observed builds get cheaper.
const BUILD_TIME_MULTIPLIER_DECAY: u64 = 8;

/// Initial estimate of total build time divided by elapsed time at tx cutoff.
pub const DEFAULT_BUILD_TIME_MULTIPLIER: f64 = 1.35;

/// Converts a human-readable multiplier into the fixed-point representation.
pub(crate) fn scaled_build_time_multiplier(multiplier: f64) -> u64 {
    assert!(
        multiplier.is_finite() && multiplier >= 1.0,
        "build time multiplier must be finite and >= 1.0"
    );

    (multiplier * BUILD_TIME_MULTIPLIER_SCALE as f64).round() as u64
}

/// Returns true when the multiplier-adjusted elapsed time has exhausted `budget`.
pub(crate) fn scaled_elapsed_exceeds_budget(
    elapsed: Duration,
    multiplier: u64,
    budget: Duration,
) -> bool {
    elapsed.as_nanos().saturating_mul(multiplier as u128) / BUILD_TIME_MULTIPLIER_SCALE as u128
        >= budget.as_nanos()
}

/// Computes the observed total-build to tx-cutoff multiplier.
pub(crate) fn observed_build_time_multiplier(
    total: Duration,
    elapsed_at_tx_cutoff: Duration,
) -> Option<u64> {
    if elapsed_at_tx_cutoff == Duration::ZERO {
        return None;
    }

    let multiplier = total
        .as_nanos()
        .saturating_mul(BUILD_TIME_MULTIPLIER_SCALE as u128)
        / elapsed_at_tx_cutoff.as_nanos();
    Some(multiplier.min(MAX_BUILD_TIME_MULTIPLIER as u128) as u64)
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
    fn scaled_elapsed_compares_against_budget() {
        assert!(scaled_elapsed_exceeds_budget(
            Duration::from_millis(100),
            1_350_000,
            Duration::from_millis(134)
        ));
        assert!(!scaled_elapsed_exceeds_budget(
            Duration::from_millis(100),
            1_350_000,
            Duration::from_millis(136)
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
