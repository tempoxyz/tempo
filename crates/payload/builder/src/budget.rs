//! Budget helpers for deciding when to stop executing pool transactions.
//!
//! The builder can stop transaction execution, but it still has to finish
//! non-interruptible work like state root calculation. These helpers learn the
//! relation between tx execution cutoff time and total builder time.

use std::time::Duration;

/// Fixed-point scale for build time multipliers.
pub(crate) const BUILD_TIME_MULTIPLIER_SCALE: u64 = 1_000_000;
/// Initial estimate of total build time divided by elapsed time at tx cutoff.
pub(crate) const DEFAULT_BUILD_TIME_MULTIPLIER: u64 = 1_350_000;
/// Lower bound for the learned build time multiplier.
const MIN_BUILD_TIME_MULTIPLIER: u64 = 1_200_000;
/// Upper bound for the learned build time multiplier.
const MAX_BUILD_TIME_MULTIPLIER: u64 = 1_700_000;
/// How quickly the multiplier decays when observed builds get cheaper.
const BUILD_TIME_MULTIPLIER_DECAY: u64 = 8;

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
    Some(
        multiplier
            .clamp(
                MIN_BUILD_TIME_MULTIPLIER as u128,
                MAX_BUILD_TIME_MULTIPLIER as u128,
            )
            .try_into()
            .expect("clamped multiplier fits u64"),
    )
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
    fn adaptive_build_multiplier_is_conservative() {
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(135), Duration::from_millis(100)),
            Some(1_350_000)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(105), Duration::from_millis(100)),
            Some(MIN_BUILD_TIME_MULTIPLIER)
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
}
