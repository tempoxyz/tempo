//! Budget helpers for deciding when to stop executing pool transactions.
//!
//! The builder can stop transaction execution, but it still has to finish
//! non-interruptible finalization work like state hashing, state root updates,
//! and block assembly. These helpers learn the relation between tx execution
//! cutoff time and total builder time.

use std::{fmt, str::FromStr, time::Duration};

/// Fixed-point scale for build time multipliers.
pub(crate) const BUILD_TIME_MULTIPLIER_SCALE: u64 = 1_000_000;
const DEFAULT_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_350_000;
const MAX_BUILD_TIME_MULTIPLIER: u64 = 1_700_000;
/// How quickly the multiplier decays when observed builds get cheaper.
const BUILD_TIME_MULTIPLIER_DECAY: u64 = 8;

/// Initial estimate of total build time divided by elapsed time at tx cutoff.
pub const DEFAULT_BUILD_TIME_MULTIPLIER: BuildTimeMultiplier =
    BuildTimeMultiplier::from_scaled(DEFAULT_BUILD_TIME_MULTIPLIER_SCALED);

/// Total build time divided by elapsed time at tx cutoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildTimeMultiplier(u64);

impl BuildTimeMultiplier {
    const fn from_scaled(multiplier: u64) -> Self {
        Self(multiplier)
    }

    /// Returns the fixed-point representation.
    pub const fn scaled(self) -> u64 {
        self.0
    }
}

impl Default for BuildTimeMultiplier {
    fn default() -> Self {
        DEFAULT_BUILD_TIME_MULTIPLIER
    }
}

impl fmt::Display for BuildTimeMultiplier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / BUILD_TIME_MULTIPLIER_SCALE;
        let fraction = self.0 % BUILD_TIME_MULTIPLIER_SCALE;
        if fraction == 0 {
            return write!(f, "{whole}");
        }

        let mut fraction = format!("{fraction:06}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        write!(f, "{whole}.{fraction}")
    }
}

impl FromStr for BuildTimeMultiplier {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let multiplier = value
            .parse::<f64>()
            .map_err(|_| "multiplier must be a finite positive number".to_string())?;
        if !multiplier.is_finite() || multiplier <= 0.0 {
            return Err("multiplier must be a finite positive number".to_string());
        }

        let scaled = multiplier * BUILD_TIME_MULTIPLIER_SCALE as f64;
        if scaled < 1.0 || scaled > u64::MAX as f64 {
            return Err("multiplier is outside the supported range".to_string());
        }

        Ok(Self(scaled.round() as u64))
    }
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
            observed_build_time_multiplier(Duration::from_millis(10), Duration::from_millis(100)),
            Some(100_000)
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
    fn build_multiplier_parses_decimal_values() {
        assert_eq!(
            "1.35".parse::<BuildTimeMultiplier>().unwrap().scaled(),
            DEFAULT_BUILD_TIME_MULTIPLIER_SCALED
        );
        assert_eq!(
            "0.1".parse::<BuildTimeMultiplier>().unwrap().scaled(),
            100_000
        );
        assert!("0".parse::<BuildTimeMultiplier>().is_err());
    }
}
