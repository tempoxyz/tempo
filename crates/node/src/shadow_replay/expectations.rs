//! Reviewed expectations, registered at the fork that introduces a feature.
//!
//! A check accepts one difference, not a transaction. Returning `Some(false)` also asserts that
//! this difference preserves comparability of the remaining execution. Missing evidence must
//! return `None`; fee provenance or an affected opcode alone is not an explanation.
//! The first accepting check owns attribution AND continuation; later checks are not run.

use super::{Boundary, Evidence, analysis::Field};
use tempo_chainspec::hardfork::TempoHardfork;

#[derive(Debug)]
pub(super) struct Expectation {
    /// Stable feature/check name, also used as a bounded-cardinality metric label.
    pub id: &'static str,
    /// `None`: unexplained. `Some(invalidates_suffix)`: accepted; true cuts off later comparisons.
    pub check: fn(&Context<'_>, &Field) -> Option<bool>,
}

/// Evidence is borrowed from the existing executions; checks must not perform another replay.
pub(super) struct Context<'a> {
    pub boundary: Boundary,
    pub real: &'a Evidence,
    pub shadow: &'a Evidence,
}

/// Register only forks with expectations, in ascending fork order.
///
/// No production exceptions are established yet. In particular, TIP-1016 needs independently
/// checked gas/fee accounting before its differences can be accepted. Empty means unexplained,
/// not equal, safe, or ignored. Add each feature's checks and fixtures together.
const REGISTRY: &[(TempoHardfork, &[Expectation])] = &[];

/// Select once per block, including every newly active fork and excluding canonical features.
/// Forks run in registry order (oldest first), then checks in slice order.
pub(super) fn between(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> Vec<&'static Expectation> {
    newly_active(REGISTRY, canonical, candidate)
        .flat_map(|(_, rules)| *rules)
        .collect()
}

fn newly_active(
    registry: &'static [(TempoHardfork, &'static [Expectation])],
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> impl Iterator<Item = &'static (TempoHardfork, &'static [Expectation])> {
    registry
        .iter()
        .filter(move |(fork, _)| *fork > canonical && *fork <= candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_newly_active_forks() {
        use TempoHardfork::*;
        const SPARSE: &[(TempoHardfork, &[Expectation])] = &[(T11, &[]), (T13, &[])];
        let forks = |a, b| {
            newly_active(SPARSE, a, b)
                .map(|(fork, _)| *fork)
                .collect::<Vec<_>>()
        };
        assert_eq!(forks(T10, T13), [T11, T13]);
        assert_eq!(forks(T12, T13), [T13]);
        assert!(forks(T11, T12).is_empty());
        assert!(forks(T13, T13).is_empty());
        assert!(forks(T13, T12).is_empty());
        assert_eq!(newly_active(&[], T10, T13).count(), 0);
    }

    #[test]
    fn registry_is_ordered_and_rule_ids_are_unique() {
        assert!(REGISTRY.windows(2).all(|pair| pair[0].0 < pair[1].0));
        let mut ids = std::collections::HashSet::new();
        for (_, rules) in REGISTRY {
            for rule in *rules {
                assert!(!rule.id.is_empty());
                assert!(ids.insert(rule.id), "duplicate expectation {}", rule.id);
            }
        }
    }
}
