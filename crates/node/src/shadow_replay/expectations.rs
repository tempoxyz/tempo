//! Reviewed expectations, registered at the fork that introduces a feature.
//!
//! A check accepts one difference, not a transaction. Returning `Continue` also asserts that
//! this difference preserves comparability of the remaining execution. Missing evidence must
//! return `None`; fee provenance or an affected opcode alone is not an explanation.
//! The first accepting check owns attribution AND continuation; later checks are not run.

use super::{Boundary, Evidence, analysis::Difference};
use tempo_chainspec::hardfork::TempoHardfork;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Continuation {
    Continue,
    InconclusiveSuffix,
}

#[derive(Debug)]
pub(super) struct Expectation {
    /// Stable feature/check name, also used as a bounded-cardinality metric label.
    pub id: &'static str,
    pub check: fn(&Context<'_>, &Difference) -> Option<Continuation>,
}

/// Evidence is borrowed from the existing executions; checks must not perform another replay.
pub(super) struct Context<'a> {
    pub boundary: Boundary,
    pub real: &'a Evidence,
    pub shadow: &'a Evidence,
}

/// Keep an explicit entry per fork so adding a fork requires reviewing its expectations.
///
/// No production exceptions are established yet. In particular, TIP-1016 needs independently
/// checked gas/fee accounting before its differences can be accepted. Empty means unexplained,
/// not equal, safe, or ignored. Add each feature's checks and fixtures together.
const REGISTRY: &[(TempoHardfork, &[Expectation])] = &[
    (TempoHardfork::Genesis, &[]),
    (TempoHardfork::T0, &[]),
    (TempoHardfork::T1, &[]),
    (TempoHardfork::T1A, &[]),
    (TempoHardfork::T1B, &[]),
    (TempoHardfork::T1C, &[]),
    (TempoHardfork::T2, &[]),
    (TempoHardfork::T3, &[]),
    (TempoHardfork::T4, &[]),
    (TempoHardfork::T5, &[]),
    (TempoHardfork::T6, &[]),
    (TempoHardfork::T7, &[]),
    (TempoHardfork::T8, &[]),
    (TempoHardfork::T9, &[]),
    (TempoHardfork::T10, &[]),
    (TempoHardfork::T11, &[]),
    (TempoHardfork::T12, &[]),
    (TempoHardfork::T13, &[]),
];

// TempoHardfork is non_exhaustive across crates, so a match cannot enforce this.
const _: () = assert!(REGISTRY.len() == TempoHardfork::VARIANTS.len());

/// Select once per block, including every newly active fork and excluding canonical features.
/// Forks run in registry order (oldest first), then checks in slice order.
pub(super) fn between(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> Vec<&'static Expectation> {
    newly_active(canonical, candidate)
        .flat_map(|(_, rules)| *rules)
        .collect()
}

fn newly_active(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> impl Iterator<Item = &'static (TempoHardfork, &'static [Expectation])> {
    REGISTRY
        .iter()
        .filter(move |(fork, _)| *fork > canonical && *fork <= candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_newly_active_forks() {
        use TempoHardfork::*;
        let forks = |a, b| {
            newly_active(a, b)
                .map(|(fork, _)| *fork)
                .collect::<Vec<_>>()
        };
        assert_eq!(forks(T10, T13), [T11, T12, T13]);
        assert_eq!(forks(T12, T13), [T13]);
        assert_eq!(newly_active(T13, T13).count(), 0);
        assert_eq!(newly_active(T13, T12).count(), 0);
    }

    #[test]
    fn rule_ids_are_unique_across_forks() {
        let mut ids = std::collections::HashSet::new();
        for ((fork, rules), expected) in REGISTRY.iter().zip(TempoHardfork::VARIANTS) {
            assert_eq!(fork, expected);
            for rule in *rules {
                assert!(!rule.id.is_empty());
                assert!(ids.insert(rule.id), "duplicate expectation {}", rule.id);
            }
        }
    }
}
