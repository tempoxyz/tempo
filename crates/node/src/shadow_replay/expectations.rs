//! Reviewed expectations, registered at the fork that introduces a feature.
//!
//! A check accepts one difference, not a transaction. Returning `Continue` also asserts that
//! this difference preserves comparability of the remaining execution. Missing evidence must
//! return `None`; fee provenance or an affected opcode alone is not an explanation.

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

pub(super) fn expectations(fork: TempoHardfork) -> &'static [Expectation] {
    REGISTRY
        .iter()
        .find_map(|&(registered, rules)| (registered == fork).then_some(rules))
        .unwrap_or(&[])
}

/// Select once per block, including every newly active fork and excluding canonical features.
pub(super) fn between(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> Vec<&'static Expectation> {
    newly_active(canonical, candidate)
        .flat_map(expectations)
        .collect()
}

fn newly_active(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> impl Iterator<Item = TempoHardfork> {
    TempoHardfork::VARIANTS
        .iter()
        .copied()
        .filter(move |&fork| fork > canonical && fork <= candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_newly_active_forks() {
        use TempoHardfork::*;
        assert_eq!(newly_active(T10, T13).collect::<Vec<_>>(), [T11, T12, T13]);
        assert_eq!(newly_active(T12, T13).collect::<Vec<_>>(), [T13]);
        assert_eq!(newly_active(T13, T13).count(), 0);
        assert_eq!(newly_active(T13, T12).count(), 0);
    }

    #[test]
    fn rule_ids_are_unique_across_forks() {
        let mut ids = std::collections::HashSet::new();
        for fork in TempoHardfork::VARIANTS {
            assert_eq!(
                REGISTRY
                    .iter()
                    .filter(|(registered, _)| registered == fork)
                    .count(),
                1
            );
            for rule in expectations(*fork) {
                assert!(!rule.id.is_empty());
                assert!(ids.insert(rule.id), "duplicate expectation {}", rule.id);
            }
        }
    }
}
