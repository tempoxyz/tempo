//! Reviewed expectations registered at the fork introducing a feature.
//!
//! Checks receive one difference, not a transaction. `None` means unexplained and `Some(())`
//! accepts it.

use super::Field;
use crate::shadow_replay::{Boundary, Evidence};
use tempo_chainspec::hardfork::TempoHardfork;

#[derive(Debug)]
pub(crate) struct Expectation {
    pub id: &'static str,
    pub check: fn(&Context<'_>, &Field) -> Option<()>,
}

pub(crate) struct Context<'a> {
    pub boundary: Boundary,
    pub real: &'a Evidence,
    pub shadow: &'a Evidence,
}

/// Forks are ordered oldest-first; canonical features are excluded.
const REGISTRY: &[(TempoHardfork, &[Expectation])] = &[];

pub(crate) fn between(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> Vec<&'static Expectation> {
    select(REGISTRY, canonical, candidate)
}

fn select(
    registry: &'static [(TempoHardfork, &[Expectation])],
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> Vec<&'static Expectation> {
    registry
        .iter()
        .filter(|(fork, _)| *fork > canonical && *fork <= candidate)
        .flat_map(|(_, rules)| *rules)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_newly_active_forks() {
        use TempoHardfork::*;
        const T11_RULE: Expectation = Expectation {
            id: "t11",
            check: |_, _| None,
        };
        const T13_RULE: Expectation = Expectation {
            id: "t13",
            check: |_, _| None,
        };
        const SPARSE: &[(TempoHardfork, &[Expectation])] =
            &[(T11, &[T11_RULE]), (T13, &[T13_RULE])];

        let ids = |a, b| {
            select(SPARSE, a, b)
                .into_iter()
                .map(|rule| rule.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(T10, T13), ["t11", "t13"]);
        assert_eq!(ids(T12, T13), ["t13"]);
        assert!(ids(T11, T12).is_empty());
        assert!(ids(T13, T13).is_empty());
        assert!(ids(T13, T12).is_empty());
    }
}
