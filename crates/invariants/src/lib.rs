//! Tempo protocol invariants as predicates over state read through view
//! calls.
//!
//! Each module observes one contract's state through [`Views`] and checks
//! it, alone or against the events that changed it. Nothing here decodes
//! calldata or predicts a transaction's outcome, so a check runs unchanged
//! wherever view calls can be answered and logs read: an in-process EVM, or a
//! node at a block hash. Invariant IDs follow the Tempo fuzz harness's
//! `TEMPO-<AREA>-<NAME>` scheme, though not every ID exists in the harness.

use alloy_primitives::{Address, U256};
pub use invariants_core::{
    AnyCheck, CallKind, Check, Checked, Complete, Frame, Meta, Observe, ObserveError, Outcome,
    Replay, Report, Severity, Step, StepChecked, Verdict, Views, Violation, view, view_from,
};
use invariants_core::{decode, optional, view_many};
use tempo_hardfork::TempoHardfork;

pub mod account;
pub mod dex;
pub mod fee_amm;
pub mod keychain;
pub mod receive_policy;
pub mod tip20;
pub mod zones;

/// The transaction a step ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tx {
    pub sender: Address,
    /// Whether execution succeeded (not reverted or halted).
    pub success: bool,
}

/// Every Tempo check, whatever its context.
pub fn all() -> impl Iterator<Item = &'static dyn AnyCheck> {
    fn erased<C: 'static>(
        checks: &'static [Check<C>],
    ) -> impl Iterator<Item = &'static dyn AnyCheck> {
        checks.iter().map(|check| check as &dyn AnyCheck)
    }
    erased(tip20::CHECKS)
        .chain(erased(tip20::STEP_CHECKS))
        .chain(erased(fee_amm::CHECKS))
        .chain(erased(fee_amm::STEP_CHECKS))
        .chain(erased(dex::CHECKS))
        .chain(erased(dex::STEP_CHECKS))
        .chain(erased(account::STEP_CHECKS))
        .chain(erased(keychain::CHECKS))
        .chain(erased(receive_policy::CHECKS))
        .chain(erased(zones::portal::CHECKS))
        .chain(erased(zones::portal::STEP_CHECKS))
        .chain(zones::zone::all())
}

/// The position of the fork named `name` (such as `T14`, as [`TempoHardfork`] displays it) in
/// Tempo's fork order; `None` for a name that is not a Tempo fork.
pub fn fork_position(name: &str) -> Option<usize> {
    TempoHardfork::VARIANTS
        .iter()
        .position(|fork| fork.to_string() == name)
}

/// Whether a check with `meta` applies at `fork`: `fork` is at or after its `since` and before its
/// `until`. A bound naming no Tempo fork never admits the check, and a test fails on it.
pub fn applies_at(meta: &Meta, fork: TempoHardfork) -> bool {
    let current = fork_position(&fork.to_string()).expect("a fork has a position");
    let known = |bound: Option<&str>| bound.is_none_or(|name| fork_position(name).is_some());
    known(meta.since) && known(meta.until) && meta.applies(fork_position, current)
}

/// `value` as text, `missing` when there is none.
fn or_text(value: Option<U256>, missing: &str) -> String {
    value.map_or_else(|| missing.to_string(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_has_a_doc_and_names_only_tempo_forks() {
        for check in all() {
            let meta = check.meta();
            assert!(!meta.doc.is_empty(), "{} has no doc", check.id());
            for fork in [meta.since, meta.until].into_iter().flatten() {
                assert!(
                    fork_position(fork).is_some(),
                    "{} names {fork}, not a Tempo fork",
                    check.id()
                );
            }
        }
    }

    #[test]
    fn a_check_applies_from_its_since_until_its_until() {
        let meta = Meta {
            since: Some("T3"),
            until: Some("T14"),
            ..Meta::EMPTY
        };
        assert!(!applies_at(&meta, TempoHardfork::T2));
        assert!(applies_at(&meta, TempoHardfork::T3));
        assert!(applies_at(&meta, TempoHardfork::T13));
        assert!(!applies_at(&meta, TempoHardfork::T14));
        assert!(applies_at(&Meta::EMPTY, TempoHardfork::Genesis));
        let unknown = Meta {
            since: Some("T99"),
            ..Meta::EMPTY
        };
        assert!(!applies_at(&unknown, TempoHardfork::T15));
        let unknown_until = Meta {
            until: Some("T99"),
            ..Meta::EMPTY
        };
        assert!(!applies_at(&unknown_until, TempoHardfork::T12));
    }
}
