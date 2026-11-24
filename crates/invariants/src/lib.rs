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
    AnyCheck, Check, Checked, Observe, ObserveError, Replay, Report, Step, StepChecked, Verdict,
    Views, Violation, view,
};
use invariants_core::{Batch, optional, view_many};

pub mod configurable_account;
pub mod dex;
pub mod fee_amm;
pub mod keychain;
pub mod receive_policy;
pub mod tip20;

/// The transaction a step ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub sender: Address,
    /// Whether execution succeeded (not reverted or halted).
    pub success: bool,
    /// Who its signatures authorize it for.
    pub authority: configurable_account::Authority,
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
        .chain(erased(configurable_account::STEP_CHECKS))
        .chain(erased(configurable_account::LEAF_CHECKS))
        .chain(erased(keychain::CHECKS))
        .chain(erased(receive_policy::CHECKS))
}

/// `value` as text, `missing` when there is none.
fn or_text(value: Option<U256>, missing: &str) -> String {
    value.map_or_else(|| missing.to_string(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runners count checks by ID, so two checks sharing one would merge their counts.
    #[test]
    fn check_ids_are_unique() {
        let mut ids: Vec<_> = all().map(|check| check.id()).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count);
    }
}
