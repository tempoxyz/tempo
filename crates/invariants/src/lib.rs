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
    AnyCheck, Check, Checked, Complete, Observe, ObserveError, Replay, Report, Step, StepChecked,
    Verdict, Views, Violation, view,
};
use invariants_core::{decode, optional, view_many};

pub mod account;
pub mod dex;
pub mod fee_amm;
pub mod keychain;
pub mod receive_policy;
pub mod tip20;

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
}

/// `value` as text, `missing` when there is none.
fn or_text(value: Option<U256>, missing: &str) -> String {
    value.map_or_else(|| missing.to_string(), |value| value.to_string())
}
