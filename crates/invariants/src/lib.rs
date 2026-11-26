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
    AnyCheck, Checked, Observe, ObserveError, Replay, Report, Step, StepChecked, Verdict, Views,
    Violation, view,
};
use invariants_core::{Batch, optional, view_many};
pub use tempo_hardfork::TempoHardfork;

pub mod block;
pub mod configurable_account;
pub mod dex;
pub mod fee_amm;
pub mod keychain;
pub mod model;
pub mod receive_policy;
pub mod tip20;

/// A Tempo check, applying from and until the hardforks its metadata names.
pub type Check<C> = invariants_core::Check<C, TempoHardfork>;

/// The transaction a step ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub sender: Address,
    /// Whether execution succeeded (not reverted or halted).
    pub success: bool,
    /// Who its signatures authorize it for.
    pub authority: configurable_account::Authority,
}

/// What a step ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ran {
    PreBlock,
    Tx(Tx),
    PostBlock,
}

impl Ran {
    /// The transaction, when the step ran one.
    pub fn tx(&self) -> Option<&Tx> {
        match self {
            Self::Tx(tx) => Some(tx),
            Self::PreBlock | Self::PostBlock => None,
        }
    }
}

/// The ID and doc of each model's counter of reads that failed.
pub const VIEWS: [(&str, &str); 4] = [
    (tip20::VIEW, "A TIP-20's views answer."),
    (fee_amm::VIEW, "The fee manager's views answer."),
    (dex::VIEW, "The stablecoin DEX's views answer."),
    (
        configurable_account::VIEW,
        "The configurable account precompile's views answer.",
    ),
];

/// Every Tempo check, whatever its context.
pub fn all() -> impl Iterator<Item = &'static dyn AnyCheck<TempoHardfork>> {
    fn erased<C>(
        checks: &'static [Check<C>],
    ) -> impl Iterator<Item = &'static dyn AnyCheck<TempoHardfork>> {
        checks
            .iter()
            .map(|check| check as &dyn AnyCheck<TempoHardfork>)
    }
    erased(tip20::CHECKS)
        .chain(erased(tip20::STEP_CHECKS))
        .chain(erased(tip20::roles::STEP_CHECKS))
        .chain(erased(fee_amm::CHECKS))
        .chain(erased(fee_amm::STEP_CHECKS))
        .chain(erased(fee_amm::exit::CHECKS))
        .chain(erased(dex::CHECKS))
        .chain(erased(dex::STEP_CHECKS))
        .chain(erased(configurable_account::STEP_CHECKS))
        .chain(erased(configurable_account::LEAF_CHECKS))
        .chain(erased(keychain::CHECKS))
        .chain(erased(receive_policy::CHECKS))
        .chain(erased(block::CHECKS))
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

    /// `INVARIANTS.md` is the catalog [`all`] renders, rewritten when `UPDATE_CATALOG` is set.
    #[test]
    fn the_catalog_lists_every_check() {
        let catalog = format!(
            "# Tempo invariants\n\nGenerated from each check's metadata by `the_catalog_lists_every_check`.\n\n{}",
            invariants_core::markdown(all())
        );
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/INVARIANTS.md");
        if std::env::var_os("UPDATE_CATALOG").is_some() {
            std::fs::write(path, &catalog).unwrap();
        }
        let written = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            written == catalog,
            "{path} is stale: rerun with UPDATE_CATALOG=1"
        );
    }
}
