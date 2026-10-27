//! Tempo protocol invariants as predicates over state read through view
//! calls.
//!
//! Each module observes one contract's state through [`Views`] and checks
//! it, alone or against the events that changed it. Nothing here decodes
//! calldata or predicts a transaction's outcome, so a check runs unchanged
//! wherever view calls can be answered and logs read: an in-process EVM, or a
//! node at a block hash. Invariant IDs follow the Tempo fuzz harness's
//! `TEMPO-<AREA>-<NAME>` scheme, though not every ID exists in the harness.

pub mod dex;
pub mod fee_amm;
pub mod keychain;
pub mod receive_policy;
pub mod tip20;

use invariants_core::decode;
pub use invariants_core::{Check, ObserveError, Report, Verdict, Views, Violation, complete, view};

/// The violations `checks` find in `ctx`.
pub fn judge<C: ?Sized>(checks: &[Check<C>], ctx: &C) -> Vec<Violation> {
    let mut report = Report::default();
    report.run(checks, ctx);
    report.violations
}
