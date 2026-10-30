//! The configurable account invariants.

use alloy_primitives::{Address, B256};
use invariants_core::{check, ensure};

use super::{AccountUpgraded, Commitments, ConfigurableAccountConfigUpdated};
use crate::{Check, Step, StepChecked, Tx};

/// The configurable account precompile's views answer. Counted by runners that read the model, not judged by a check here.
pub const VIEW: &str = "TEMPO-ACCOUNT-VIEW";
pub const COMMITMENT_KEPT: &str = "TEMPO-ACCOUNT-COMMITMENT-KEPT";
pub const COMMITMENT_BY_SELF: &str = "TEMPO-ACCOUNT-COMMITMENT-BY-SELF";
pub const COMMITMENT_EVENT: &str = "TEMPO-ACCOUNT-COMMITMENT-EVENT";

/// A step's effect on each observed account's configuration commitment.
pub const STEP_CHECKS: &[Check<Step<Commitments, Option<Tx>>>] = &[
    // Once an account has a configuration, nothing clears it (TIP-1108).
    check! {
        id: COMMITMENT_KEPT,
        over: |step: &Step<Commitments, Option<Tx>>| step.post.of.keys(),
        judge: |s, account| {
            let (pre, post) = commitments(s, account)?;
            if pre.is_zero() {
                return None;
            }
            ensure!(!post.is_zero(), "commitment {pre} cleared")
        },
    },
    // Only the account's own transaction changes its configuration: `updateConfig` takes the
    // sender's own configuration and `upgradeAccount` migrates the transaction's own sender
    // (TIP-1109, TIP-1113).
    check! {
        id: COMMITMENT_BY_SELF,
        over: |step: &Step<Commitments, Option<Tx>>| step.post.of.keys(),
        judge: |s, account| {
            let (pre, post) = commitments(s, account)?;
            let tx = s.tx.as_ref()?;
            if pre == post {
                return None;
            }
            ensure!(
                tx.sender == **account,
                "commitment {pre} -> {post} in a transaction from {}",
                tx.sender
            )
        },
    },
    // A changed commitment is announced: `AccountUpgraded` with the new commitment, or
    // `ConfigurableAccountConfigUpdated`, for the account.
    check! {
        id: COMMITMENT_EVENT,
        over: |step: &Step<Commitments, Option<Tx>>| step.post.of.keys(),
        judge: |s, account| {
            let (pre, post) = commitments(s, account)?;
            if pre == post {
                return None;
            }
            let precompile = s.post.precompile;
            let upgraded = s
                .events::<AccountUpgraded>(precompile)
                .iter()
                .any(|e| e.account == **account && e.commitment == post);
            let updated = s
                .events::<ConfigurableAccountConfigUpdated>(precompile)
                .iter()
                .any(|e| e.account == **account);
            ensure!(
                upgraded || updated,
                "commitment {pre} -> {post} without an event announcing it"
            )
        },
    },
];

impl StepChecked<Option<Tx>> for Commitments {
    const STEP_CHECKS: &'static [Check<Step<Self, Option<Tx>>>] = STEP_CHECKS;
}

/// `account`'s commitment before and after the step, when both reads answered.
fn commitments(s: &Step<Commitments, Option<Tx>>, account: &Address) -> Option<(B256, B256)> {
    Some((*s.pre.of.get(account)?, *s.post.of.get(account)?))
}
