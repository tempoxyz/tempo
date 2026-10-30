//! The TIP-20 invariants.

use std::fmt;

use invariants_core::{check, ensure};

use super::{Ledger, Transfer, transfer};
use crate::{Check, Checked, Replay, Step, StepChecked, Tx, Verdict, or_text};

/// A TIP-20's views answer. Counted by runners that read the model, not judged by a check here.
pub const VIEW: &str = "TEMPO-TIP20-VIEW";
pub const SUPPLY_CAP: &str = "TEMPO-TIP20-SUPPLY-CAP";
pub const BALANCE_SUM: &str = "TEMPO-TIP20-BALANCE-SUM";
pub const TRANSFER_EVENTS: &str = "TEMPO-TIP20-TRANSFER-EVENTS";

/// A token's supply and the balances read of it.
pub const CHECKS: &[Check<Ledger>] = &[
    // A zero cap is not exempt: minting checks the cap with no exception, and `setSupplyCap`
    // rejects a cap below the supply.
    check! {
        id: SUPPLY_CAP,
        judge: |l: &Ledger| {
            let cap = l.supply_cap?;
            ensure!(l.supply <= cap, "totalSupply {} exceeds supplyCap {cap}", l.supply)
        },
    },
    // The balances read may be any subset of the holders, so their sum is a lower bound.
    check! {
        id: BALANCE_SUM,
        judge: |l: &Ledger| {
            let sum = l.balance_sum();
            ensure!(
                sum.is_some_and(|sum| sum <= l.supply),
                "balances sum to {}, totalSupply {}: {:?}",
                or_text(sum, "more than 2^256"),
                l.supply,
                l.balances
            )
        },
    },
];

/// A step's effect on one token, its ledgers read over the same accounts before and after it.
pub const STEP_CHECKS: &[Check<Step<Ledger, Option<Tx>>>] = &[
    // Each observed balance moves by exactly the step's `Transfer` events into and out of it,
    // never going negative, and the supply by the mints (from the zero address) and burns (to
    // it). A transfer between an observed and an unobserved account moves only the observed side.
    check! {
        id: TRANSFER_EVENTS,
        over: |step: &Step<Ledger, Option<Tx>>| [&step.post],
        judge: |s, _| {
            let transfers: Vec<Transfer> = s
                .logs_from(s.post.token)
                .filter_map(|log| transfer(&log.data))
                .collect();
            let (pre, post) = s.pre.common(&s.post);
            let detail = match pre.replay(&transfers) {
                // `Transfer` events say nothing of the cap.
                Ok(want) if want.balances == post.balances && want.supply == post.supply => {
                    return Some(Verdict::Holds);
                }
                Ok(want) => format!("expected -> read: {}", want.diff(&post)),
                Err(e) => format!("on the earlier balances: {e}"),
            };
            Some(Verdict::Broken(format!("{} transfers; {detail}", transfers.len())))
        },
    },
];

impl fmt::Display for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "token={}", self.token)
    }
}

impl Checked for Ledger {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}

impl StepChecked<Option<Tx>> for Ledger {
    const STEP_CHECKS: &'static [Check<Step<Self, Option<Tx>>>] = STEP_CHECKS;
}
