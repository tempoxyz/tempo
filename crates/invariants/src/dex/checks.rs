//! The stablecoin DEX invariants.

use invariants_core::{check, ensure};

use super::{Books, Escrow};
use crate::{Check, Checked, Step, StepChecked, Tx};

/// The DEX's views answer. Counted by runners that read the model, not judged by a check here.
pub const VIEW: &str = "TEMPO-DEX-VIEW";
pub const DEX_CUSTODY: &str = "TEMPO-DEX10";
pub const CUSTODY_STEP: &str = "TEMPO-DEX10-STEP";

pub const CHECKS: &[Check<Books>] = &[
    // The DEX holds, of each token, at least its users' internal balances of it plus its live
    // orders' escrow in it.
    check! {
        id: DEX_CUSTODY,
        over: |books: &Books| books.holdings.keys(),
        judge: |b, token| {
            let token = **token;
            let held = b.holdings[&token];
            let (internal, escrowed) = b.owed(token);
            let orders: Vec<&Escrow> = b.escrow.iter().filter(|e| e.token == token).collect();
            let owed = internal + escrowed;
            ensure!(
                owed <= held,
                "holds {held}, owes {owed} (internal balances {internal}, escrow of {} live orders {escrowed}); short {}",
                orders.len(),
                owed - held
            )
        },
    },
];

/// The step's effect on the DEX's custody, read before and after it.
pub const STEP_CHECKS: &[Check<Step<Books, Option<Tx>>>] = &[
    // The DEX's holdings of each token never fall by more than what it owes in it: a token that
    // leaves it must leave a user's internal balance or a live order's escrow. More can come in
    // than it comes to owe, such as a plain transfer to it.
    check! {
        id: CUSTODY_STEP,
        over: |step: &Step<Books, Option<Tx>>| step.post.holdings.keys(),
        judge: |s, token| {
            let token = **token;
            let (Some(&held_before), Some(&held_after)) =
                (s.pre.holdings.get(&token), s.post.holdings.get(&token))
            else {
                return None;
            };
            let owed = |books: &Books| {
                let (internal, escrowed) = books.owed(token);
                internal + escrowed
            };
            let (owed_before, owed_after) = (owed(&s.pre), owed(&s.post));
            if held_before == held_after && owed_before == owed_after {
                return None;
            }
            ensure!(
                held_after + owed_before >= held_before + owed_after,
                "token {token} held {held_before} -> {held_after}, owed {owed_before} -> {owed_after}"
            )
        },
    },
];

impl Checked for Books {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}

impl StepChecked<Option<Tx>> for Books {
    const STEP_CHECKS: &'static [Check<Step<Self, Option<Tx>>>] = STEP_CHECKS;
}
