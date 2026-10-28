//! The stablecoin DEX invariants.

use alloy_primitives::U256;
use invariants_core::{check, ensure};

use super::{Books, Escrow};
use crate::{Check, Checked};

/// The DEX's views answer. Counted by runners that read the model, not judged by a check here.
pub const VIEW: &str = "TEMPO-DEX-VIEW";
pub const DEX_CUSTODY: &str = "TEMPO-DEX10";

pub const CHECKS: &[Check<Books>] = &[
    // The DEX holds, of each token, at least its users' internal balances of it plus its live
    // orders' escrow in it.
    check! {
        id: DEX_CUSTODY,
        over: |books: &Books| books.holdings.keys(),
        judge: |b, token| {
            let token = **token;
            let held = b.holdings[&token];
            let internal: U256 = b
                .internal
                .iter()
                .filter(|((_, t), _)| *t == token)
                .map(|(_, v)| *v)
                .sum();
            let orders: Vec<&Escrow> = b.escrow.iter().filter(|e| e.token == token).collect();
            let escrowed: U256 = orders.iter().map(|e| e.amount).sum();
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

impl Checked for Books {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}
