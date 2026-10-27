//! The fee manager and fee AMM invariants.

use std::fmt;

use alloy_primitives::U256;
use invariants_core::{check, ensure};

use super::{Books, MIN_LIQUIDITY, PoolState};
use crate::{Check, Checked, or_text};

pub const FEE_CUSTODY: &str = "TEMPO-FEE5";
pub const LP_SUPPLY: &str = "TEMPO-AMM14";
pub const POOL_SHAPE: &str = "TEMPO-AMM30";

pub const CHECKS: &[Check<Books>] = &[
    // The fee manager holds, of each token, at least its pools' reserves of it plus the fees it
    // collected in it.
    check! {
        id: FEE_CUSTODY,
        over: |books: &Books| books.holdings.keys(),
        judge: |b, token| {
            let held = b.holdings[*token];
            let owed = b.owed(**token);
            let total = owed.and_then(|(reserves, fees)| reserves.checked_add(fees));
            ensure!(
                total.is_some_and(|total| total <= held),
                "holds {held}, owes {} (pool reserves {}, collected fees {})",
                or_text(total, "more than 2^256"),
                owed.map_or_else(|| "?".to_string(), |(r, _)| r.to_string()),
                owed.map_or_else(|| "?".to_string(), |(_, f)| f.to_string())
            )
        },
    },
    // A pool is uninitialized (no LP supply, reserves or LP) or has at least the locked minimum
    // LP supply.
    check! {
        id: POOL_SHAPE,
        over: |books: &Books| &books.pools,
        judge: |_, p| {
            if p.total_supply.is_zero() {
                let lp = p.lp_sum();
                ensure!(
                    p.reserve_user.is_zero() && p.reserve_validator.is_zero() && lp == Some(U256::ZERO),
                    "LP supply 0 with reserves ({}, {}) and LP {lp:?}",
                    p.reserve_user,
                    p.reserve_validator
                )
            } else {
                ensure!(
                    p.total_supply >= MIN_LIQUIDITY,
                    "LP supply {} below MIN_LIQUIDITY {MIN_LIQUIDITY}",
                    p.total_supply
                )
            }
        },
    },
    // An initialized pool's LP holders hold at most its LP supply less the locked minimum.
    check! {
        id: LP_SUPPLY,
        over: |books: &Books| &books.pools,
        judge: |_, p| {
            if p.total_supply < MIN_LIQUIDITY {
                return None;
            }
            let lp = p.lp_sum();
            ensure!(
                lp.and_then(|lp| lp.checked_add(MIN_LIQUIDITY))
                    .is_some_and(|lp| lp <= p.total_supply),
                "holders' LP {lp:?} plus the locked {MIN_LIQUIDITY} exceed the LP supply {}: {:?}",
                p.total_supply,
                p.lp
            )
        },
    },
];

impl PoolState {
    /// The observed holders' LP, or `None` if it overflows.
    fn lp_sum(&self) -> Option<U256> {
        self.lp
            .values()
            .try_fold(U256::ZERO, |sum, lp| sum.checked_add(*lp))
    }
}

impl fmt::Display for PoolState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pool ({}, {})", self.user_token, self.validator_token)
    }
}

impl Checked for Books {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}
