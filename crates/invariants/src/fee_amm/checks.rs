//! The fee manager and fee AMM invariants.

use alloy_primitives::{Address, U256};
use invariants_core::{check, ensure};

use super::{Books, Burn, MIN_LIQUIDITY, Mint, PoolState, RebalanceSwap, Unminted};
use crate::{Check, Checked, Replay, Step, StepChecked, Tx, Verdict, or_text};

/// The fee manager's views answer. Counted by runners that read the model, not judged by a check here.
pub const VIEW: &str = "TEMPO-FEE-VIEW";
pub const FEE_CUSTODY: &str = "TEMPO-FEE5";
pub const LP_SUPPLY: &str = "TEMPO-AMM14";
pub const POOL_SHAPE: &str = "TEMPO-AMM30";
pub const MINT_SUPPLY: &str = "TEMPO-AMM2";
pub const MINT_BALANCE: &str = "TEMPO-AMM3";
pub const MINT_RESERVE: &str = "TEMPO-AMM4";
pub const CUSTODY_STEP: &str = "TEMPO-FEE5-STEP";
pub const SHARE_VALUE: &str = "TEMPO-AMM-SHARE-VALUE";

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

/// The step's effect on each pool the fee manager's books read before and after it.
pub const STEP_CHECKS: &[Check<Step<Books, Option<Tx>>>] = &[
    // The fee manager's holdings of each token never fall by more than what it owes in it: a
    // token that leaves it must leave a pool reserve or a validator's collected fees. More can
    // come in than it comes to owe, such as a plain transfer or mint to it.
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
                let (reserves, fees) = books.owed(token)?;
                reserves.checked_add(fees)
            };
            let (owed_before, owed_after) = (owed(&s.pre)?, owed(&s.post)?);
            if held_before == held_after && owed_before == owed_after {
                return None;
            }
            let (kept, due) = (held_after.checked_add(owed_before)?, held_before.checked_add(owed_after)?);
            ensure!(
                kept >= due,
                "token {token} held {held_before} -> {held_after}, owed {owed_before} -> {owed_after}"
            )
        },
    },
    // A pool's value per LP share, `V + floor(N * U / SCALE)` over the LP supply, never falls: swaps,
    // rebalances and mints price in its favour, and each burn's rounding may cost it 1.
    check! {
        id: SHARE_VALUE,
        over: |step: &Step<Books, Option<Tx>>| &step.post.pools,
        judge: |s, post| {
            let pre = s.pre.pools.iter().find(|pre| pre.is(post.user_token, post.validator_token))?;
            if pre.total_supply.is_zero() || post.total_supply.is_zero() {
                return None;
            }
            let burns = s
                .events::<Burn>(s.post.fee_manager)
                .iter()
                .filter(|b| post.is(b.userToken, b.validatorToken))
                .count();
            let (before, after) = (pre.share_value()?, post.share_value()?.checked_add(U256::from(burns))?);
            if pre == *post {
                return None;
            }
            ensure!(
                after.checked_mul(pre.total_supply)? >= before.checked_mul(post.total_supply)?,
                "value {before} over LP supply {} -> {after} over {} ({burns} burns)",
                pre.total_supply,
                post.total_supply
            )
        },
    },
    // The LP supply grows by exactly the minted liquidity, plus `MIN_LIQUIDITY` on a pool's first
    // mint.
    check! {
        id: MINT_SUPPLY,
        over: |step: &Step<Books, Option<Tx>>| &step.post.pools,
        judge: |s, pool| {
            let want = match minted(s, pool)? {
                Ok(want) => want,
                Err(err) => return Some(Verdict::Broken(err.to_string())),
            };
            ensure!(
                want.total_supply == pool.total_supply,
                "LP supply {} after mints, expected {}",
                pool.total_supply,
                want.total_supply
            )
        },
    },
    // The recipient's LP balance grows by exactly the liquidity minted to it.
    check! {
        id: MINT_BALANCE,
        over: |step: &Step<Books, Option<Tx>>| &step.post.pools,
        judge: |s, pool| {
            let want = match minted(s, pool)? {
                Ok(want) => want,
                Err(err) => return Some(Verdict::Broken(err.to_string())),
            };
            ensure!(want.lp == pool.lp, "LP balances {:?} after mints, expected {:?}", pool.lp, want.lp)
        },
    },
    // The validator reserve grows by exactly the validator tokens deposited.
    check! {
        id: MINT_RESERVE,
        over: |step: &Step<Books, Option<Tx>>| &step.post.pools,
        judge: |s, pool| {
            let want = match minted(s, pool)? {
                Ok(want) => want,
                Err(err) => return Some(Verdict::Broken(err.to_string())),
            };
            ensure!(
                want.reserve_validator == pool.reserve_validator,
                "validator reserve {} after mints, expected {}",
                pool.reserve_validator,
                want.reserve_validator
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

/// `pool` as the step's `Mint`s into it predict it from its state before the step, or why it
/// cannot be predicted. `None` (not armed) unless the step only minted into the pool: no burn,
/// rebalance or fee swap (which moves the user reserve) touched it.
fn minted(step: &Step<Books, Option<Tx>>, pool: &PoolState) -> Option<Result<PoolState, Unminted>> {
    let pre = step
        .pre
        .pools
        .iter()
        .find(|pre| pre.is(pool.user_token, pool.validator_token))?;
    let manager = step.post.fee_manager;
    let mints: Vec<Mint> = step.events(manager);
    let ours = |user: Address, validator: Address| pool.is(user, validator);
    let burned = step
        .events::<Burn>(manager)
        .iter()
        .any(|b| ours(b.userToken, b.validatorToken));
    let swapped = step
        .events::<RebalanceSwap>(manager)
        .iter()
        .any(|r| ours(r.userToken, r.validatorToken));
    let minted_here = mints.iter().any(|m| ours(m.userToken, m.validatorToken));
    if !minted_here || burned || swapped || pre.reserve_user != pool.reserve_user {
        return None;
    }
    Some(pre.replay(&mints))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256};

    use super::{SHARE_VALUE, STEP_CHECKS};
    use crate::{
        Report, Step,
        fee_amm::{Books, PoolState},
    };

    fn books(reserve_user: u64, reserve_validator: u64, total_supply: u64) -> Books {
        Books {
            fee_manager: Address::repeat_byte(0xfe),
            holdings: Default::default(),
            pools: vec![PoolState {
                user_token: Address::repeat_byte(1),
                validator_token: Address::repeat_byte(2),
                reserve_user: U256::from(reserve_user),
                reserve_validator: U256::from(reserve_validator),
                total_supply: U256::from(total_supply),
                lp: Default::default(),
            }],
            collected: Default::default(),
        }
    }

    fn fired(pre: Books, post: Books) -> u64 {
        let step = Step {
            pre,
            post,
            changes: vec![],
            logs: vec![],
            tx: None,
        };
        let mut report = Report::default();
        report.run(STEP_CHECKS, &step);
        report.counts[SHARE_VALUE].fired
    }

    #[test]
    fn share_value() {
        // A fee swap of 1000 user tokens pays out 997 validator tokens: value per share grows.
        assert_eq!(
            fired(books(0, 10_000, 5_000), books(1_000, 9_003, 5_000)),
            0
        );
        // Paying out at par instead loses value.
        assert_eq!(
            fired(books(0, 10_000, 5_000), books(1_000, 9_000, 5_000)),
            1
        );
        // A mint of 1000 at the pool's value keeps it.
        assert_eq!(fired(books(0, 10_000, 5_000), books(0, 11_000, 5_500)), 0);
        // Minting more LP than the deposit is worth loses it.
        assert_eq!(fired(books(0, 10_000, 5_000), books(0, 11_000, 5_600)), 1);
    }
}
