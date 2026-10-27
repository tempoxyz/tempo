//! The fee manager's custody: the TIP-20 balances it holds against what it
//! owes, its fee AMM pools' reserves and the fees it has collected for
//! validators, and its LP ledger.
//!
//! The fee manager is a protected custody address (no privileged burn can
//! take from it), so its balance of each token covers every claim on it.
//! Pools, validators and LP holders need not all be known: each check sums
//! claims over the observed subset, which only makes it weaker.

use std::{collections::BTreeMap, fmt};

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, sol};

use crate::tip20::ITIP20;
use invariants_core::{check, ensure};

use crate::{Check, ObserveError, Views, Violation, decode, judge};

sol! {
    #[derive(Debug, PartialEq, Eq)]
    interface IFeeAmm {
        struct Pool {
            uint128 reserveUserToken;
            uint128 reserveValidatorToken;
        }
        function getPoolId(address userToken, address validatorToken) external pure returns (bytes32);
        function getPool(address userToken, address validatorToken) external view returns (Pool memory);
        function totalSupply(bytes32 poolId) external view returns (uint256);
        function liquidityBalances(bytes32 poolId, address user) external view returns (uint256);
        function collectedFees(address validator, address token) external view returns (uint256);
        event Mint(address sender, address indexed to, address indexed userToken, address indexed validatorToken, uint256 amountValidatorToken, uint256 liquidity);
        event Burn(address indexed sender, address indexed userToken, address indexed validatorToken, uint256 amountUserToken, uint256 amountValidatorToken, uint256 liquidity, address to);
        event RebalanceSwap(address indexed userToken, address indexed validatorToken, address indexed swapper, uint256 amountIn, uint256 amountOut);
    }
}

pub use IFeeAmm::{Burn, Mint, RebalanceSwap};

/// LP supply locked on a pool's first mint and assigned to no holder.
pub const MIN_LIQUIDITY: U256 = U256::from_limbs([1000, 0, 0, 0]);

/// One pool, as the fee manager reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolState {
    pub user_token: Address,
    pub validator_token: Address,
    pub reserve_user: U256,
    pub reserve_validator: U256,
    pub total_supply: U256,
    /// LP balances of the observed holders.
    pub lp: BTreeMap<Address, U256>,
}

/// The fee manager's books over the observed tokens, pools and validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Books {
    /// Its own balance of each token.
    pub holdings: BTreeMap<Address, U256>,
    pub pools: Vec<PoolState>,
    /// `collectedFees(validator, token)`, keyed `(validator, token)`.
    pub collected: BTreeMap<(Address, Address), U256>,
}

impl Books {
    /// What the fee manager owes in `token`: pool reserves and collected
    /// fees, or `None` if the sum overflows.
    pub fn owed(&self, token: Address) -> Option<(U256, U256)> {
        let reserves = self.pools.iter().try_fold(U256::ZERO, |sum, p| {
            let mut s = sum;
            if p.user_token == token {
                s = s.checked_add(p.reserve_user)?;
            }
            if p.validator_token == token {
                s = s.checked_add(p.reserve_validator)?;
            }
            Some(s)
        })?;
        let fees = self
            .collected
            .iter()
            .filter(|((_, t), _)| *t == token)
            .try_fold(U256::ZERO, |sum, (_, v)| sum.checked_add(*v))?;
        Some((reserves, fees))
    }
}

/// Reads the fee manager at `fee_manager`: its balance of every token in
/// `tokens` and of every pool's, the pools `pairs` (`(userToken,
/// validatorToken)`), the LP balances of `holders` in each, and
/// `collectedFees` of every validator in `validators` for every token.
pub fn observe<V: Views>(
    views: &mut V,
    fee_manager: Address,
    tokens: &[Address],
    pairs: &[(Address, Address)],
    validators: &[Address],
    holders: &[Address],
) -> Result<Books, ObserveError<V::Error>> {
    let mut all: Vec<Address> = tokens.to_vec();
    all.extend(pairs.iter().flat_map(|&(u, v)| [u, v]));
    all.sort();
    all.dedup();

    let ids: Vec<(Address, Bytes)> = pairs
        .iter()
        .map(|&(user_token, validator_token)| {
            let call = IFeeAmm::getPoolIdCall {
                userToken: user_token,
                validatorToken: validator_token,
            };
            (fee_manager, call.abi_encode().into())
        })
        .collect();
    let mut out = views.call(&ids).map_err(ObserveError::Views)?.into_iter();
    let ids: Vec<B256> = pairs
        .iter()
        .map(|_| decode::<IFeeAmm::getPoolIdCall, _>(fee_manager, out.next()))
        .collect::<Result<_, _>>()?;

    let mut calls: Vec<(Address, Bytes)> = Vec::new();
    for &token in &all {
        let c = ITIP20::balanceOfCall {
            account: fee_manager,
        };
        calls.push((token, c.abi_encode().into()));
    }
    for (&(user_token, validator_token), &pool_id) in pairs.iter().zip(&ids) {
        let get = IFeeAmm::getPoolCall {
            userToken: user_token,
            validatorToken: validator_token,
        };
        calls.push((fee_manager, get.abi_encode().into()));
        let supply = IFeeAmm::totalSupplyCall { poolId: pool_id };
        calls.push((fee_manager, supply.abi_encode().into()));
        for &user in holders {
            let c = IFeeAmm::liquidityBalancesCall {
                poolId: pool_id,
                user,
            };
            calls.push((fee_manager, c.abi_encode().into()));
        }
    }
    for &validator in validators {
        for &token in &all {
            let c = IFeeAmm::collectedFeesCall { validator, token };
            calls.push((fee_manager, c.abi_encode().into()));
        }
    }
    let mut out = views.call(&calls).map_err(ObserveError::Views)?.into_iter();

    let mut holdings = BTreeMap::new();
    for &token in &all {
        holdings.insert(
            token,
            decode::<ITIP20::balanceOfCall, _>(token, out.next())?,
        );
    }
    let mut pools = Vec::new();
    for &(user_token, validator_token) in pairs {
        let pool = decode::<IFeeAmm::getPoolCall, _>(fee_manager, out.next())?;
        let total_supply = decode::<IFeeAmm::totalSupplyCall, _>(fee_manager, out.next())?;
        let mut lp = BTreeMap::new();
        for &user in holders {
            lp.insert(
                user,
                decode::<IFeeAmm::liquidityBalancesCall, _>(fee_manager, out.next())?,
            );
        }
        pools.push(PoolState {
            user_token,
            validator_token,
            reserve_user: U256::from(pool.reserveUserToken),
            reserve_validator: U256::from(pool.reserveValidatorToken),
            total_supply,
            lp,
        });
    }
    let mut collected = BTreeMap::new();
    for &validator in validators {
        for &token in &all {
            let fees = decode::<IFeeAmm::collectedFeesCall, _>(fee_manager, out.next())?;
            collected.insert((validator, token), fees);
        }
    }
    Ok(Books {
        holdings,
        pools,
        collected,
    })
}

pub const FEE_CUSTODY: &str = "TEMPO-FEE5";
pub const LP_SUPPLY: &str = "TEMPO-AMM14";
pub const POOL_SHAPE: &str = "TEMPO-AMM30";

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

pub static CHECKS: &[Check<Books>] = &[
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
                total.map_or_else(|| "more than 2^256".to_string(), |o| o.to_string()),
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

/// The violations of [`CHECKS`] in `books`.
pub fn check(books: &Books) -> Vec<Violation> {
    judge(CHECKS, books)
}
