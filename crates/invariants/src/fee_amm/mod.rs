//! The fee manager's custody: the TIP-20 balances it holds against what it
//! owes, its fee AMM pools' reserves and the fees it has collected for
//! validators, and its LP ledger.
//!
//! The fee manager is a protected custody address (no privileged burn can
//! take from it), so its balance of each token covers every claim on it.
//! Pools, validators and LP holders need not all be known: each check sums
//! claims over the observed subset, which only makes it weaker.

use std::{collections::BTreeMap, fmt};

use alloy_primitives::{Address, B256, U256};

use tempo_contracts::precompiles::ITIP20;

use crate::{
    Batch, Observe, ObserveError, Replay, Views,
    model::{Reader, Scope, logged_addresses},
};

pub use tempo_contracts::precompiles::{
    IFeeManager,
    ITIPFeeAMM::{self, Burn, Mint, RebalanceSwap},
    TIP_FEE_MANAGER_ADDRESS,
};

mod checks;

pub use checks::{
    CHECKS, CUSTODY_STEP, FEE_CUSTODY, LP_SUPPLY, MINT_BALANCE, MINT_RESERVE, MINT_SUPPLY,
    POOL_SHAPE, STEP_CHECKS, VIEW,
};

/// Checks the fee manager's books when the scope selects them.
pub(crate) fn check<R: Reader>(reader: &mut R, scope: &Scope<'_>) {
    let fee_manager = TIP_FEE_MANAGER_ADDRESS;
    if !(scope.selected)(&fee_manager) {
        return;
    }
    let tokens = scope.tokens;
    let pairs: Vec<(Address, Address)> = tokens
        .iter()
        .flat_map(|&user| tokens.iter().map(move |&validator| (user, validator)))
        .filter(|(user, validator)| user != validator)
        .collect();
    // Fees are collected for the block's beneficiary, and a step that distributes another
    // validator's fees names it in its logs.
    let mut validators: Vec<Address> = logged_addresses(scope.logs())
        .chain([scope.beneficiary])
        .collect();
    validators.sort_unstable();
    validators.dedup();
    let at = At {
        fee_manager,
        tokens,
        pairs: &pairs,
        validators: &validators,
        holders: scope.holders,
    };
    reader.check::<Books>(at, fee_manager, VIEW);
}

/// The LP supply a pool's first mint locks, as `tempo_precompiles::tip_fee_manager::amm::MIN_LIQUIDITY`
/// (not depended on: it pulls in revm).
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

impl PoolState {
    /// Whether `(user_token, validator_token)` names this pool.
    fn is(&self, user_token: Address, validator_token: Address) -> bool {
        self.user_token == user_token && self.validator_token == validator_token
    }

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

/// A pool after a step is the pool before it with the step's `Mint`s into it replayed: the first
/// mint also locks [`MIN_LIQUIDITY`] in the LP supply, every mint adds its liquidity to the LP
/// supply and to the observed recipient's LP balance, and its validator-token deposit to the
/// validator reserve.
impl Replay<Mint> for PoolState {
    type Error = Unminted;

    fn replay(&self, mints: &[Mint]) -> Result<Self, Unminted> {
        let mut next = self.clone();
        for mint in mints
            .iter()
            .filter(|m| self.is(m.userToken, m.validatorToken))
        {
            let locked = if next.total_supply.is_zero() {
                MIN_LIQUIDITY
            } else {
                U256::ZERO
            };
            next.total_supply = next
                .total_supply
                .checked_add(mint.liquidity)
                .and_then(|supply| supply.checked_add(locked))
                .ok_or(Unminted::Supply)?;
            next.reserve_validator = next
                .reserve_validator
                .checked_add(mint.amountValidatorToken)
                .ok_or(Unminted::Reserve)?;
            if let Some(lp) = next.lp.get_mut(&mint.to) {
                *lp = lp.checked_add(mint.liquidity).ok_or(Unminted::Balance)?;
            }
        }
        Ok(next)
    }
}

/// The fee manager's books over the observed tokens, pools and validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Books {
    /// The fee manager read.
    pub fee_manager: Address,
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

impl Observe for Books {
    type At<'a> = At<'a>;

    /// Reads the fee manager at `fee_manager`: its balance of every token in
    /// `tokens` and of every pool's, the pools `pairs` (`(userToken,
    /// validatorToken)`), the LP balances of `holders` in each, and
    /// `collectedFees` of every validator in `validators` for every token.
    fn observe<V: Views>(views: &mut V, at: Self::At<'_>) -> Result<Self, ObserveError<V::Error>> {
        let At {
            fee_manager,
            tokens,
            pairs,
            validators,
            holders,
        } = at;
        let mut all: Vec<Address> = tokens.to_vec();
        all.extend(pairs.iter().flat_map(|&(u, v)| [u, v]));
        all.sort();
        all.dedup();

        let mut batch = Batch::default();
        let reads: Vec<_> = pairs
            .iter()
            .map(|&(user_token, validator_token)| {
                let call = ITIPFeeAMM::getPoolIdCall {
                    userToken: user_token,
                    validatorToken: validator_token,
                };
                batch.push(None, fee_manager, &call)
            })
            .collect();
        let answers = batch.run(views)?;
        let ids: Vec<B256> = reads
            .iter()
            .map(|read| answers.decode(read))
            .collect::<Result<_, _>>()?;

        let mut batch = Batch::default();
        let held: Vec<_> = all
            .iter()
            .map(|&token| {
                let call = ITIP20::balanceOfCall {
                    account: fee_manager,
                };
                batch.push(None, token, &call)
            })
            .collect();
        let pool_reads: Vec<_> = pairs
            .iter()
            .zip(&ids)
            .map(|(&(user_token, validator_token), &pool_id)| {
                let get = ITIPFeeAMM::getPoolCall {
                    userToken: user_token,
                    validatorToken: validator_token,
                };
                let pool = batch.push(None, fee_manager, &get);
                let supply = ITIPFeeAMM::totalSupplyCall { poolId: pool_id };
                let supply = batch.push(None, fee_manager, &supply);
                let lp: Vec<_> = holders
                    .iter()
                    .map(|&user| {
                        let call = ITIPFeeAMM::liquidityBalancesCall {
                            poolId: pool_id,
                            user,
                        };
                        (user, batch.push(None, fee_manager, &call))
                    })
                    .collect();
                (pool, supply, lp)
            })
            .collect();
        let fee_reads: Vec<_> = validators
            .iter()
            .flat_map(|&validator| all.iter().map(move |&token| (validator, token)))
            .map(|(validator, token)| {
                let call = IFeeManager::collectedFeesCall { validator, token };
                ((validator, token), batch.push(None, fee_manager, &call))
            })
            .collect();
        let answers = batch.run(views)?;

        let mut holdings = BTreeMap::new();
        for (&token, read) in all.iter().zip(&held) {
            holdings.insert(token, answers.decode(read)?);
        }
        let mut pools = Vec::with_capacity(pairs.len());
        for (&(user_token, validator_token), (pool, supply, lp_reads)) in
            pairs.iter().zip(&pool_reads)
        {
            let pool = answers.decode(pool)?;
            let total_supply = answers.decode(supply)?;
            let mut lp = BTreeMap::new();
            for (user, read) in lp_reads {
                lp.insert(*user, answers.decode(read)?);
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
        for (key, read) in &fee_reads {
            collected.insert(*key, answers.decode(read)?);
        }
        Ok(Self {
            fee_manager,
            holdings,
            pools,
            collected,
        })
    }
}

/// The fee manager and the tokens, pools, validators and LP holders to read of it.
#[derive(Debug, Clone, Copy)]
pub struct At<'a> {
    pub fee_manager: Address,
    pub tokens: &'a [Address],
    /// Pools as `(userToken, validatorToken)`.
    pub pairs: &'a [(Address, Address)],
    pub validators: &'a [Address],
    pub holders: &'a [Address],
}

/// What a `Mint` would take out of `U256`.
#[derive(Debug, Clone, Copy)]
pub enum Unminted {
    Supply,
    Reserve,
    Balance,
}

impl fmt::Display for Unminted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            Self::Supply => "the LP supply",
            Self::Reserve => "the validator reserve",
            Self::Balance => "an LP balance",
        };
        write!(f, "minting overflows {what}")
    }
}
