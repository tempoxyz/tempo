//! Every observed LP holder of a pool burning its whole position in turn, on a throwaway copy of
//! the state.

use std::fmt;

use alloy_primitives::{Address, U256};
use alloy_sol_types::{ContractError, GenericContractError};
use invariants_core::{Outcome, Probe, Simulate, check, ensure_eq};

use super::{ITIPFeeAMM, MIN_LIQUIDITY};
use crate::{Batch, Check, Checked, ObserveError, TempoHardfork, Verdict, optional};

pub const BURN_PRO_RATA: &str = "TEMPO-AMM5";
pub const EXIT: &str = "TEMPO-AMM-EXIT";

/// A pool before its observed LP holders exit it, and how each exit ended, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    /// The pool's user token.
    pub user_token: Address,
    /// The pool's validator token.
    pub validator_token: Address,
    /// The user-token reserve before any exit.
    pub reserve_user: U256,
    /// The validator-token reserve before any exit.
    pub reserve_validator: U256,
    /// The LP supply before any exit.
    pub total_supply: U256,
    /// The holders' burns, in the order they ran.
    pub burns: Vec<ExitBurn>,
}

impl Probe for Exit {
    type At<'a> = At<'a>;

    /// Reads the pool and the holders' LP balances, then burns each nonzero balance in turn. An
    /// uninitialized pool, or a holder's balance nothing answers, is not burned.
    fn probe<V: Simulate>(views: &mut V, at: At<'_>) -> Result<Self, ObserveError<V::Error>> {
        let At {
            fee_manager,
            user_token,
            validator_token,
            holders,
        } = at;
        let mut batch = Batch::default();
        let id = batch.push(
            None,
            fee_manager,
            &ITIPFeeAMM::getPoolIdCall {
                userToken: user_token,
                validatorToken: validator_token,
            },
        );
        let pool_id = batch.run(views)?.decode(&id)?;

        let mut batch = Batch::default();
        let pool = batch.push(
            None,
            fee_manager,
            &ITIPFeeAMM::getPoolCall {
                userToken: user_token,
                validatorToken: validator_token,
            },
        );
        let supply = batch.push(
            None,
            fee_manager,
            &ITIPFeeAMM::totalSupplyCall { poolId: pool_id },
        );
        let balances: Vec<_> = holders
            .iter()
            .map(|&user| {
                let call = ITIPFeeAMM::liquidityBalancesCall {
                    poolId: pool_id,
                    user,
                };
                (user, batch.push(None, fee_manager, &call))
            })
            .collect();
        let answers = batch.run(views)?;
        let pool = answers.decode(&pool)?;
        let total_supply = answers.decode(&supply)?;

        let mut batch = Batch::default();
        let mut burns = Vec::new();
        for (holder, read) in balances {
            if total_supply >= MIN_LIQUIDITY
                && let Some(liquidity) = optional(views, answers.decode(&read))?
                && !liquidity.is_zero()
            {
                let call = ITIPFeeAMM::burnCall {
                    userToken: user_token,
                    validatorToken: validator_token,
                    liquidity,
                    to: holder,
                };
                let burn = batch.push(Some(holder), fee_manager, &call);
                burns.push((holder, liquidity, burn));
            }
        }
        let answers = batch.simulate(views)?;
        Ok(Self {
            user_token,
            validator_token,
            reserve_user: U256::from(pool.reserveUserToken),
            reserve_validator: U256::from(pool.reserveValidatorToken),
            total_supply,
            burns: burns
                .into_iter()
                .map(|(holder, liquidity, burn)| ExitBurn {
                    holder,
                    liquidity,
                    outcome: answers.outcome(&burn).cloned(),
                })
                .collect(),
        })
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pool ({}, {})", self.user_token, self.validator_token)
    }
}

/// One holder burning all its liquidity to itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitBurn {
    /// The LP holder, which burns to itself.
    pub holder: Address,
    /// Its whole LP balance, burned.
    pub liquidity: U256,
    /// `None` when nothing answered it.
    pub outcome: Option<Outcome>,
}

/// The fee manager, the pool, and the accounts whose LP to burn.
#[derive(Debug, Clone, Copy)]
pub struct At<'a> {
    /// The fee manager to read and burn at.
    pub fee_manager: Address,
    /// The pool's user token.
    pub user_token: Address,
    /// The pool's validator token.
    pub validator_token: Address,
    /// The accounts whose LP to burn.
    pub holders: &'a [Address],
}

/// A burn with the pool as the burns before it left it.
#[derive(Debug, Clone, Copy)]
struct Turn<'a> {
    burn: &'a ExitBurn,
    reserve_user: U256,
    reserve_validator: U256,
    total_supply: U256,
}

impl fmt::Display for Turn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} exits", self.burn.holder)
    }
}

/// The exit's burns, each with the pool as the returned burns before it left it, up to the first
/// burn whose effect is unknown: one nothing answered, or one that returned what does not decode.
fn turns(exit: &Exit) -> Vec<Turn<'_>> {
    let (mut reserve_user, mut reserve_validator, mut total_supply) =
        (exit.reserve_user, exit.reserve_validator, exit.total_supply);
    let mut turns = Vec::with_capacity(exit.burns.len());
    for burn in &exit.burns {
        turns.push(Turn {
            burn,
            reserve_user,
            reserve_validator,
            total_supply,
        });
        match &burn.outcome {
            None => break,
            Some(Outcome::Revert(_) | Outcome::Halt) => {}
            Some(outcome @ Outcome::Return(_)) => {
                let Some(paid) = outcome.returns::<ITIPFeeAMM::burnCall>() else {
                    break;
                };
                let (Some(user), Some(validator), Some(supply)) = (
                    reserve_user.checked_sub(paid.amountUserToken),
                    reserve_validator.checked_sub(paid.amountValidatorToken),
                    total_supply.checked_sub(burn.liquidity),
                ) else {
                    break;
                };
                (reserve_user, reserve_validator, total_supply) = (user, validator, supply);
            }
        }
    }
    turns
}

pub const CHECKS: &[Check<Exit>] = &[
    check! {
        id: BURN_PRO_RATA,
        doc: "A burn pays `liquidity * reserve / totalSupply` of each token, rounded down.",
        over: |e: &Exit| turns(e),
        judge: |_, turn| {
            let paid = turn.burn.outcome.as_ref()?.returns::<ITIPFeeAMM::burnCall>()?;
            // The replayed supply reaches zero only on a corrupted pre-state, after which no burn is
            // judged, as is none whose product overflows.
            let share = |reserve: U256| {
                turn.burn.liquidity.checked_mul(reserve)?.checked_div(turn.total_supply)
            };
            let (user, validator) = (share(turn.reserve_user)?, share(turn.reserve_validator)?);
            ensure_eq!(
                (paid.amountUserToken, paid.amountValidatorToken),
                (user, validator),
                "burning {} of {} LP",
                turn.burn.liquidity,
                turn.total_supply
            )
        },
    },
    check! {
        id: EXIT,
        doc: "An LP holder burning its whole position never halts or panics.",
        over: |e: &Exit| turns(e),
        judge: |_, turn| match turn.burn.outcome.as_ref()? {
            Outcome::Halt => Some(Verdict::Broken("halted".to_string())),
            outcome => match outcome.revert::<GenericContractError>() {
                Some(ContractError::Panic(panic)) => {
                    Some(Verdict::Broken(format!("panicked with code {}", panic.code)))
                }
                _ => Some(Verdict::Holds),
            },
        },
    },
];

impl Checked<TempoHardfork> for Exit {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_primitives::{Bytes, address};
    use alloy_sol_types::{PanicKind, SolCall, SolError};
    use invariants_core::Report;

    const ALICE: Address = address!("0x0000000000000000000000000000000000000a11");
    const BOB: Address = address!("0x0000000000000000000000000000000000000b0b");

    fn paid(user: u64, validator: u64) -> Option<Outcome> {
        let returned = ITIPFeeAMM::burnCall::abi_encode_returns(&ITIPFeeAMM::burnReturn {
            amountUserToken: U256::from(user),
            amountValidatorToken: U256::from(validator),
        });
        Some(Outcome::Return(returned.into()))
    }

    /// A pool of 1000 user and 3000 validator tokens over 2000 LP, which Alice exits with 1000 LP
    /// and then Bob with 500.
    fn exit(alice: Option<Outcome>, bob: Option<Outcome>) -> Exit {
        let burn = |holder, liquidity: u64, outcome| ExitBurn {
            holder,
            liquidity: U256::from(liquidity),
            outcome,
        };
        Exit {
            user_token: Address::ZERO,
            validator_token: Address::ZERO,
            reserve_user: U256::from(1000),
            reserve_validator: U256::from(3000),
            total_supply: U256::from(2000),
            burns: vec![burn(ALICE, 1000, alice), burn(BOB, 500, bob)],
        }
    }

    fn judge(exit: &Exit) -> [(u64, u64, u64); 2] {
        let mut report = Report::default();
        report.run(CHECKS, exit, None);
        [BURN_PRO_RATA, EXIT].map(|id| {
            let counts = report.counts[id];
            (counts.evaluated, counts.armed, counts.fired)
        })
    }

    #[test]
    fn each_exit_pays_pro_rata_of_what_the_exits_before_it_left() {
        // Alice takes half, leaving 500 / 1500 over 1000 LP, of which Bob takes half again.
        assert_eq!(
            judge(&exit(paid(500, 1500), paid(250, 750))),
            [(2, 2, 0), (2, 2, 0)]
        );
        assert_eq!(
            judge(&exit(paid(500, 1500), paid(250, 749))),
            [(2, 2, 1), (2, 2, 0)]
        );
        // A burn that reverted left the pool as it was for the next.
        let reverted = Some(Outcome::Revert(Bytes::from_static(&[1, 2, 3, 4])));
        assert_eq!(
            judge(&exit(reverted, paid(250, 750))),
            [(2, 1, 0), (2, 2, 0)]
        );
        // An unanswered burn leaves the rest unknown.
        assert_eq!(judge(&exit(None, paid(250, 750))), [(1, 0, 0), (1, 0, 0)]);
        // On a corrupted pre-state Alice's 1000 LP is the whole supply, so Bob's burn is not
        // judged against the zero supply she left.
        let mut drained = exit(paid(1000, 3000), paid(0, 0));
        drained.total_supply = U256::from(1000);
        assert_eq!(judge(&drained), [(2, 1, 0), (2, 2, 0)]);
        // Nor is a burn whose `liquidity * reserve` overflows.
        let mut huge = exit(paid(500, 1500), paid(250, 750));
        huge.total_supply = U256::MAX;
        huge.burns[0].liquidity = U256::MAX;
        assert_eq!(judge(&huge), [(2, 0, 0), (2, 2, 0)]);
    }

    #[test]
    fn an_exit_never_halts_or_panics() {
        let panicked = Some(Outcome::Revert(
            alloy_sol_types::Panic::from(PanicKind::UnderOverflow)
                .abi_encode()
                .into(),
        ));
        assert_eq!(judge(&exit(panicked, paid(250, 750)))[1], (2, 2, 1));
        assert_eq!(
            judge(&exit(Some(Outcome::Halt), paid(250, 750)))[1],
            (2, 2, 1)
        );
    }
}
