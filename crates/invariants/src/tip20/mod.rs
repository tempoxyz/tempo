//! TIP-20: a token's supply, its supply cap, and the balances of a known set
//! of accounts, alone and against the `Transfer` events that changed them.
//!
//! The accounts need not be every holder, so [`CHECKS`] and [`STEP_CHECKS`]
//! assert only what holds for any subset of them.

use std::{collections::BTreeMap, fmt};

use alloy_primitives::{Address, Bytes, Log, LogData, U256};
use alloy_sol_types::{SolCall, SolEvent};

use crate::{Observe, ObserveError, Replay, Views, decode, optional, or_text};

use tempo_contracts::precompiles::ITIP20::{Burn, BurnAt, BurnBlocked, Mint};

pub use tempo_contracts::precompiles::ITIP20::{self, Transfer};

mod checks;

pub use checks::{BALANCE_SUM, CHECKS, STEP_CHECKS, SUPPLY_CAP, TRANSFER_EVENTS, VIEW};

/// A token's state, as its views report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    pub token: Address,
    pub supply: U256,
    /// `None` when nothing answered it.
    pub supply_cap: Option<U256>,
    /// Balances of the observed accounts.
    pub balances: BTreeMap<Address, U256>,
}

impl Ledger {
    /// The sum of the observed balances, or `None` if it overflows.
    /// `self` and `other` over only the accounts both read.
    fn common(&self, other: &Self) -> (Self, Self) {
        let mut this = self.clone();
        let mut that = other.clone();
        this.balances
            .retain(|account, _| other.balances.contains_key(account));
        that.balances
            .retain(|account, _| self.balances.contains_key(account));
        (this, that)
    }

    pub fn balance_sum(&self) -> Option<U256> {
        self.balances
            .values()
            .try_fold(U256::ZERO, |sum, balance| sum.checked_add(*balance))
    }

    /// Fields of `self` that differ in `other`, as `field: self -> other`.
    pub fn diff(&self, other: &Self) -> String {
        let mut out: Vec<String> = self
            .balances
            .iter()
            .filter(|(account, balance)| other.balances.get(*account) != Some(*balance))
            .map(|(account, balance)| {
                format!("{account}: {balance} -> {:?}", other.balances.get(account))
            })
            .collect();
        if self.supply != other.supply {
            out.push(format!("supply: {} -> {}", self.supply, other.supply));
        }
        if self.supply_cap != other.supply_cap {
            out.push(format!(
                "supplyCap: {} -> {}",
                or_text(self.supply_cap, "?"),
                or_text(other.supply_cap, "?")
            ));
        }
        out.join(", ")
    }

    fn mint(&mut self, amount: U256) -> Result<(), Unapplied> {
        self.supply = self
            .supply
            .checked_add(amount)
            .ok_or(Unapplied::MintOverflows {
                amount,
                supply: self.supply,
            })?;
        Ok(())
    }

    fn burn(&mut self, amount: U256) -> Result<(), Unapplied> {
        self.supply = self
            .supply
            .checked_sub(amount)
            .ok_or(Unapplied::BurnExceeds {
                amount,
                supply: self.supply,
            })?;
        Ok(())
    }

    /// Debits `from` if it is observed.
    fn debit(&mut self, from: Address, amount: U256) -> Result<(), Unapplied> {
        if let Some(balance) = self.balances.get_mut(&from) {
            *balance = balance.checked_sub(amount).ok_or(Unapplied::Overspends {
                from,
                amount,
                balance: *balance,
            })?;
        }
        Ok(())
    }

    /// Credits `to` if it is observed.
    fn credit(&mut self, to: Address, amount: U256) -> Result<(), Unapplied> {
        if let Some(balance) = self.balances.get_mut(&to) {
            *balance = balance
                .checked_add(amount)
                .ok_or(Unapplied::ReceiveOverflows {
                    to,
                    amount,
                    balance: *balance,
                })?;
        }
        Ok(())
    }
}

impl Observe for Ledger {
    type At<'a> = At<'a>;

    /// Reads the token's supply, supply cap and the holders' balances, in one batch of view
    /// calls. Over partial views a supply cap or balance nothing answers is left out; the supply
    /// must answer.
    fn observe<V: Views>(views: &mut V, at: At<'_>) -> Result<Self, ObserveError<V::Error>> {
        let At {
            token,
            holders: accounts,
        } = at;
        let calls: Vec<(Address, Bytes)> = [
            ITIP20::totalSupplyCall {}.abi_encode(),
            ITIP20::supplyCapCall {}.abi_encode(),
        ]
        .into_iter()
        .chain(
            accounts
                .iter()
                .map(|&account| ITIP20::balanceOfCall { account }.abi_encode()),
        )
        .map(|input| (token, input.into()))
        .collect();
        let mut outputs = views.call(&calls).map_err(ObserveError::Views)?.into_iter();
        let supply = decode::<ITIP20::totalSupplyCall, _>(token, outputs.next())?;
        let supply_cap = optional(
            views,
            decode::<ITIP20::supplyCapCall, _>(token, outputs.next()),
        )?;
        let mut balances = BTreeMap::new();
        for &account in accounts {
            let balance = decode::<ITIP20::balanceOfCall, _>(token, outputs.next());
            if let Some(balance) = optional(views, balance)? {
                balances.insert(account, balance);
            }
        }
        Ok(Self {
            token,
            supply,
            supply_cap,
            balances,
        })
    }
}

/// What one of a token's `Transfer` events moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Move {
    /// A transfer, a mint (from the zero address) or a burn (to it).
    Transfer(Transfer),
    /// (-T3) A mint to the zero address, which credits its balance.
    ZeroMint(U256),
    /// A burn from the zero address' balance, which only a (-T3) [`Move::ZeroMint`] fills.
    ZeroBurn(U256),
}

/// The `Transfer`s in a token's `logs`, in order. A `Transfer` from and to the zero address
/// is a mint to it or a burn from it, which only the `Mint` or `Burn*` event to or from the
/// zero address that follows it, before the next `Transfer`, tells apart.
pub(crate) fn moves<'a>(logs: impl IntoIterator<Item = &'a Log>) -> Vec<Move> {
    let logs: Vec<&LogData> = logs.into_iter().map(|log| &log.data).collect();
    logs.iter()
        .enumerate()
        .filter_map(|(i, log)| {
            let t = transfer(log)?;
            if !(t.from.is_zero() && t.to.is_zero()) {
                return Some(Move::Transfer(t));
            }
            let kind = logs[i + 1..]
                .iter()
                .take_while(|log| transfer(log).is_none())
                .find_map(|log| {
                    if Mint::decode_log_data(log).is_ok_and(|e| e.to.is_zero()) {
                        Some(Move::ZeroMint(t.amount))
                    } else if Burn::decode_log_data(log).is_ok_and(|e| e.from.is_zero())
                        || BurnBlocked::decode_log_data(log).is_ok_and(|e| e.from.is_zero())
                        || BurnAt::decode_log_data(log).is_ok_and(|e| e.from.is_zero())
                    {
                        Some(Move::ZeroBurn(t.amount))
                    } else {
                        None
                    }
                });
            Some(kind.unwrap_or(Move::Transfer(t)))
        })
        .collect()
}

/// The ledger after a step is the ledger before it with the step's `Move`s replayed: each
/// observed balance moves by the transfers into and out of it, and the supply by the mints (from
/// the zero address) and burns (to it). The zero address' own balance moves only by
/// `Move::ZeroMint` and `Move::ZeroBurn`. A transfer between an observed and an unobserved
/// account moves only the observed side.
impl Replay<Move> for Ledger {
    type Error = Unapplied;

    fn replay(&self, moves: &[Move]) -> Result<Self, Unapplied> {
        let mut next = self.clone();
        for m in moves {
            match m {
                Move::Transfer(t) => {
                    if t.from.is_zero() {
                        next.mint(t.amount)?;
                    } else {
                        next.debit(t.from, t.amount)?;
                    }
                    if t.to.is_zero() {
                        next.burn(t.amount)?;
                    } else {
                        next.credit(t.to, t.amount)?;
                    }
                }
                Move::ZeroMint(amount) => {
                    next.mint(*amount)?;
                    next.credit(Address::ZERO, *amount)?;
                }
                Move::ZeroBurn(amount) => {
                    next.debit(Address::ZERO, *amount)?;
                    next.burn(*amount)?;
                }
            }
        }
        Ok(next)
    }
}

/// A token and the accounts whose balances to read.
#[derive(Debug, Clone, Copy)]
pub struct At<'a> {
    pub token: Address,
    pub holders: &'a [Address],
}

/// Why `Transfer`s do not apply to a [`Ledger`]: a balance or the supply would leave `U256`.
#[derive(Debug, Clone, Copy)]
pub enum Unapplied {
    MintOverflows {
        amount: U256,
        supply: U256,
    },
    Overspends {
        from: Address,
        amount: U256,
        balance: U256,
    },
    BurnExceeds {
        amount: U256,
        supply: U256,
    },
    ReceiveOverflows {
        to: Address,
        amount: U256,
        balance: U256,
    },
}

impl fmt::Display for Unapplied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MintOverflows { amount, supply } => {
                write!(f, "minting {amount} overflows the supply {supply}")
            }
            Self::Overspends {
                from,
                amount,
                balance,
            } => {
                write!(f, "{from} spends {amount} of {balance}")
            }
            Self::BurnExceeds { amount, supply } => {
                write!(f, "burning {amount} exceeds the supply {supply}")
            }
            Self::ReceiveOverflows {
                to,
                amount,
                balance,
            } => {
                write!(f, "{to} receives {amount} on {balance}")
            }
        }
    }
}

/// Decodes a `Transfer` event. Returns `None` for any other log, including
/// one with `Transfer`'s signature that does not decode.
pub fn transfer(log: &LogData) -> Option<Transfer> {
    // ABI decoding ignores trailing bytes, and `Transfer`'s data is one word.
    (log.data.len() == 32)
        .then(|| Transfer::decode_log_data(log).ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_primitives::address;
    use test_case::test_case;

    const TOKEN: Address = address!("0x20C0000000000000000000000000000000000000");
    const HOLDER: Address = address!("0x0000000000000000000000000000000000001234");

    fn log(event: &impl SolEvent) -> Log {
        Log {
            address: TOKEN,
            data: event.encode_log_data(),
        }
    }

    fn ledger(supply: u64, zero: u64, holder: u64) -> Ledger {
        Ledger {
            token: TOKEN,
            supply: U256::from(supply),
            supply_cap: None,
            balances: BTreeMap::from([
                (Address::ZERO, U256::from(zero)),
                (HOLDER, U256::from(holder)),
            ]),
        }
    }

    fn transfer(from: Address, to: Address, amount: u64) -> Transfer {
        Transfer {
            from,
            to,
            amount: U256::from(amount),
        }
    }

    #[test]
    fn mint_to_zero_credits_zero() {
        let one = U256::from(1);
        let logs = [
            log(&transfer(Address::ZERO, Address::ZERO, 1)),
            log(&Mint {
                to: Address::ZERO,
                amount: one,
            }),
        ];
        let moves = moves(&logs);
        assert_eq!(moves, [Move::ZeroMint(one)]);
        assert_eq!(ledger(10, 0, 5).replay(&moves).unwrap(), ledger(11, 1, 5));
    }

    #[test_case(log(&Burn { from: Address::ZERO, amount: U256::from(2) }) ; "burn")]
    #[test_case(log(&BurnBlocked { from: Address::ZERO, amount: U256::from(2) }) ; "burn blocked")]
    #[test_case(log(&BurnAt { burner: HOLDER, from: Address::ZERO, amount: U256::from(2) }) ; "burn at")]
    fn burn_from_zero_debits_zero(burn: Log) {
        let logs = [log(&transfer(Address::ZERO, Address::ZERO, 2)), burn];
        let moves = moves(&logs);
        assert_eq!(moves, [Move::ZeroBurn(U256::from(2))]);
        assert_eq!(ledger(10, 3, 5).replay(&moves).unwrap(), ledger(8, 1, 5));
    }

    #[test]
    fn burn_from_zero_overspends() {
        let result = ledger(10, 1, 5).replay(&[Move::ZeroBurn(U256::from(2))]);
        assert!(
            matches!(
                result,
                Err(Unapplied::Overspends { from, amount, balance })
                    if from.is_zero() && amount == U256::from(2) && balance == U256::from(1)
            ),
            "{result:?}"
        );
    }

    #[test]
    fn mint_burn_and_transfer() {
        let logs = [
            log(&transfer(Address::ZERO, HOLDER, 4)),
            log(&Mint {
                to: HOLDER,
                amount: U256::from(4),
            }),
            log(&transfer(HOLDER, Address::ZERO, 3)),
            log(&Burn {
                from: HOLDER,
                amount: U256::from(3),
            }),
        ];
        let moves = moves(&logs);
        assert_eq!(moves.len(), 2);
        assert_eq!(ledger(10, 0, 5).replay(&moves).unwrap(), ledger(11, 0, 6));
    }

    #[test]
    fn mint_to_holder_after_zero_transfer_is_not_a_zero_mint() {
        // The `Mint` belongs to the second `Transfer`, so the first stays a plain one.
        let logs = [
            log(&transfer(Address::ZERO, Address::ZERO, 1)),
            log(&transfer(Address::ZERO, HOLDER, 1)),
            log(&Mint {
                to: Address::ZERO,
                amount: U256::from(1),
            }),
        ];
        assert_eq!(
            moves(&logs)[0],
            Move::Transfer(transfer(Address::ZERO, Address::ZERO, 1))
        );
    }
}
