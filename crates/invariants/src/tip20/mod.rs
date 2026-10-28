//! TIP-20: a token's supply, its supply cap, and the balances of a known set
//! of accounts, alone and against the `Transfer` events that changed them.
//!
//! The accounts need not be every holder, so [`CHECKS`] and [`STEP_CHECKS`]
//! assert only what holds for any subset of them.

use std::{collections::BTreeMap, fmt};

use alloy_primitives::{Address, Bytes, LogData, U256};
use alloy_sol_types::{SolCall, SolEvent};

use crate::{Observe, ObserveError, Replay, Views, decode, optional, or_text};

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

/// The ledger after a step is the ledger before it with the step's `Transfer`s replayed: each
/// observed balance moves by the transfers into and out of it, and the supply by the mints (from
/// the zero address) and burns (to it). A transfer between an observed and an unobserved account
/// moves only the observed side.
impl Replay<Transfer> for Ledger {
    type Error = Unapplied;

    fn replay(&self, transfers: &[Transfer]) -> Result<Self, Unapplied> {
        let mut next = self.clone();
        for t in transfers {
            if t.from.is_zero() {
                next.supply =
                    next.supply
                        .checked_add(t.amount)
                        .ok_or(Unapplied::MintOverflows {
                            amount: t.amount,
                            supply: next.supply,
                        })?;
            } else if let Some(balance) = next.balances.get_mut(&t.from) {
                *balance = balance.checked_sub(t.amount).ok_or(Unapplied::Overspends {
                    from: t.from,
                    amount: t.amount,
                    balance: *balance,
                })?;
            }
            if t.to.is_zero() {
                next.supply = next
                    .supply
                    .checked_sub(t.amount)
                    .ok_or(Unapplied::BurnExceeds {
                        amount: t.amount,
                        supply: next.supply,
                    })?;
            } else if let Some(balance) = next.balances.get_mut(&t.to) {
                *balance = balance
                    .checked_add(t.amount)
                    .ok_or(Unapplied::ReceiveOverflows {
                        to: t.to,
                        amount: t.amount,
                        balance: *balance,
                    })?;
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
