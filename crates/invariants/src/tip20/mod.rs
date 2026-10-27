//! TIP-20: a token's supply, its supply cap, and the balances of a known set
//! of accounts, alone and against the `Transfer` events that changed them.
//!
//! The accounts need not be every holder, so [`CHECKS`] and [`STEP_CHECKS`]
//! assert only what holds for any subset of them.

use std::collections::BTreeMap;

use alloy_primitives::{Address, Bytes, LogData, U256};
use alloy_sol_types::{SolCall, SolEvent, sol};

use crate::{ObserveError, Views, decode, or_text};

sol! {
    #[derive(Debug, PartialEq, Eq)]
    interface ITIP20 {
        function totalSupply() external view returns (uint256);
        function supplyCap() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        event Transfer(address indexed from, address indexed to, uint256 amount);
    }
}

pub use ITIP20::Transfer;

mod checks;

pub use checks::{BALANCE_SUM, CHECKS, STEP_CHECKS, SUPPLY_CAP, TRANSFER_EVENTS};

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

/// Decodes a `Transfer` event. Returns `None` for any other log, including
/// one with `Transfer`'s signature that does not decode.
pub fn decode_transfer(log: &LogData) -> Option<Transfer> {
    // ABI decoding ignores trailing bytes, and `Transfer`'s data is one word.
    (log.data.len() == 32)
        .then(|| Transfer::decode_log_data(log).ok())
        .flatten()
}

/// Reads `token`'s supply, supply cap and the balances of `accounts`, in one
/// batch of view calls. Every view must answer.
pub fn observe<V: Views>(
    views: &mut V,
    token: Address,
    accounts: &[Address],
) -> Result<Ledger, ObserveError<V::Error>> {
    read(views, token, accounts, false)
}

/// Like [`observe`], over a partial state: a supply cap or balance nothing answers is left out.
/// The supply must still answer.
pub fn observe_partial<V: Views>(
    views: &mut V,
    token: Address,
    accounts: &[Address],
) -> Result<Ledger, ObserveError<V::Error>> {
    read(views, token, accounts, true)
}

fn read<V: Views>(
    views: &mut V,
    token: Address,
    accounts: &[Address],
    partial: bool,
) -> Result<Ledger, ObserveError<V::Error>> {
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
    let supply_cap = answered(
        decode::<ITIP20::supplyCapCall, _>(token, outputs.next()),
        partial,
    )?;
    let mut balances = BTreeMap::new();
    for &account in accounts {
        let balance = decode::<ITIP20::balanceOfCall, _>(token, outputs.next());
        if let Some(balance) = answered(balance, partial)? {
            balances.insert(account, balance);
        }
    }
    Ok(Ledger {
        token,
        supply,
        supply_cap,
        balances,
    })
}

/// §Ok(None)§ for a view nothing answered, if §partial§.
fn answered<T, E>(
    read: Result<T, ObserveError<E>>,
    partial: bool,
) -> Result<Option<T>, ObserveError<E>> {
    match read {
        Ok(value) => Ok(Some(value)),
        Err(err) if partial && err.is_not_answered() => Ok(None),
        Err(err) => Err(err),
    }
}

/// `ledger` after `transfers`, or `Err` if a balance or the supply would
/// leave `U256`.
fn apply(ledger: &Ledger, transfers: &[Transfer]) -> Result<Ledger, String> {
    let mut next = ledger.clone();
    for t in transfers {
        if t.from.is_zero() {
            next.supply = next.supply.checked_add(t.amount).ok_or_else(|| {
                format!("minting {} overflows the supply {}", t.amount, next.supply)
            })?;
        } else if let Some(balance) = next.balances.get_mut(&t.from) {
            *balance = balance
                .checked_sub(t.amount)
                .ok_or_else(|| format!("{} spends {} of {balance}", t.from, t.amount))?;
        }
        if t.to.is_zero() {
            next.supply = next.supply.checked_sub(t.amount).ok_or_else(|| {
                format!("burning {} exceeds the supply {}", t.amount, next.supply)
            })?;
        } else if let Some(balance) = next.balances.get_mut(&t.to) {
            *balance = balance
                .checked_add(t.amount)
                .ok_or_else(|| format!("{} receives {} on {balance}", t.to, t.amount))?;
        }
    }
    Ok(next)
}
