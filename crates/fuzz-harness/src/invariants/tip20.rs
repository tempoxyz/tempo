//! TIP-20: a token's supply, its supply cap, and the balances of a known set
//! of accounts, alone and against the `Transfer` events that changed them.
//!
//! The accounts need not be every holder, so [`check`] and [`check_transfers`]
//! assert only what holds for any subset of them.

use std::{collections::BTreeMap, fmt};

use alloy_primitives::{Address, Bytes, LogData, U256};
use alloy_sol_types::{SolCall, SolEvent, sol};

use invariants_core::{check, ensure};

use super::{Check, ObserveError, Verdict, Views, Violation, decode, judge};

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
                "supplyCap: {:?} -> {:?}",
                self.supply_cap, other.supply_cap
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
/// batch of view calls.
pub fn observe<V: Views>(
    views: &mut V,
    token: Address,
    accounts: &[Address],
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
    let supply_cap = answered(decode::<ITIP20::supplyCapCall, _>(token, outputs.next()))?;
    let mut balances = BTreeMap::new();
    for &account in accounts {
        let balance = decode::<ITIP20::balanceOfCall, _>(token, outputs.next());
        if let Some(balance) = answered(balance)? {
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

/// `Ok(None)` for a view nothing answered, such as one reading outside a partial state.
fn answered<T, E>(read: Result<T, ObserveError<E>>) -> Result<Option<T>, ObserveError<E>> {
    match read {
        Ok(value) => Ok(Some(value)),
        Err(err) if err.is_not_answered() => Ok(None),
        Err(err) => Err(err),
    }
}

pub const SUPPLY_CAP: &str = "TEMPO-TIP20-SUPPLY-CAP";
pub const BALANCE_SUM: &str = "TEMPO-TIP20-BALANCE-SUM";
pub const TRANSFER_EVENTS: &str = "TEMPO-TIP20-TRANSFER-EVENTS";

impl fmt::Display for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "token={}", self.token)
    }
}

/// A token's supply and the balances read of it.
pub static CHECKS: &[Check<Ledger>] = &[
    // A zero cap is not exempt: minting checks the cap with no exception, and `setSupplyCap`
    // rejects a cap below the supply.
    check! {
        id: SUPPLY_CAP,
        over: |ledger: &Ledger| [ledger],
        judge: |_, l| {
            let cap = l.supply_cap?;
            ensure!(l.supply <= cap, "totalSupply {} exceeds supplyCap {cap}", l.supply)
        },
    },
    // The balances read may be any subset of the holders, so their sum is a lower bound.
    check! {
        id: BALANCE_SUM,
        over: |ledger: &Ledger| [ledger],
        judge: |_, l| {
            let sum = l.balance_sum();
            ensure!(
                sum.is_some_and(|sum| sum <= l.supply),
                "balances sum to {}, totalSupply {}: {:?}",
                sum.map_or_else(|| "more than 2^256".to_string(), |sum| sum.to_string()),
                l.supply,
                l.balances
            )
        },
    },
];

/// The violations of [`CHECKS`] in `ledger`.
pub fn check(ledger: &Ledger) -> Vec<Violation> {
    judge(CHECKS, ledger)
}

/// A token's ledger before and after `transfers`.
pub struct Transition {
    pub pre: Ledger,
    pub post: Ledger,
    pub transfers: Vec<Transfer>,
}

impl fmt::Display for Transition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.post.fmt(f)
    }
}

/// Each observed balance moves by exactly the transfers into and out of it, never going
/// negative, and the supply by the mints (from the zero address) and burns (to it). A transfer
/// between an observed and an unobserved account moves only the observed side.
pub static TRANSITION_CHECKS: &[Check<Transition>] = &[check! {
    id: TRANSFER_EVENTS,
    over: |transition: &Transition| [transition],
    judge: |_, t| {
        let detail = match apply(&t.pre, &t.transfers) {
            // `Transfer` events say nothing of the cap.
            Ok(want) if want.balances == t.post.balances && want.supply == t.post.supply => {
                return Some(Verdict::Holds);
            }
            Ok(want) => format!("expected -> read: {}", want.diff(&t.post)),
            Err(e) => format!("on the earlier balances: {e}"),
        };
        Some(Verdict::Broken(format!("{} transfers; {detail}", t.transfers.len())))
    },
}];

/// The violations of [`TRANSITION_CHECKS`] from `pre` to `post` through `transfers`, in order.
pub fn check_transfers(pre: &Ledger, post: &Ledger, transfers: &[Transfer]) -> Vec<Violation> {
    judge(
        TRANSITION_CHECKS,
        &Transition {
            pre: pre.clone(),
            post: post.clone(),
            transfers: transfers.to_vec(),
        },
    )
}

/// `ledger` after `transfers`, or `Err` if a balance or the supply would
/// leave `U256`.
fn apply(ledger: &Ledger, transfers: &[Transfer]) -> Result<Ledger, String> {
    let mut next = ledger.clone();
    for t in transfers {
        if t.from == Address::ZERO {
            next.supply = next.supply.checked_add(t.amount).ok_or_else(|| {
                format!("minting {} overflows the supply {}", t.amount, next.supply)
            })?;
        } else if let Some(balance) = next.balances.get_mut(&t.from) {
            *balance = balance
                .checked_sub(t.amount)
                .ok_or_else(|| format!("{} spends {} of {balance}", t.from, t.amount))?;
        }
        if t.to == Address::ZERO {
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
