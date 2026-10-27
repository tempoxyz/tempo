//! TIP-20 supply invariants, judged per token.

use std::fmt;

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use invariants_core::{Check, ObserveError, Verdict, Views, check, ensure, view, view_many};
use tempo_contracts::precompiles::ITIP20;

/// The tokens a step's state holds, as their views report them.
pub(super) struct Tokens(pub(super) Vec<Token>);

pub(super) struct Token {
    address: Address,
    /// `None` when a view failed: `error` says which.
    supply: Option<U256>,
    /// `None` when the pre-state cannot answer it or a view failed.
    cap: Option<U256>,
    balances: Option<Balances>,
    error: Option<String>,
}

enum Balances {
    Sum(U256),
    /// The sum left U256 when adding this account's balance.
    Overflow(Address),
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "token={}", self.address)
    }
}

pub(super) static CHECKS: &[Check<Tokens>] = &[
    // A token's views answer.
    check! {
        id: "TEMPO-TIP20-VIEW",
        over: |tokens: &Tokens| &tokens.0,
        judge: |_, t| Some(match &t.error {
            Some(error) => Verdict::Broken(error.clone()),
            None => Verdict::Holds,
        }),
    },
    // A zero cap is not exempt: minting checks the cap without exception, and setSupplyCap
    // rejects a cap below the supply.
    check! {
        id: "TEMPO-TIP20-SUPPLY-CAP",
        over: |tokens: &Tokens| &tokens.0,
        judge: |_, t| {
            let (supply, cap) = (t.supply?, t.cap?);
            ensure!(supply <= cap, "total_supply={supply} supply_cap={cap}")
        },
    },
    // The balances read sum to at most the supply, without overflow. They may be any subset of
    // the holders, so the sum is a lower bound.
    check! {
        id: "TEMPO-TIP20-BALANCE-SUM",
        over: |tokens: &Tokens| &tokens.0,
        judge: |_, t| {
            let supply = t.supply?;
            match t.balances.as_ref()? {
                Balances::Overflow(account) => {
                    Some(Verdict::Broken(format!("balances overflow at account={account}")))
                }
                Balances::Sum(sum) => ensure!(*sum <= supply, "balances={sum} total_supply={supply}"),
            }
        },
    },
];

/// `token` over `holders`, or `None` when the pre-state cannot answer its supply. A balance
/// nobody answers for is left out.
pub(super) fn observe<V: Views<Error = String>>(
    views: &mut V,
    address: Address,
    holders: &[Address],
) -> Option<Token> {
    let mut token = Token {
        address,
        supply: None,
        cap: None,
        balances: None,
        error: None,
    };
    match view(views, address, ITIP20::totalSupplyCall {}) {
        Ok(supply) => token.supply = Some(supply),
        Err(err) if err.is_not_answered() => return None,
        Err(err) => {
            token.error = Some(failed::<ITIP20::totalSupplyCall>(err));
            return Some(token);
        }
    }
    match view(views, address, ITIP20::supplyCapCall {}) {
        Ok(cap) => token.cap = Some(cap),
        Err(err) if err.is_not_answered() => {}
        Err(err) => token.error = Some(failed::<ITIP20::supplyCapCall>(err)),
    }
    match balances(views, address, holders) {
        Ok(balances) => token.balances = Some(balances),
        Err(error) => token.error = token.error.or(Some(error)),
    }
    Some(token)
}

fn balances<V: Views<Error = String>>(
    views: &mut V,
    token: Address,
    holders: &[Address],
) -> Result<Balances, String> {
    let calls: Vec<_> = holders
        .iter()
        .map(|&account| (token, ITIP20::balanceOfCall { account }))
        .collect();
    let mut sum = U256::ZERO;
    for (&account, balance) in holders
        .iter()
        .zip(view_many(views, &calls).map_err(failed::<ITIP20::balanceOfCall>)?)
    {
        let Some(next) = balance.map_or(Some(sum), |balance| sum.checked_add(balance)) else {
            return Ok(Balances::Overflow(account));
        };
        sum = next;
    }
    Ok(Balances::Sum(sum))
}

/// Why `C` could not be read, naming the view.
fn failed<C: SolCall>(err: ObserveError<String>) -> String {
    match err {
        ObserveError::Views(err) => format!("{}: {err}", C::SIGNATURE),
        err => err.to_string(),
    }
}
