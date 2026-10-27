//! TIP-20 supply invariants.

use alloy_primitives::{Address, U256};
use invariants_core::{Check, Layer, Views, view, view_many};
use tempo_contracts::precompiles::ITIP20;

/// A token's supply, cap and the sum of the balances read, or why they could not be read.
pub(super) struct Token {
    token: Address,
    read: Result<Ledger, String>,
}

struct Ledger {
    supply: U256,
    /// `None` when the pre-state cannot answer it.
    cap: Option<U256>,
    balances: Balances,
}

enum Balances {
    Sum(U256),
    /// The sum left U256 when adding this account's balance.
    Overflow(Address),
}

pub(super) static CHECKS: &[Check<Token>] = &[
    // A token's views answer.
    Check {
        id: "TEMPO-TIP20-VIEW",
        layer: Layer::State,
        run: |t, p| {
            if let Err(error) = &t.read {
                p.fail(format!("token={} {error}", t.token));
            }
        },
    },
    // A zero cap is not exempt: minting checks the cap without exception, and setSupplyCap
    // rejects a cap below the supply.
    Check {
        id: "TEMPO-TIP20-SUPPLY-CAP",
        layer: Layer::State,
        run: |t, p| {
            let Ok(Ledger {
                supply,
                cap: Some(cap),
                ..
            }) = &t.read
            else {
                p.when(false);
                return;
            };
            p.ensure(supply <= cap, || {
                format!("token={} total_supply={supply} supply_cap={cap}", t.token)
            });
        },
    },
    // The balances read sum to at most the supply, without overflow. They may be any subset of
    // the holders, so the sum is a lower bound.
    Check {
        id: "TEMPO-TIP20-BALANCE-SUM",
        layer: Layer::State,
        run: |t, p| {
            let Ok(Ledger {
                supply, balances, ..
            }) = &t.read
            else {
                p.when(false);
                return;
            };
            match balances {
                Balances::Overflow(account) => p.fail(format!(
                    "token={} balances overflow at account={account}",
                    t.token
                )),
                Balances::Sum(sum) => {
                    p.ensure(sum <= supply, || {
                        format!("token={} balances={sum} total_supply={supply}", t.token)
                    });
                }
            }
        },
    },
];

/// `token`'s ledger over `holders`, or `None` when the pre-state cannot answer its supply. A
/// balance nobody answers for is left out.
pub(super) fn observe<V: Views<Error = String>>(
    views: &mut V,
    token: Address,
    holders: &[Address],
) -> Option<Token> {
    let read = read(views, token, holders).transpose()?;
    Some(Token { token, read })
}

fn read<V: Views<Error = String>>(
    views: &mut V,
    token: Address,
    holders: &[Address],
) -> Result<Option<Ledger>, String> {
    let supply = match view(views, token, ITIP20::totalSupplyCall {}) {
        Ok(supply) => supply,
        Err(err) if err.is_not_answered() => return Ok(None),
        Err(err) => return Err(err.to_string()),
    };
    let cap = match view(views, token, ITIP20::supplyCapCall {}) {
        Ok(cap) => Some(cap),
        Err(err) if err.is_not_answered() => None,
        Err(err) => return Err(err.to_string()),
    };
    let calls: Vec<_> = holders
        .iter()
        .map(|&account| (token, ITIP20::balanceOfCall { account }))
        .collect();
    let mut sum = U256::ZERO;
    for (&account, balance) in holders
        .iter()
        .zip(view_many(views, &calls).map_err(|err| err.to_string())?)
    {
        let Some(next) = balance.map_or(Some(sum), |balance| sum.checked_add(balance)) else {
            return Ok(Some(Ledger {
                supply,
                cap,
                balances: Balances::Overflow(account),
            }));
        };
        sum = next;
    }
    Ok(Some(Ledger {
        supply,
        cap,
        balances: Balances::Sum(sum),
    }))
}
