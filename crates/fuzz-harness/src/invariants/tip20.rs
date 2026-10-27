//! TIP-20 supply invariants.
//!
//! - `TEMPO-TIP20-SUPPLY-CAP`: a token's `totalSupply` does not exceed its `supplyCap`. A zero cap
//!   is not exempt: minting checks the cap without exception, and `setSupplyCap` rejects a cap
//!   below the supply.
//! - `TEMPO-TIP20-BALANCE-SUM`: the balances of the accounts the state holds sum to at most
//!   `totalSupply`, without overflow.
//! - `TEMPO-TIP20-VIEW`: a token's views answer.

use alloy_primitives::{Address, U256};
use tempo_contracts::precompiles::ITIP20;
use tempo_primitives::is_tip20_prefix;

use super::Views;

/// Invariants broken by each TIP-20 among `accounts` for which `selected` holds, as `(id, message)`.
pub(super) fn check(
    views: &mut Views<'_>,
    accounts: &[Address],
    selected: impl Fn(&Address) -> bool,
) -> Vec<(&'static str, String)> {
    let mut failures = Vec::new();
    let tokens = accounts
        .iter()
        .filter(|account| is_tip20_prefix(**account) && selected(account));
    for &token in tokens {
        if let Err(message) = check_token(views, token, accounts, &mut failures) {
            failures.push(("TEMPO-TIP20-VIEW", message));
        }
    }
    failures
}

fn check_token(
    views: &mut Views<'_>,
    token: Address,
    accounts: &[Address],
    failures: &mut Vec<(&'static str, String)>,
) -> Result<(), String> {
    let Some(supply) = views.call(token, ITIP20::totalSupplyCall {})? else {
        return Ok(());
    };
    if let Some(cap) = views.call(token, ITIP20::supplyCapCall {})?
        && supply > cap
    {
        failures.push((
            "TEMPO-TIP20-SUPPLY-CAP",
            format!("token={token} total_supply={supply} supply_cap={cap}"),
        ));
    }

    let mut sum = U256::ZERO;
    for &account in accounts {
        // A balance nobody answers for is left out: a subset sums to less.
        let Some(balance) = views.call(token, ITIP20::balanceOfCall { account })? else {
            continue;
        };
        let Some(next) = sum.checked_add(balance) else {
            failures.push((
                "TEMPO-TIP20-BALANCE-SUM",
                format!("token={token} balances overflow at account={account}"),
            ));
            return Ok(());
        };
        sum = next;
    }
    if sum > supply {
        failures.push((
            "TEMPO-TIP20-BALANCE-SUM",
            format!("token={token} balances={sum} total_supply={supply}"),
        ));
    }
    Ok(())
}
