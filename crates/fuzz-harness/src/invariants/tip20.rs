use std::collections::BTreeSet;

use alloy_primitives::{Address, U256};
use tempo_contracts::precompiles::ITIP20;
use tempo_fuzz_types::StateInput;

use super::{HarnessEvm, fmt_addr, is_tip20_like, state_accounts, view_call};

pub(super) fn validate(
    evm: &mut HarnessEvm<'_>,
    side: &'static str,
    state: &StateInput,
) -> Result<(), String> {
    check_supply(evm, side, state)
}

fn check_supply(
    evm: &mut HarnessEvm<'_>,
    side: &'static str,
    state: &StateInput,
) -> Result<(), String> {
    let tokens = known_tip20_tokens(state);
    let accounts = known_accounts(state);

    for token in tokens {
        let Some(total_supply) = total_supply(evm, token)? else {
            continue;
        };

        let decimals = view_call::<ITIP20::decimalsCall>(evm, token, ITIP20::decimalsCall {})?
            .ok_or_else(|| {
                format!(
                    "TEMPO-TIP21 side={side} token={} empty decimals",
                    fmt_addr(token)
                )
            })?;
        if decimals != 6 {
            return Err(format!(
                "TEMPO-TIP21 side={side} token={} decimals={decimals} expected=6",
                fmt_addr(token)
            ));
        }

        if let Some(opted_in_supply) =
            view_call::<ITIP20::optedInSupplyCall>(evm, token, ITIP20::optedInSupplyCall {})?
            && U256::from(opted_in_supply) > total_supply
        {
            return Err(format!(
                "TEMPO-TIP19 side={side} token={} opted_in_supply={} total_supply={total_supply}",
                fmt_addr(token),
                opted_in_supply
            ));
        }

        check_quote_token_chain(evm, side, token)?;

        if let Some(supply_cap) = supply_cap(evm, token)?
            && !supply_cap.is_zero()
            && total_supply > supply_cap
        {
            return Err(format!(
                "TEMPO-TIP20-SUPPLY-CAP side={side} token={} total_supply={} supply_cap={}",
                fmt_addr(token),
                total_supply,
                supply_cap
            ));
        }

        let mut known_balance_sum = U256::ZERO;
        for account in &accounts {
            let balance = balance_of(evm, token, *account)?.unwrap_or(U256::ZERO);
            known_balance_sum = known_balance_sum.checked_add(balance).ok_or_else(|| {
                format!(
                    "TEMPO-TIP20-BALANCE-SUM side={side} token={} known balance summation overflowed",
                    fmt_addr(token)
                )
            })?;
        }

        if known_balance_sum > total_supply {
            let final_excess = known_balance_sum.saturating_sub(total_supply);
            return Err(format!(
                "TEMPO-TIP20-BALANCE-SUM side={side} token={} known_balances={} total_supply={} excess={}",
                fmt_addr(token),
                known_balance_sum,
                total_supply,
                final_excess
            ));
        }
    }

    Ok(())
}

fn check_quote_token_chain(
    evm: &mut HarnessEvm<'_>,
    side: &'static str,
    token: Address,
) -> Result<(), String> {
    let mut current = token;
    let mut seen = BTreeSet::from([token]);
    for depth in 0..20 {
        let Some(next) =
            view_call::<ITIP20::quoteTokenCall>(evm, current, ITIP20::quoteTokenCall {})?
        else {
            return Ok(());
        };
        if next.is_zero() {
            return Ok(());
        }
        if !seen.insert(next) {
            return Err(format!(
                "TEMPO-TIP20-QUOTE-CYCLE side={side} token={} repeated={} depth={}",
                fmt_addr(token),
                fmt_addr(next),
                depth + 1
            ));
        }
        current = next;
    }
    Err(format!(
        "TEMPO-TIP20-QUOTE-DEPTH side={side} token={} max_depth=20",
        fmt_addr(token)
    ))
}

fn known_tip20_tokens(state: &StateInput) -> BTreeSet<Address> {
    state_accounts(state)
        .filter(|address| is_tip20_like(*address))
        .collect()
}

fn known_accounts(state: &StateInput) -> BTreeSet<Address> {
    state_accounts(state).collect()
}

fn total_supply(evm: &mut HarnessEvm<'_>, token: Address) -> Result<Option<U256>, String> {
    view_call::<ITIP20::totalSupplyCall>(evm, token, ITIP20::totalSupplyCall {})
}

fn supply_cap(evm: &mut HarnessEvm<'_>, token: Address) -> Result<Option<U256>, String> {
    view_call::<ITIP20::supplyCapCall>(evm, token, ITIP20::supplyCapCall {})
}

fn balance_of(
    evm: &mut HarnessEvm<'_>,
    token: Address,
    account: Address,
) -> Result<Option<U256>, String> {
    view_call::<ITIP20::balanceOfCall>(evm, token, ITIP20::balanceOfCall { account })
}
