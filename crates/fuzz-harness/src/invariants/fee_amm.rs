use std::collections::BTreeSet;

use alloy_primitives::{Address, U256, address};
use tempo_contracts::precompiles::{ITIPFeeAMM, PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
use tempo_fuzz_types::StateInput;

use super::{HarnessEvm, fmt_addr, is_tip20_like, state_accounts, view_call};

const EXPECTED_M: u64 = 9_970;
const EXPECTED_N: u64 = 9_985;
const EXPECTED_SCALE: u64 = 10_000;
const EXPECTED_MIN_LIQUIDITY: u64 = 1_000;

pub(super) fn validate(
    evm: &mut HarnessEvm<'_>,
    side: &'static str,
    state: &StateInput,
) -> Result<(), String> {
    let target = TIP_FEE_MANAGER_ADDRESS;
    let m = required(evm, target, ITIPFeeAMM::MCall {}, "M")?;
    let n = required(evm, target, ITIPFeeAMM::NCall {}, "N")?;
    let scale = required(evm, target, ITIPFeeAMM::SCALECall {}, "SCALE")?;
    let minimum = required(
        evm,
        target,
        ITIPFeeAMM::MIN_LIQUIDITYCall {},
        "MIN_LIQUIDITY",
    )?;

    if m != EXPECTED_M || n != EXPECTED_N || scale != EXPECTED_SCALE {
        return Err(format!(
            "TEMPO-AMM16 side={side} M={m} N={n} SCALE={scale} expected={EXPECTED_M}/{EXPECTED_N}/{EXPECTED_SCALE}"
        ));
    }
    if m >= n || n - m != 15 {
        return Err(format!(
            "TEMPO-AMM21 side={side} M={m} N={n} spread={}",
            n.saturating_sub(m)
        ));
    }
    if minimum != EXPECTED_MIN_LIQUIDITY {
        return Err(format!(
            "TEMPO-AMM15 side={side} MIN_LIQUIDITY={minimum} expected={EXPECTED_MIN_LIQUIDITY}"
        ));
    }

    // Foundry's pool-id uniqueness assertion, using fixed non-system sentinels.
    let a = address!("0x0000000000000000000000000000000000000011");
    let b = address!("0x0000000000000000000000000000000000000022");
    let ab = view_call::<ITIPFeeAMM::getPoolIdCall>(
        evm,
        target,
        ITIPFeeAMM::getPoolIdCall {
            userToken: a,
            validatorToken: b,
        },
    )?;
    let ba = view_call::<ITIPFeeAMM::getPoolIdCall>(
        evm,
        target,
        ITIPFeeAMM::getPoolIdCall {
            userToken: b,
            validatorToken: a,
        },
    )?;
    if ab == ba {
        return Err(format!(
            "TEMPO-AMM27 side={side} directional pool ids collide"
        ));
    }

    validate_pool_shapes(evm, side, state, minimum)?;
    Ok(())
}

/// Foundry TEMPO-AMM15/28/30 over every pool addressable by tokens present in the
/// materialized state. A pool is either entirely empty or has the permanently locked supply.
fn validate_pool_shapes(
    evm: &mut HarnessEvm<'_>,
    side: &'static str,
    state: &StateInput,
    minimum: u64,
) -> Result<(), String> {
    let mut tokens: BTreeSet<_> = state_accounts(state)
        .filter(|address| is_tip20_like(*address))
        .collect();
    tokens.insert(PATH_USD_ADDRESS);

    for user_token in &tokens {
        for validator_token in &tokens {
            if user_token == validator_token {
                continue;
            }
            let pool_id = view_call::<ITIPFeeAMM::getPoolIdCall>(
                evm,
                TIP_FEE_MANAGER_ADDRESS,
                ITIPFeeAMM::getPoolIdCall {
                    userToken: *user_token,
                    validatorToken: *validator_token,
                },
            )?
            .ok_or_else(|| "TEMPO-AMM30 getPoolId returned no value".to_string())?;
            let pool = view_call::<ITIPFeeAMM::getPoolCall>(
                evm,
                TIP_FEE_MANAGER_ADDRESS,
                ITIPFeeAMM::getPoolCall {
                    userToken: *user_token,
                    validatorToken: *validator_token,
                },
            )?
            .ok_or_else(|| "TEMPO-AMM30 getPool returned no value".to_string())?;
            let total_supply = view_call::<ITIPFeeAMM::totalSupplyCall>(
                evm,
                TIP_FEE_MANAGER_ADDRESS,
                ITIPFeeAMM::totalSupplyCall { poolId: pool_id },
            )?
            .unwrap_or(U256::ZERO);
            let has_reserves = pool.reserveUserToken != 0 || pool.reserveValidatorToken != 0;

            if total_supply.is_zero() && has_reserves {
                return Err(format!(
                    "TEMPO-AMM30 side={side} user_token={} validator_token={} reserves={}/{} total_supply=0",
                    fmt_addr(*user_token),
                    fmt_addr(*validator_token),
                    pool.reserveUserToken,
                    pool.reserveValidatorToken
                ));
            }
            if !total_supply.is_zero() && total_supply < U256::from(minimum) {
                return Err(format!(
                    "TEMPO-AMM15 side={side} user_token={} validator_token={} total_supply={} minimum={minimum}",
                    fmt_addr(*user_token),
                    fmt_addr(*validator_token),
                    total_supply
                ));
            }
        }
    }
    Ok(())
}

fn required<C>(
    evm: &mut HarnessEvm<'_>,
    target: Address,
    call: C,
    name: &str,
) -> Result<u64, String>
where
    C: alloy_sol_types::SolCall<
            Return = <alloy_sol_types::sol_data::Uint<256> as alloy_sol_types::SolType>::RustType,
        >,
{
    let value = view_call(evm, target, call)?
        .ok_or_else(|| format!("TEMPO-AMM-CONSTANT name={name} empty return"))?;
    value
        .try_into()
        .map_err(|_| format!("TEMPO-AMM-CONSTANT name={name} exceeds u64"))
}
