use alloy_primitives::{Address, address};
use tempo_contracts::precompiles::{ITIPFeeAMM, TIP_FEE_MANAGER_ADDRESS};

use super::{HarnessEvm, view_call};

const EXPECTED_M: u64 = 9_970;
const EXPECTED_N: u64 = 9_985;
const EXPECTED_SCALE: u64 = 10_000;
const EXPECTED_MIN_LIQUIDITY: u64 = 1_000;

pub(super) fn validate(evm: &mut HarnessEvm<'_>, side: &'static str) -> Result<(), String> {
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
