use tempo_contracts::precompiles::{IStablecoinDEX, STABLECOIN_DEX_ADDRESS};

use super::{HarnessEvm, view_call};

pub(super) fn validate(evm: &mut HarnessEvm<'_>, side: &'static str) -> Result<(), String> {
    let target = STABLECOIN_DEX_ADDRESS;
    let min_tick =
        view_call::<IStablecoinDEX::MIN_TICKCall>(evm, target, IStablecoinDEX::MIN_TICKCall {})?
            .ok_or_else(|| format!("TEMPO-DEX-CONSTANT side={side} name=MIN_TICK empty"))?;
    let max_tick =
        view_call::<IStablecoinDEX::MAX_TICKCall>(evm, target, IStablecoinDEX::MAX_TICKCall {})?
            .ok_or_else(|| format!("TEMPO-DEX-CONSTANT side={side} name=MAX_TICK empty"))?;
    let scale = view_call::<IStablecoinDEX::PRICE_SCALECall>(
        evm,
        target,
        IStablecoinDEX::PRICE_SCALECall {},
    )?
    .ok_or_else(|| format!("TEMPO-DEX-CONSTANT side={side} name=PRICE_SCALE empty"))?;
    if min_tick != -2_000 || max_tick != 2_000 || scale != 100_000 {
        return Err(format!(
            "TEMPO-DEX-CONSTANT side={side} MIN_TICK={min_tick} MAX_TICK={max_tick} PRICE_SCALE={scale}"
        ));
    }
    Ok(())
}
