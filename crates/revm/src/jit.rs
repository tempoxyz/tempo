//! Compiled bytecode dispatch with Tempo storage-credit accounting.

use crate::gas_credits::StorageCreditsContext;
use alloy_primitives::U256;
use revm::interpreter::InstructionResult;
use revmc::EvmContext;
use tempo_precompiles::storage_credits::sstore_storage_credits;

pub use revmc::runtime::{
    CompilationEvent, JitBackend, LookupDecision, LookupRequest, RuntimeCacheKey, RuntimeConfig,
    RuntimeStatsSnapshot, RuntimeTuning,
};

/// Executes the Tempo SSTORE policy through the same host and gas tracker as compiled code.
pub(crate) fn sstore(
    ecx: &mut EvmContext<'_>,
    index: U256,
    value: U256,
) -> Result<(), InstructionResult> {
    if ecx.is_static {
        return Err(InstructionResult::StateChangeDuringStaticCall);
    }
    let gas_params = ecx.host.gas_params().clone();
    if ecx.gas.remaining() <= gas_params.call_stipend() {
        return Err(InstructionResult::ReentrancySentryOOG);
    }
    if !ecx.gas.record_regular_cost(gas_params.sstore_static_gas()) {
        return Err(InstructionResult::OutOfGas);
    }
    let owner = ecx.input.target_address;
    let skip_cold_load = ecx.gas.remaining() < gas_params.cold_storage_cost();
    let state_load = ecx
        .host
        .sstore_skip_cold_load(owner, index, value, skip_cold_load)?;
    sstore_storage_credits(
        &mut StorageCreditsContext {
            context: ecx.host,
            gas_tracker: ecx.gas.tracker_mut(),
        },
        owner,
        None,
        &state_load,
    )?;
    if !ecx.gas.record_regular_cost(gas_params.sstore_dynamic_gas(
        true,
        &state_load.data,
        state_load.is_cold,
    )) {
        return Err(InstructionResult::OutOfGas);
    }
    ecx.gas
        .record_refund(gas_params.sstore_refund(true, &state_load.data));
    Ok(())
}
