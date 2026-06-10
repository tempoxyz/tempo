mod tip20;

use alloy_evm::Evm as _;
use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolCall;
use revm::{
    context::result::{ExecutionResult, Output},
    database::{EmptyDB, in_memory_db::CacheDB},
};
use tempo_evm::evm::TempoEvm;
use tempo_fuzz_types::StateInput;

pub(crate) type HarnessEvm = TempoEvm<CacheDB<EmptyDB>>;

pub(crate) fn validate_state_invariants(
    evm: &mut HarnessEvm,
    side: &'static str,
    state: &StateInput,
) -> Result<(), String> {
    tip20::validate(evm, side, state)?;
    Ok(())
}

pub(super) fn view_call<C>(
    evm: &mut HarnessEvm,
    target: Address,
    call: C,
) -> Result<Option<C::Return>, String>
where
    C: SolCall,
{
    let result = evm
        .transact_system_call(Address::ZERO, target, Bytes::from(call.abi_encode()))
        .map_err(|err| format!("view_call target={} error={err}", fmt_addr(target)))?;
    match result.result {
        ExecutionResult::Success {
            output: Output::Call(output),
            ..
        } => {
            if output.is_empty() {
                return Ok(None);
            }
            C::abi_decode_returns(&output)
                .map(Some)
                .map_err(|err| format!("view_call target={} decode_error={err}", fmt_addr(target)))
        }
        ExecutionResult::Success { .. } => Ok(None),
        ExecutionResult::Revert { output, .. } => Err(format!(
            "view_call target={} reverted output=0x{}",
            fmt_addr(target),
            hex_prefix(&output, 32)
        )),
        ExecutionResult::Halt { reason, .. } => Err(format!(
            "view_call target={} halted reason={reason:?}",
            fmt_addr(target)
        )),
    }
}

pub(super) fn state_accounts(state: &StateInput) -> impl Iterator<Item = Address> + '_ {
    state
        .accounts
        .iter()
        .map(|account| Address::from(account.address))
}

pub(super) fn is_tip20_like(address: Address) -> bool {
    address.as_slice().starts_with(&[0x20, 0xc0])
}

pub(super) fn fmt_addr(address: Address) -> String {
    format!("{address:#x}")
}

fn hex_prefix(bytes: &[u8], max_len: usize) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let bytes = &bytes[..bytes.len().min(max_len)];
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}
