mod tip20;

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolCall;
use evm2::evm::SystemTx;
use tempo_evm::evm::TempoEvm;
use tempo_fuzz_types::StateInput;

pub(crate) type HarnessEvm<'a> = TempoEvm<'a>;

pub(crate) fn validate_state_invariants(
    evm: &mut HarnessEvm<'_>,
    side: &'static str,
    state: &StateInput,
) -> Result<(), String> {
    tip20::validate(evm, side, state)?;
    Ok(())
}

pub(super) fn view_call<C>(
    evm: &mut HarnessEvm<'_>,
    target: Address,
    call: C,
) -> Result<Option<C::Return>, String>
where
    C: SolCall,
{
    let result = evm
        .system_call(
            SystemTx::new(target, Bytes::from(call.abi_encode())).with_caller(Address::ZERO),
        )
        .map_err(|err| format!("view_call target={} error={err}", fmt_addr(target)))?;
    let result = result.discard();
    if result.status {
        if result.output.is_empty() {
            return Ok(None);
        }
        C::abi_decode_returns(&result.output)
            .map(Some)
            .map_err(|err| format!("view_call target={} decode_error={err}", fmt_addr(target)))
    } else {
        Err(format!(
            "view_call target={} failed stop={:?} output=0x{}",
            fmt_addr(target),
            result.stop,
            hex_prefix(&result.output, 32)
        ))
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
