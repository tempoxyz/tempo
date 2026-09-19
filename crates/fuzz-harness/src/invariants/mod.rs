mod fee_amm;
mod stablecoin_dex;
mod tip20;

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolCall;
use evm2::evm::SystemTx;
use tempo_evm::evm::TempoEvm;
use tempo_fuzz_types::StateInput;
use tempo_primitives::TempoTxEnvelope;

pub(crate) type HarnessEvm<'a> = TempoEvm<'a>;

pub(crate) fn validate_state_invariants(
    evm: &mut HarnessEvm<'_>,
    side: &'static str,
    state: &StateInput,
) -> Result<(), String> {
    fee_amm::validate(evm, side, state)?;
    stablecoin_dex::validate(evm, side)?;
    tip20::validate(evm, side, state)?;
    Ok(())
}

/// Assertions from the Foundry gas/block invariant suites that can be evaluated for every
/// successfully executed transaction without their test-only ghost state.
pub(crate) fn validate_transaction_invariants(
    tx: &TempoTxEnvelope,
    gas_used: u64,
) -> Result<(), String> {
    use alloy_consensus::transaction::Transaction;

    const TRANSACTION_GAS_CAP: u64 = 30_000_000;
    if tx.gas_limit() > TRANSACTION_GAS_CAP {
        return Err(format!(
            "TEMPO-BLOCK3 transaction over 30M gas cap was accepted gas_limit={}",
            tx.gas_limit()
        ));
    }
    if gas_used == 0 {
        return Err("TEMPO-G1 accepted transaction consumed zero gas".to_string());
    }
    if gas_used > tx.gas_limit() {
        return Err(format!(
            "TEMPO-GAS-LIMIT gas_used={gas_used} gas_limit={}",
            tx.gas_limit()
        ));
    }
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
