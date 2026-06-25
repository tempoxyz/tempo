//! ABI dispatch helpers for Tempo precompiles.

use crate::{
    IntoPrecompileResult, Result, error, input_cost, storage::StorageCtx,
    storage_credits::StorageCredits,
};
use alloy::{
    primitives::{Address, Bytes},
    sol,
    sol_types::{SolCall, SolError},
};
use revm::precompile::{PrecompileHalt, PrecompileOutput, PrecompileResult};

sol! {
    error StaticCallNotAllowed();
}

/// Dispatches a parameterless view call, encoding the return via `T`.
#[inline]
pub(crate) fn metadata<T: SolCall>(f: impl FnOnce() -> Result<T::Return>) -> PrecompileResult {
    f().into_precompile_result(0, 0, |ret| T::abi_encode_returns(&ret).into())
}

/// Dispatches a read-only call with decoded arguments, encoding the return via `T`.
#[inline]
pub(crate) fn view<T: SolCall>(
    call: T,
    f: impl FnOnce(T) -> Result<T::Return>,
) -> PrecompileResult {
    f(call).into_precompile_result(0, 0, |ret| T::abi_encode_returns(&ret).into())
}

/// Dispatches a state-mutating call that returns ABI-encoded data.
///
/// Rejects static calls with [`StaticCallNotAllowed`].
#[inline]
pub(crate) fn mutate<T: SolCall>(
    call: T,
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<T::Return>,
) -> PrecompileResult {
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::revert(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
            StorageCtx.reservoir(),
        ));
    }
    f(sender, call).into_precompile_result(0, 0, |ret| T::abi_encode_returns(&ret).into())
}

/// Dispatches a state-mutating call that returns no data (e.g. `approve`, `transfer`).
///
/// Rejects static calls with [`StaticCallNotAllowed`].
#[inline]
pub(crate) fn mutate_void<T: SolCall>(
    call: T,
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<()>,
) -> PrecompileResult {
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::revert(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
            StorageCtx.reservoir(),
        ));
    }
    f(sender, call).into_precompile_result(0, 0, |()| Bytes::new())
}

/// Sets TIP-1060 storage creation mode to Preserve for the given storage-credit owner.
#[inline]
pub(crate) fn preserve_storage_credits(credit_owner: Address) -> Result<()> {
    if StorageCtx.spec().is_t7() {
        StorageCredits::new().set_mode(
            credit_owner,
            tempo_contracts::precompiles::IStorageCredits::Mode::Preserve,
        )?;
    }
    Ok(())
}

/// Deducts the calldata input cost, returning an OOG halt result if insufficient gas.
#[inline]
pub(crate) fn charge_input_cost(
    storage: &mut StorageCtx,
    calldata: &[u8],
) -> Option<PrecompileResult> {
    if storage.deduct_gas(input_cost(calldata.len())).is_err() {
        return Some(Ok(storage.halt_output(PrecompileHalt::OutOfGas)));
    }
    None
}

/// Fills state gas accounting on a [`PrecompileOutput`] from the storage context.
///
/// State gas / reservoir tracking is only set when TIP-1016 (EIP-8037) is enabled.
/// When disabled, `state_gas_used` must remain 0 to avoid leaking into revm's reservoir
/// accounting and corrupting `tx_gas_used()` via `handle_reservoir_remaining_gas`.
///
/// SSTORE refund propagation is activated unconditionally at T4 so the
/// `TempoPrecompileProvider` wrapper can apply refunds with `record_refund`. Pre-T4
/// blocks were executed without refund propagation, so we cannot change their gas
/// accounting.
#[inline]
fn fill_state_gas(output: &mut PrecompileOutput, storage: &StorageCtx) {
    if storage.spec().is_t4() && output.is_success() {
        output.gas_refunded = storage.gas_refunded();
    }

    if storage.amsterdam_eip8037_enabled() {
        if output.is_success() {
            // On success: parent takes the child's final reservoir.
            output.reservoir = storage.reservoir();
            output.state_gas_used = storage.state_gas_used();
        } else {
            // On revert or halt: state changes are undone, so ALL state gas returns
            // to the parent's reservoir.
            output.reservoir = storage.state_gas_used() + storage.reservoir();
            output.state_gas_used = 0;
        }
    }
}

/// Decodes calldata via `decode`, then dispatches to `f`.
///
/// Handles missing selectors (revert on T1+, error on earlier forks), unknown selectors
/// (ABI-encoded `UnknownFunctionSelector`), and malformed ABI data (empty revert).
#[inline]
pub(crate) fn dispatch_call<T>(
    calldata: &[u8],
    decode: impl FnOnce(&[u8]) -> core::result::Result<T, alloy::sol_types::Error>,
    f: impl FnOnce(T) -> PrecompileResult,
) -> PrecompileResult {
    let storage = StorageCtx::default();

    if calldata.len() < 4 {
        if storage.spec().is_t1() {
            return Ok(storage.revert_output(Bytes::new()));
        } else {
            return Ok(storage.halt_output(PrecompileHalt::Other(
                "Invalid input: missing function selector".into(),
            )));
        }
    }

    let result = decode(calldata);

    match result {
        Ok(call) => f(call).map(|mut res| {
            // TODO: fix this, each precompile handler should either return output with proper gas values or don't return any gas values at all.
            res.gas_used = storage.gas_used();
            fill_state_gas(&mut res, &storage);
            res
        }),
        Err(alloy::sol_types::Error::UnknownSelector { selector, .. }) => storage.error_result(
            error::TempoPrecompileError::UnknownFunctionSelector(*selector),
        ),
        Err(_) => Ok(storage.revert_output(Bytes::new())),
    }
}

macro_rules! dispatch {
    // Public dispatcher syntax: group match arms by ABI interface.
    ($calldata:expr, |$call:ident| match $match_call:ident {
        $iface_1:ident::$calls_1:ident { $($(#[$($attr_1:tt)*])* $variant_1:ident($binding_1:pat) => $body_1:expr),* $(,)? }
        $($iface_n:ident::$calls_n:ident { $($(#[$($attr_n:tt)*])* $variant_n:ident($binding_n:pat) => $body_n:expr),* $(,)? })*
    } $(,)?) => {
        paste::paste! {{
            // Run hardfork gates before decoding, so malformed gated calls are still unknown.
            if let Some(selector) = crate::dispatch::selector_from_calldata($calldata) {
                $($(crate::dispatch!(@pre_gate $calldata, selector, $iface_1::[<$variant_1 Call>]::SELECTOR; #[$($attr_1)*]);)*)*
                $($($(crate::dispatch!(@pre_gate $calldata, selector, $iface_n::[<$variant_n Call>]::SELECTOR; #[$($attr_n)*]);)*)*)*

                // Decode with the ABI whose selector set contains the calldata selector.
                crate::dispatch!(@decode $calldata, selector, $call, $match_call,
                    $iface_1::$calls_1 { $($variant_1($binding_1) => $body_1),* }
                    $($iface_n::$calls_n { $($variant_n($binding_n) => $body_n),* })*
                    else $iface_1::$calls_1
                )
            } else {
                // Let dispatch_call apply the chain-specific missing-selector behavior.
                crate::dispatch::dispatch_call($calldata, <$iface_1::$calls_1 as alloy::sol_types::SolInterface>::abi_decode, |_| unreachable!())
            }
        }}
    };
    // Try one interface; recurse until a matching selector set is found.
    (@decode $calldata:expr, $selector:expr, $call:ident, $match_call:ident,
        $iface:ident::$calls:ident { $($variant:ident($binding:pat) => $body:expr),* } $($rest:tt)*
    ) => {{
        type Calls = $iface::$calls;
        if <Calls as alloy::sol_types::SolInterface>::valid_selector($selector) {
            crate::dispatch::dispatch_call($calldata, <Calls as alloy::sol_types::SolInterface>::abi_decode, |$call| match $match_call {
                $(Calls::$variant($binding) => $body,)*
            })
        } else {
            crate::dispatch!(@decode $calldata, $selector, $call, $match_call, $($rest)*)
        }
    }};
    // Fallback preserves dispatch_call's unknown-selector decoding path.
    (@decode $calldata:expr, $selector:expr, $call:ident, $match_call:ident, else $iface:ident::$calls:ident) => {{
        type Calls = $iface::$calls;
        crate::dispatch::dispatch_call($calldata, <Calls as alloy::sol_types::SolInterface>::abi_decode, |_| unreachable!())
    }};
    // Schedule gates: since rejects pre-fork, until rejects from that fork onward.
    (@pre_gate $calldata:expr, $selector:expr, $call_selector:expr; #[schedule(since = $since:ident, until = $until:ident)]) => {
        crate::dispatch!(@pre_gate $calldata, $selector, $call_selector; #[schedule(since = $since)]);
        crate::dispatch!(@pre_gate $calldata, $selector, $call_selector; #[schedule(until = $until)]);
    };
    (@pre_gate $calldata:expr, $selector:expr, $call_selector:expr; #[schedule(since = $hf:ident)]) => {
        if $selector == $call_selector && crate::storage::StorageCtx.spec() < tempo_chainspec::hardfork::TempoHardfork::$hf {
            return crate::dispatch::unknown_selector_result($calldata);
        }
    };
    (@pre_gate $calldata:expr, $selector:expr, $call_selector:expr; #[schedule(until = $hf:ident)]) => {
        if $selector == $call_selector && crate::storage::StorageCtx.spec() >= tempo_chainspec::hardfork::TempoHardfork::$hf {
            return crate::dispatch::unknown_selector_result($calldata);
        }
    };
}

pub(crate) use dispatch;

pub(crate) fn selector_from_calldata(calldata: &[u8]) -> Option<[u8; 4]> {
    calldata.get(..4).map(|selector| {
        selector
            .try_into()
            .expect("selector slice has exactly 4 bytes")
    })
}

pub(crate) fn unknown_selector_result(calldata: &[u8]) -> PrecompileResult {
    let selector = selector_from_calldata(calldata).expect("calldata len >= 4 after decode");
    StorageCtx::default().error_result(error::TempoPrecompileError::UnknownFunctionSelector(
        selector,
    ))
}
