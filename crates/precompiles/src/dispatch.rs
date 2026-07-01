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
pub fn metadata<T: SolCall>(f: impl FnOnce() -> Result<T::Return>) -> PrecompileResult {
    f().into_precompile_result(0, 0, |ret| T::abi_encode_returns(&ret).into())
}

/// Dispatches a read-only call with decoded arguments, encoding the return via `T`.
#[inline]
pub fn view<T: SolCall>(call: T, f: impl FnOnce(T) -> Result<T::Return>) -> PrecompileResult {
    f(call).into_precompile_result(0, 0, |ret| T::abi_encode_returns(&ret).into())
}

/// Dispatches a state-mutating call that returns ABI-encoded data.
///
/// Rejects static calls with [`StaticCallNotAllowed`].
#[inline]
pub fn mutate<T: SolCall>(
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
pub fn mutate_void<T: SolCall>(
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
pub fn preserve_storage_credits(credit_owner: Address) -> Result<()> {
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
pub fn charge_input_cost(storage: &mut StorageCtx, calldata: &[u8]) -> Option<PrecompileResult> {
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
pub fn dispatch_call<T>(
    calldata: &[u8],
    decode: impl FnOnce(&[u8]) -> core::result::Result<T, alloy::sol_types::Error>,
    f: impl FnOnce(T) -> PrecompileResult,
) -> PrecompileResult {
    let storage = StorageCtx::default();

    if calldata.len() < 4 {
        return missing_selector_result();
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

#[macro_export]
macro_rules! dispatch {
    ($calldata:expr, |$call:ident| match $match_call:ident {
        $($iface:ident::$calls:ident {
            $(
                $(#[schedule($($gate:ident = $hf:ident),+ $(,)?)])*
                $variant:ident($binding:pat) => $body:expr
            ),* $(,)?
        })+
    } $(,)?) => {
        paste::paste! {{
            #[cfg(debug_assertions)]
            {
                let mut selectors = std::collections::BTreeSet::new();
                $(assert!(
                    <$iface::$calls as alloy::sol_types::SolInterface>::selectors().all(|s| selectors.insert(s)),
                    "duplicate precompile selector in dispatch! macro",
                );)*
            }

            if let Some(selector) = $crate::dispatch::selector_from_calldata($calldata) {
                $($($($(
                    if selector == <$iface::[<$variant Call>] as alloy::sol_types::SolCall>::SELECTOR
                        && !$crate::dispatch::$gate(tempo_chainspec::hardfork::TempoHardfork::$hf)
                    {
                        return $crate::dispatch::unknown_selector_result($calldata);
                    }
                )+)*)*)+
                $(
                    if <$iface::$calls as alloy::sol_types::SolInterface>::valid_selector(selector) {
                        type Calls = $iface::$calls;
                        return $crate::dispatch::dispatch_call($calldata, <Calls as alloy::sol_types::SolInterface>::abi_decode, |$call| match $match_call {
                            $(Calls::$variant($binding) => $body,)*
                        });
                    }
                )*
                return $crate::dispatch::unknown_selector_result($calldata);
            }
            $crate::dispatch::missing_selector_result()
        }}
    };
}

pub use crate::dispatch;

pub fn selector_from_calldata(calldata: &[u8]) -> Option<[u8; 4]> {
    calldata.first_chunk::<4>().copied()
}

pub fn missing_selector_result() -> PrecompileResult {
    let storage = StorageCtx::default();

    if storage.spec().is_t1() {
        Ok(storage.revert_output(Bytes::new()))
    } else {
        Ok(storage.halt_output(PrecompileHalt::Other(
            "Invalid input: missing function selector".into(),
        )))
    }
}

#[inline]
pub fn since(hardfork: tempo_chainspec::hardfork::TempoHardfork) -> bool {
    StorageCtx.spec() >= hardfork
}

#[inline]
pub fn until(hardfork: tempo_chainspec::hardfork::TempoHardfork) -> bool {
    StorageCtx.spec() < hardfork
}

pub fn unknown_selector_result(calldata: &[u8]) -> PrecompileResult {
    let selector = selector_from_calldata(calldata).expect("calldata len >= 4 after decode");
    StorageCtx::default().error_result(error::TempoPrecompileError::UnknownFunctionSelector(
        selector,
    ))
}
