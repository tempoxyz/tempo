//! Dispatch helpers for precompile implementations.
//!
//! Contains the `Precompile` trait, calldata decoding, gas costing,
//! and typed wrappers for view/mutate dispatch patterns.

use crate::{
    error::{IntoPrecompileResult, Result, TempoPrecompileError},
    storage::StorageCtx,
};
use alloy::{
    primitives::{Address, Bytes},
    sol,
    sol_types::{SolCall, SolError},
};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};

#[cfg(test)]
use alloy::sol_types::SolInterface;

sol! {
    error StaticCallNotAllowed();
    error DelegateCallNotAllowed();

    /// Error returned when a function selector is not recognized
    #[derive(Debug, PartialEq, Eq)]
    error UnknownFunctionSelector(bytes4 selector);
}

/// Input per word cost. It covers abi decoding and cloning of input into call data.
///
/// Being careful and pricing it twice as COPY_COST to mitigate different abi decodings.
pub const INPUT_PER_WORD_COST: u64 = 6;

#[inline]
pub fn input_cost(calldata_len: usize) -> u64 {
    calldata_len
        .div_ceil(32)
        .saturating_mul(INPUT_PER_WORD_COST as usize) as u64
}

pub trait Precompile {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult;
}

#[inline]
pub fn metadata<T: SolCall>(f: impl FnOnce() -> Result<T::Return>) -> PrecompileResult {
    f().into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
pub fn metadata_with_sender<T: SolCall>(
    sender: Address,
    f: impl FnOnce(Address) -> Result<T::Return>,
) -> PrecompileResult {
    f(sender).into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
pub fn view<T: SolCall>(call: T, f: impl FnOnce(T) -> Result<T::Return>) -> PrecompileResult {
    f(call).into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
pub fn view_with_sender<T: SolCall>(
    call: T,
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<T::Return>,
) -> PrecompileResult {
    f(sender, call).into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
pub fn mutate<T: SolCall>(
    call: T,
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<T::Return>,
) -> PrecompileResult {
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::new_reverted(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
        ));
    }
    f(sender, call).into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
pub fn mutate_void<T: SolCall>(
    call: T,
    sender: Address,
    f: impl FnOnce(Address, T) -> Result<()>,
) -> PrecompileResult {
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::new_reverted(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
        ));
    }
    f(sender, call).into_precompile_result(0, |()| Bytes::new())
}

#[inline]
pub fn mutate_no_sender<T: SolCall>(
    call: T,
    f: impl FnOnce(T) -> Result<T::Return>,
) -> PrecompileResult {
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::new_reverted(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
        ));
    }
    f(call).into_precompile_result(0, |ret| T::abi_encode_returns(&ret).into())
}

#[inline]
pub fn mutate_void_no_sender<T: SolCall>(
    call: T,
    f: impl FnOnce(T) -> Result<()>,
) -> PrecompileResult {
    if StorageCtx.is_static() {
        return Ok(PrecompileOutput::new_reverted(
            0,
            StaticCallNotAllowed {}.abi_encode().into(),
        ));
    }
    f(call).into_precompile_result(0, |()| Bytes::new())
}

#[inline]
pub fn fill_precompile_output(
    mut output: PrecompileOutput,
    storage: &StorageCtx,
) -> PrecompileOutput {
    output.gas_used = storage.gas_used();

    // add refund only if it is not reverted
    if !output.reverted {
        output.gas_refunded = storage.gas_refunded();
    }
    output
}

/// Helper function to return an unknown function selector error.
/// Returns an ABI-encoded UnknownFunctionSelector error with the selector.
#[inline]
pub fn unknown_selector(selector: [u8; 4], gas: u64) -> PrecompileResult {
    TempoPrecompileError::UnknownFunctionSelector(selector).into_precompile_result(gas)
}

/// Helper function to decode calldata and dispatch it.
#[inline]
pub fn dispatch_call<T>(
    calldata: &[u8],
    decode: impl FnOnce(&[u8]) -> core::result::Result<T, alloy::sol_types::Error>,
    f: impl FnOnce(T) -> PrecompileResult,
) -> PrecompileResult {
    let storage = StorageCtx::default();

    if calldata.len() < 4 {
        if storage.spec().is_t1() {
            return Ok(fill_precompile_output(
                PrecompileOutput::new_reverted(0, Bytes::new()),
                &storage,
            ));
        } else {
            return Err(PrecompileError::Other(
                "Invalid input: missing function selector".into(),
            ));
        }
    }
    let result = decode(calldata);

    match result {
        Ok(call) => f(call).map(|res| fill_precompile_output(res, &storage)),
        Err(alloy::sol_types::Error::UnknownSelector { selector, .. }) => {
            unknown_selector(*selector, storage.gas_used())
                .map(|res| fill_precompile_output(res, &storage))
        }
        Err(_) => Ok(fill_precompile_output(
            PrecompileOutput::new_reverted(0, Bytes::new()),
            &storage,
        )),
    }
}

#[cfg(test)]
pub fn expect_precompile_revert<E>(result: &PrecompileResult, expected_error: E)
where
    E: SolInterface + PartialEq + std::fmt::Debug,
{
    match result {
        Ok(result) => {
            assert!(result.reverted);
            let decoded = E::abi_decode(&result.bytes).unwrap();
            assert_eq!(decoded, expected_error);
        }
        Err(other) => {
            panic!("expected reverted output, got: {other:?}");
        }
    }
}
