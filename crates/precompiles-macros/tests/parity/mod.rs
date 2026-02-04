//! Test utilities and assertion helpers for parity tests.
//!
//! # Known Gaps
//!
//! These features are supported by `sol!` but NOT by `#[abi]`:
//!
//! - **Anonymous events**: `sol!` supports `event Foo() anonymous;`
//! - **Overloaded functions**: Rust traits don't support method overloading

use alloy::{
    primitives::keccak256,
    sol_types::{SolCall, SolError, SolEvent, SolValue},
};

mod enums;
mod errors;
mod events;
mod functions;
mod structs;

/// Assert that two `SolCall` implementations have identical signatures and selectors.
pub(crate) fn assert_call_parity<T: SolCall, U: SolCall>() {
    assert_eq!(
        T::SIGNATURE,
        U::SIGNATURE,
        "SolCall signature mismatch: {:?} vs {:?}",
        T::SIGNATURE,
        U::SIGNATURE
    );
    assert_eq!(
        T::SELECTOR,
        U::SELECTOR,
        "SolCall selector mismatch for signature {:?}",
        T::SIGNATURE
    );
    let expected: [u8; 4] = keccak256(T::SIGNATURE)[..4].try_into().unwrap();
    assert_eq!(
        T::SELECTOR,
        expected,
        "SolCall selector != keccak256(signature)"
    );
}

/// Assert that two `SolError` implementations have identical signatures and selectors.
pub(crate) fn assert_error_parity<T: SolError, U: SolError>() {
    assert_eq!(
        T::SIGNATURE,
        U::SIGNATURE,
        "SolError signature mismatch: {:?} vs {:?}",
        T::SIGNATURE,
        U::SIGNATURE
    );
    assert_eq!(
        T::SELECTOR,
        U::SELECTOR,
        "SolError selector mismatch for signature {:?}",
        T::SIGNATURE
    );
    let expected: [u8; 4] = keccak256(T::SIGNATURE)[..4].try_into().unwrap();
    assert_eq!(
        T::SELECTOR,
        expected,
        "SolError selector != keccak256(signature)"
    );
}

/// Assert that two `SolEvent` implementations have identical signatures and hashes.
pub(crate) fn assert_event_parity<T: SolEvent, U: SolEvent>() {
    assert_eq!(
        T::SIGNATURE,
        U::SIGNATURE,
        "SolEvent signature mismatch: {:?} vs {:?}",
        T::SIGNATURE,
        U::SIGNATURE
    );
    assert_eq!(
        T::SIGNATURE_HASH,
        U::SIGNATURE_HASH,
        "SolEvent signature hash mismatch for {:?}",
        T::SIGNATURE
    );
    assert_eq!(
        T::SIGNATURE_HASH,
        keccak256(T::SIGNATURE),
        "SolEvent signature hash != keccak256(signature)"
    );
}

/// Assert that two values produce identical ABI encoding.
pub(crate) fn assert_encoding_parity<T: SolValue, U: SolValue>(sol_val: &T, our_val: &U) {
    assert_eq!(
        sol_val.abi_encode(),
        our_val.abi_encode(),
        "abi_encode() mismatch"
    );
    assert_eq!(
        sol_val.abi_encode_packed(),
        our_val.abi_encode_packed(),
        "abi_encode_packed() mismatch"
    );
}
