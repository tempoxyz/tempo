//! The C ABI every harness exports, minus the symbols: a harness's cdylib declares
//! `tempo_fuzz_execute_with_result_v1`, `tempo_fuzz_capabilities_v1`,
//! `tempo_fuzz_enable_mock_crypto_v1` and `tempo_fuzz_last_rejection_v1` and implements each
//! with these.

use core::ffi::c_int;
use std::cell::RefCell;

use bincode::Options as _;
use serde::{Serialize, de::DeserializeOwned};
use tempo_fuzz_types::{
    ErrorClass, FUZZ_ACCEPT, FUZZ_REJECT, TYPED_HARNESS_SCHEMA_VERSION, TempoHarnessCapabilities,
};

use crate::{Engine, Rejection, rejection::Check};

thread_local! {
    /// Why the last input this thread executed stopped short, or empty.
    static LAST_REJECTION: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Decodes a bincode-encoded input from `input`, runs it with `run` and writes the
/// bincode-encoded outcome, as `tempo_fuzz_execute_with_result_v1` does, recording why it stopped
/// short for [`last_rejection`]. A null input is [`reject_null`]'s.
///
/// # Safety
///
/// `out_ptr` must be writable for `out_len` bytes, and `out_written` writable.
pub unsafe fn execute<I: DeserializeOwned, O: Serialize>(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
    input: &[u8],
    run: impl FnOnce(I) -> (O, Option<Rejection>),
) -> c_int {
    let Ok(input) = bincode_options().deserialize::<I>(input) else {
        record(Some(&Rejection::new(
            ErrorClass::InvalidInput,
            Check::HarnessInput,
        )));
        return FUZZ_REJECT;
    };
    let (outcome, rejection) = run(input);
    record(rejection.as_ref());
    let Ok(outcome) = bincode_options().serialize(&outcome) else {
        record(Some(&Rejection::new(
            ErrorClass::Internal,
            Check::OutcomeEncoding,
        )));
        return FUZZ_REJECT;
    };
    unsafe { write_output(out_ptr, out_len, out_written, &outcome) }
}

/// Records that a harness got a null input, and returns `FUZZ_REJECT`.
pub fn reject_null() -> c_int {
    record(Some(&Rejection::new(ErrorClass::InvalidInput, Check::Null)));
    FUZZ_REJECT
}

/// Writes `E`'s bincode-encoded [`TempoHarnessCapabilities`], as `tempo_fuzz_capabilities_v1`
/// does.
///
/// # Safety
///
/// `out_ptr` must be writable for `out_len` bytes, and `out_written` writable.
pub unsafe fn capabilities<E: Engine>(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> c_int {
    let capabilities = TempoHarnessCapabilities {
        schema_version: TYPED_HARNESS_SCHEMA_VERSION,
        implementation: E::IMPLEMENTATION.to_string(),
        git_revision: option_env!("TEMPO_GIT_REVISION")
            .unwrap_or("unknown")
            .to_string(),
        supported_hardforks: E::HARDFORKS
            .to_vec()
            .try_into()
            .expect("an engine supports hardforks"),
        supported_inputs: E::INPUTS
            .to_vec()
            .try_into()
            .expect("an engine supports inputs"),
        invariants: crate::invariants::catalog::<E>(),
    };
    let Ok(bytes) = bincode_options().serialize(&capabilities) else {
        return FUZZ_REJECT;
    };
    unsafe { write_output(out_ptr, out_len, out_written, &bytes) }
}

/// Makes every check also accept [`tempo_primitives::crypto::mock`] signatures, if no input ran
/// yet, as `tempo_fuzz_enable_mock_crypto_v1` does. Returns the mock format's version, or 0 when
/// mocks stay off.
pub fn enable_mock_crypto() -> u32 {
    if crate::crypto::enable() {
        tempo_primitives::crypto::mock::VERSION
    } else {
        0
    }
}

/// Writes why the last input this thread executed stopped short, as
/// `tempo_fuzz_last_rejection_v1` does.
///
/// # Safety
///
/// `out_ptr` must be writable for `out_len` bytes, and `out_written` writable.
pub unsafe fn last_rejection(out_ptr: *mut u8, out_len: usize, out_written: *mut usize) -> c_int {
    LAST_REJECTION.with_borrow(|why| {
        if why.is_empty() && !out_written.is_null() {
            unsafe { *out_written = 0 };
            return FUZZ_ACCEPT;
        }
        unsafe { write_output(out_ptr, out_len, out_written, why.as_bytes()) }
    })
}

/// `bincode::serialize`'s encoding, rejecting trailing bytes.
pub fn bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

/// Records `rejection`'s reason for [`last_rejection`], or that the input applied in full.
fn record(rejection: Option<&Rejection>) {
    LAST_REJECTION.with_borrow_mut(|why| {
        why.clear();
        why.push_str(rejection.map_or("", Rejection::reason));
    });
}

/// Writes `bytes` to `dst` if it fits, and sets `written` to their length either way.
unsafe fn write_output(dst: *mut u8, dst_len: usize, written: *mut usize, bytes: &[u8]) -> c_int {
    if written.is_null() {
        return FUZZ_REJECT;
    }
    unsafe { *written = bytes.len() };
    if dst.is_null() || dst_len < bytes.len() {
        return FUZZ_REJECT;
    }
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
    FUZZ_ACCEPT
}
