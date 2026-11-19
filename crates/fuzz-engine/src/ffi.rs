//! The C ABI every harness exports, minus the symbols: a harness's cdylib declares
//! `tempo_fuzz_execute_with_result_v1`, `tempo_fuzz_capabilities_v1` and
//! `tempo_fuzz_last_rejection_v1` and implements each with these.

use core::ffi::c_int;

use bincode::Options as _;
use serde::{Serialize, de::DeserializeOwned};
use tempo_fuzz_types::{ErrorClass, FUZZ_ACCEPT, FUZZ_REJECT};

use crate::execute as exec;

/// Decodes a bincode-encoded input from `input`, runs it with `run` and writes the
/// bincode-encoded outcome, as `tempo_fuzz_execute_with_result_v1` does. A null input is
/// [`reject_null`]'s.
///
/// # Safety
///
/// `out_ptr` must be writable for `out_len` bytes, and `out_written` writable.
pub unsafe fn execute<I: DeserializeOwned, O: Serialize>(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
    input: &[u8],
    run: impl FnOnce(I) -> O,
) -> c_int {
    let Ok(input) = bincode_options().deserialize::<I>(input) else {
        exec::reject(ErrorClass::InvalidInput, exec::Check::HarnessInput);
        return FUZZ_REJECT;
    };
    let Ok(outcome) = bincode_options().serialize(&run(input)) else {
        exec::reject(ErrorClass::Internal, exec::Check::OutcomeEncoding);
        return FUZZ_REJECT;
    };
    unsafe { write_output(out_ptr, out_len, out_written, &outcome) }
}

/// Records that a harness got a null input, and returns `FUZZ_REJECT`.
pub fn reject_null() -> c_int {
    exec::reject(ErrorClass::InvalidInput, exec::Check::Null);
    FUZZ_REJECT
}

/// Writes `value` bincode-encoded, as `tempo_fuzz_capabilities_v1` does.
///
/// # Safety
///
/// `out_ptr` must be writable for `out_len` bytes, and `out_written` writable.
pub unsafe fn write_encoded(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
    value: &impl Serialize,
) -> c_int {
    let Ok(bytes) = bincode_options().serialize(value) else {
        return FUZZ_REJECT;
    };
    unsafe { write_output(out_ptr, out_len, out_written, &bytes) }
}

/// Writes why the last input this thread executed stopped short, as
/// `tempo_fuzz_last_rejection_v1` does.
///
/// # Safety
///
/// `out_ptr` must be writable for `out_len` bytes, and `out_written` writable.
pub unsafe fn last_rejection(out_ptr: *mut u8, out_len: usize, out_written: *mut usize) -> c_int {
    exec::with_rejection(|why| {
        if why.is_empty() && !out_written.is_null() {
            unsafe { *out_written = 0 };
            return FUZZ_ACCEPT;
        }
        unsafe { write_output(out_ptr, out_len, out_written, why.as_bytes()) }
    })
}

/// Why the last input this thread executed stopped short, or an empty string.
pub fn last_rejection_string() -> String {
    exec::with_rejection(|why| why.to_string())
}

/// `bincode::serialize`'s encoding, rejecting trailing bytes.
pub fn bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
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
