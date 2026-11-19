//! Tempo's stateless block executor for fuzzing and replay, loaded as a cdylib.
//!
//! An input is a chain, a pre-state and blocks ([`tempo_fuzz_types`]). The harness executes the
//! blocks with Tempo's block executor on an in-memory state and reports receipts, the resulting
//! state, what changed, and which protocol invariants broke. A panic inside the executor aborts the
//! process: the node would crash on the same block. The executor is [`tempo_fuzz_engine`]'s, on
//! [`Tempo`] L1; this crate exports its C ABI.

use core::ffi::c_int;

use tempo_fuzz_engine::{Tempo, ffi};
use tempo_fuzz_types::TempoHarnessInput;

/// Executes a bincode-encoded [`TempoHarnessInput`] and writes the bincode-encoded
/// [`tempo_fuzz_types::TempoHarnessOutcome`] to `out_ptr`.
///
/// Returns `FUZZ_ACCEPT` once the outcome is written. Returns `FUZZ_REJECT` when the input does not
/// decode, or when `out_len` is too small; in the latter case `*out_written` holds the size needed.
///
/// # Safety
///
/// `in_ptr` must be readable for `in_len` bytes, `out_ptr` writable for `out_len` bytes, and
/// `out_written` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tempo_fuzz_execute_with_result_v1(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
    in_ptr: *const u8,
    in_len: usize,
) -> c_int {
    if in_ptr.is_null() {
        return ffi::reject_null();
    }
    let input = unsafe { core::slice::from_raw_parts(in_ptr, in_len) };
    unsafe {
        ffi::execute(
            out_ptr,
            out_len,
            out_written,
            input,
            |input: TempoHarnessInput| tempo_fuzz_engine::run(&Tempo, input),
        )
    }
}

/// Writes the bincode-encoded [`tempo_fuzz_types::TempoHarnessCapabilities`] to `out_ptr`, with
/// the same return values and safety contract as [`tempo_fuzz_execute_with_result_v1`].
///
/// # Safety
///
/// `out_ptr` must be writable for `out_len` bytes, and `out_written` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tempo_fuzz_capabilities_v1(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> c_int {
    unsafe { ffi::capabilities::<Tempo>(out_ptr, out_len, out_written) }
}

/// Writes why the last input this thread executed stopped short, as UTF-8 (empty when every block
/// applied), with the same return values and safety contract as [`tempo_fuzz_capabilities_v1`].
/// An empty reason needs no buffer, so `out_ptr` may then be null.
/// The outcome's [`tempo_fuzz_types::ErrorClass`] says only that it was rejected. This says which
/// check rejected it, such as a transaction's nonce or its fee payment.
///
/// # Safety
///
/// `out_ptr` must be writable for `out_len` bytes, and `out_written` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tempo_fuzz_last_rejection_v1(
    out_ptr: *mut u8,
    out_len: usize,
    out_written: *mut usize,
) -> c_int {
    unsafe { ffi::last_rejection(out_ptr, out_len, out_written) }
}

#[cfg(test)]
mod tests;
