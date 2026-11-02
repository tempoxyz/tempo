//! Tempo's stateless block executor for fuzzing and replay, loaded as a cdylib.
//!
//! An input is a chain, a pre-state and blocks ([`tempo_fuzz_types`]). The harness executes the
//! blocks with Tempo's block executor on an in-memory state and reports receipts, the resulting
//! state, what changed, and which protocol invariants broke. A panic inside the executor aborts the
//! process: the node would crash on the same block.

mod chain;
mod execute;
mod invariants;
mod state;

use bincode::Options as _;
use core::ffi::c_int;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_fuzz_types::{
    FUZZ_ACCEPT, FUZZ_REJECT, HarnessInputKind, TYPED_HARNESS_SCHEMA_VERSION,
    TempoHarnessCapabilities, TempoHarnessInput,
};

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
        return FUZZ_REJECT;
    }
    let input = unsafe { core::slice::from_raw_parts(in_ptr, in_len) };
    let Ok(input) = bincode_options().deserialize::<TempoHarnessInput>(input) else {
        return FUZZ_REJECT;
    };
    let Ok(outcome) = bincode_options().serialize(&execute::run(input)) else {
        return FUZZ_REJECT;
    };
    unsafe { write_output(out_ptr, out_len, out_written, &outcome) }
}

/// Writes the bincode-encoded [`TempoHarnessCapabilities`] to `out_ptr`, with the same return
/// values and safety contract as [`tempo_fuzz_execute_with_result_v1`].
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
    let capabilities = TempoHarnessCapabilities {
        schema_version: TYPED_HARNESS_SCHEMA_VERSION,
        implementation: "tempo".to_string(),
        git_revision: option_env!("TEMPO_GIT_REVISION")
            .unwrap_or("unknown")
            .to_string(),
        supported_hardforks: TempoHardfork::VARIANTS
            .to_vec()
            .try_into()
            .expect("there are hardforks"),
        supported_inputs: vec![
            HarnessInputKind::Transaction,
            HarnessInputKind::State,
            HarnessInputKind::Blockchain,
        ]
        .try_into()
        .expect("the harness supports inputs"),
    };
    let Ok(capabilities) = bincode_options().serialize(&capabilities) else {
        return FUZZ_REJECT;
    };
    unsafe { write_output(out_ptr, out_len, out_written, &capabilities) }
}

/// `bincode::serialize`'s encoding, rejecting trailing bytes.
fn bincode_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

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

#[cfg(test)]
mod tests;
