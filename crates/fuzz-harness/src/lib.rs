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
    ErrorClass, FUZZ_ACCEPT, FUZZ_REJECT, HarnessInputKind, TYPED_HARNESS_SCHEMA_VERSION,
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
    execute::reset_execution_time();
    if in_ptr.is_null() {
        execute::reject(ErrorClass::InvalidInput, execute::Check::Null);
        return FUZZ_REJECT;
    }
    let input = unsafe { core::slice::from_raw_parts(in_ptr, in_len) };
    let Ok(input) = bincode_options().deserialize::<TempoHarnessInput>(input) else {
        execute::reject(ErrorClass::InvalidInput, execute::Check::HarnessInput);
        return FUZZ_REJECT;
    };
    let Ok(outcome) = bincode_options().serialize(&execute::run(input)) else {
        execute::reset_execution_time();
        execute::reject(ErrorClass::Internal, execute::Check::OutcomeEncoding);
        return FUZZ_REJECT;
    };
    let result = unsafe { write_output(out_ptr, out_len, out_written, &outcome) };
    if result == FUZZ_REJECT {
        execute::reset_execution_time();
    }
    result
}

/// Returns executor nanoseconds for the last execution request on the calling thread.
///
/// Includes pre-execution changes, transactions and finalization, but excludes input decoding,
/// state setup, invariant checks and outcome encoding. Rejected requests reset the counter;
/// a partial execution can have a nonzero value, so callers must check the outcome separately.
/// This optional symbol does not change the serialized harness ABI.
#[unsafe(no_mangle)]
pub extern "C" fn tempo_fuzz_execution_nanos_v1() -> u64 {
    execute::execution_nanos()
}

/// Copies executor-only LLVM counters for the last request on this thread.
///
/// Requires an `executor-counters` build with `-C instrument-coverage`. Slots match the LLVM
/// counter section. Snapshots bracket only the executor's timed regions, including finalization;
/// decoding, state setup, invariants and outcome encoding are excluded. Snapshot and timer
/// bookkeeping may contribute a small number of counts. LLVM counters are process-global, so
/// concurrent harness calls or other instrumented work must be excluded by the caller.
///
/// Lengths are in `u64` elements, not bytes. A null or short destination reports the required
/// length through `out_written` and returns `FUZZ_REJECT`; a sufficient destination returns
/// `FUZZ_ACCEPT`. A null `out_written` returns `FUZZ_REJECT`. Retrieval never resamples counters
/// or changes saved values. Before the first execution it reports a full zero-filled vector.
/// Rejected execution ABI calls zero the saved vector.
///
/// # Safety
///
/// `out_written` must be writable and aligned when nonnull. When nonnull and sufficiently long,
/// `out_ptr` must be aligned and writable for the reported number of `u64` elements. These
/// destinations must not overlap each other or the harness's internal counter storage.
#[cfg(feature = "executor-counters")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tempo_fuzz_executor_counts_v1(
    out_ptr: *mut u64,
    out_len: usize,
    out_written: *mut usize,
) -> c_int {
    if out_written.is_null() {
        return FUZZ_REJECT;
    }
    execute::with_executor_counts(|counts| {
        unsafe { *out_written = counts.len() };
        if out_ptr.is_null() || out_len < counts.len() {
            return FUZZ_REJECT;
        }
        unsafe { core::ptr::copy_nonoverlapping(counts.as_ptr(), out_ptr, counts.len()) };
        FUZZ_ACCEPT
    })
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
    execute::with_rejection(|why| {
        if why.is_empty() && !out_written.is_null() {
            unsafe { *out_written = 0 };
            return FUZZ_ACCEPT;
        }
        unsafe { write_output(out_ptr, out_len, out_written, why.as_bytes()) }
    })
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
