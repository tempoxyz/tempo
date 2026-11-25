//! Tempo Zone's stateless block executor for fuzzing and replay, loaded as a cdylib.
//!
//! The same harness as `tempo-fuzz-harness`, on a zone: an input is a [`ZoneHarnessInput`], a
//! [`tempo_fuzz_types::TempoHarnessInput`] with the Tempo L1 state the zone reads. Its blocks
//! execute with the zone node's EVM, block executor and consensus on an in-memory state; a block
//! whose header the harness builds opens and closes with the system transactions the sequencer
//! adds. The outcome is a [`tempo_fuzz_types::TempoHarnessOutcome`] with Tempo's protocol
//! invariants checked after every step. It exports the Tempo harness's C ABI, so the same loader
//! runs either.

mod accounts;
mod consensus;
mod engine;
mod types;

use core::ffi::c_int;

use alloy_primitives::Address;
use tempo_fuzz_engine::{Rejection, ffi};
use tempo_fuzz_types::{PreState, TempoHarnessInput, TempoHarnessOutcome};

pub use consensus::ZoneConsensus;
pub use engine::{L1, Zone};
pub use types::{L1StateInput, ZoneHarnessInput};

/// Executes `input` on a zone that reads its L1 state. Returns the outcome and, unless its error
/// is `None`, why it stopped short.
pub fn run(input: ZoneHarnessInput) -> (TempoHarnessOutcome, Option<Rejection>) {
    let watched = watched(&input.input);
    tempo_fuzz_engine::run(&Zone::new(input.l1, watched), input.input)
}

/// The accounts `input` names, which the account checks watch: its pre-state's, then its senders.
fn watched(input: &TempoHarnessInput) -> Vec<Address> {
    match input {
        TempoHarnessInput::Transaction(input) => input.sender.into_iter().collect(),
        TempoHarnessInput::State(input) => input
            .pre_state
            .accounts
            .keys()
            .copied()
            .chain(input.sender)
            .collect(),
        TempoHarnessInput::Blockchain(input) => {
            let (PreState::Genesis(state) | PreState::Exact { state, .. }) = &input.pre_state;
            state
                .accounts
                .keys()
                .copied()
                .chain(
                    input
                        .blocks
                        .as_slice()
                        .iter()
                        .flat_map(|block| block.senders.iter().copied()),
                )
                .collect()
        }
    }
}

/// Executes a bincode-encoded [`ZoneHarnessInput`] and writes the bincode-encoded
/// [`TempoHarnessOutcome`] to `out_ptr`, with the Tempo harness's return values.
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
    unsafe { ffi::execute(out_ptr, out_len, out_written, input, run) }
}

/// Writes the bincode-encoded [`tempo_fuzz_types::TempoHarnessCapabilities`] to `out_ptr`.
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
    unsafe { ffi::capabilities::<Zone>(out_ptr, out_len, out_written) }
}

/// Writes why the last input this thread executed stopped short, as the Tempo harness does.
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
