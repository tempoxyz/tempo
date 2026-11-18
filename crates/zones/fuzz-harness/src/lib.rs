//! Tempo Zone's stateless block executor for fuzzing and replay, loaded as a cdylib.
//!
//! The same harness as `tempo-fuzz-harness`, on a zone: an input is a [`ZoneHarnessInput`], a
//! [`tempo_fuzz_types::TempoHarnessInput`] with the Tempo L1 state the zone reads. Its blocks
//! execute with the zone node's EVM and block executor on an in-memory state, opened and closed by
//! the system transactions the sequencer adds, and the outcome is a
//! [`tempo_fuzz_types::TempoHarnessOutcome`] with Tempo's protocol invariants checked after every
//! step. It exports the Tempo harness's C ABI, so the same loader runs either.

mod accounts;
mod chain;
mod engine;
mod types;

use core::ffi::c_int;

use tempo_chainspec::hardfork::TempoHardfork;
use tempo_fuzz_engine::ffi;
use tempo_fuzz_types::{
    ErrorClass, HarnessInputKind, PreState, TYPED_HARNESS_SCHEMA_VERSION, TempoExecutionOutcome,
    TempoHarnessCapabilities, TempoHarnessInput, TempoHarnessOutcome,
};

use chain::watched;
pub use engine::{L1, L1Chain, Zone};
pub use types::{L1Input, L1StateInput, ZoneHarnessInput};

/// The hardforks a zone runs: zones launched on T13.
const HARDFORKS: &[TempoHardfork] = &[TempoHardfork::T13, TempoHardfork::T14, TempoHardfork::T15];

/// Executes `input` on a zone that reads its L1 state.
pub fn run(input: ZoneHarnessInput) -> TempoHarnessOutcome {
    if zone_code(&input.input) {
        return invalid(
            &input.input,
            "the zone pre-state holds code a zone never stores",
        );
    }
    match input.l1 {
        L1Input::State(l1) => {
            let zone = Zone::new(L1::state(&l1), watched(&input.input));
            tempo_fuzz_engine::run(&zone, input.input)
        }
        L1Input::Chain(tempo) => chain::run(&tempo, input.input),
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

/// Writes the bincode-encoded [`TempoHarnessCapabilities`] to `out_ptr`.
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
        implementation: "tempo-zone".to_string(),
        git_revision: option_env!("TEMPO_GIT_REVISION")
            .unwrap_or("unknown")
            .to_string(),
        supported_hardforks: HARDFORKS.to_vec().try_into().expect("there are hardforks"),
        supported_inputs: vec![HarnessInputKind::State, HarnessInputKind::Blockchain]
            .try_into()
            .expect("the harness supports inputs"),
    };
    unsafe { ffi::write_encoded(out_ptr, out_len, out_written, &capabilities) }
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

/// Whether `input`'s pre-state holds code starting with 0xef outside the zone genesis: the
/// configurable account marker or a delegation. Zones create no contracts and reject
/// authorization lists, so they never store either.
fn zone_code(input: &TempoHarnessInput) -> bool {
    let accounts = match input {
        TempoHarnessInput::Transaction(_) => return false,
        TempoHarnessInput::State(state) => &state.pre_state.accounts,
        TempoHarnessInput::Blockchain(chain) => match &chain.pre_state {
            PreState::Genesis(state) | PreState::Exact { state, .. } => &state.accounts,
        },
    };
    accounts.iter().any(|(address, account)| {
        !engine::GENESIS_STATE.accounts.contains_key(address) && account.code.first() == Some(&0xef)
    })
}

/// The outcome of `input`'s kind for an input the zone cannot run, rejected for `why`.
fn invalid(input: &TempoHarnessInput, why: &'static str) -> TempoHarnessOutcome {
    let error = tempo_fuzz_engine::reject(ErrorClass::InvalidInput, why);
    chain::failed(
        input,
        TempoExecutionOutcome {
            error,
            ..Default::default()
        },
    )
}
