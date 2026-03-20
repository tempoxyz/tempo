#![no_main]

use libfuzzer_sys::fuzz_target;
use tempo_evm_fuzz::input::FuzzInput;
use tempo_evm_fuzz::normalize::NormalizedInput;

fuzz_target!(|input: FuzzInput| {
    let normalized = NormalizedInput::from_raw(input);

    // TODO: Build scenario from normalized input
    // TODO: Run oracle (sequential reference)
    // TODO: Run SUT (real executor)
    // TODO: Assert invariants
    let _ = normalized;
});
