#![no_main]
//! libFuzzer target: one input drives a config and a sequence of up to 64 candidates (or a
//! replay-format input, first byte 0xFF); the Lean core and the reference must agree on every
//! result code, tip (height, digest, stateRoot) and oracle call.
use kaizen_fuzz::diff::{Stats, describe, minimize, run_input};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut s = Stats::default();
    if let Err(f) = run_input(data, 64, &mut s) {
        let m = minimize(&f);
        panic!("{}", describe(&m));
    }
});
