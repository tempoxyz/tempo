# Differential fuzzer for the Kaizen follower core

Runs the Lean-extracted follower core (`Kaizen/FFI.lean`, compiled to C exactly as `shim/` does) side by side with an independent Rust reference, and fails on the first step where they disagree.

## What is compared

After every step: the result code (0..12), the tip (height, digest, stateRoot) and the exact sequence of oracle calls (`kz_verify_finalization` and `kz_verify_execution` arguments and results).

The reference ([`src/reference.rs`](src/reference.rs)) is written from Tempo's and commonware's Rust code, not from the Lean code:

- decoding uses commonware's `Finalization<Scheme<PublicKey, MinSig>, Digest>::decode`
- the epoch comes from `FixedEpocher::containing`, rounds from commonware's `Ord` on `Round`, and the boundary test from `EpochInfo::last`
- identity selection follows `FinalizationVerifier::verify_certificate` (the scheme provider first, then the network identity if `epoch >= from_epoch`, with the fallback scheme registered after it verifies)

Check order and codes follow `Kaizen/Follower/Spec.lean`. Inputs that Tempo's code cannot process (epoch length 1 panics in `FixedEpocher::new`, and heights in the final partial epoch near `u64::MAX` make `containing` return `None`, so Tempo's `expect` panics) are counted as *unsupported*, and the sequence stops there.

Both sides call the same oracles ([`src/oracle.rs`](src/oracle.rs)):

- **Fake**: a signature is valid iff it equals the first 96 bytes of sha256-expanded(key, epoch, view, parent, payload), and execution is valid iff post == sha256(pre || digest). Generators use this to build valid chains.
- **AcceptAll**: replays real certificates in the fuzzer.
- **RealBls**: `verify_finalization` copied from the shim, with execution always valid.

Inputs ([`src/generate.rs`](src/generate.rs)) come in four kinds:

- fully random candidates
- replays of earlier candidates
- random structured certificates
- valid next blocks encoded with commonware's `Encode`, then optionally mutated

Field mutations include:

- epoch, height or view off by one, including around boundaries, and `u64::MAX` values
- round regressions
- payload, signature, parent or stateRoot mismatches, and re-signing with the wrong key
- a missing DKG outcome, or one for the wrong epoch or with the wrong key
- wrong digest or signature lengths

Encoding mutations cover non-canonical, overflowing, 11-byte and unterminated varints. Byte mutations flip, insert or delete bytes, truncate, add trailing bytes, or overwrite header bytes.

## Run

```sh
cargo run --release --bin diff -- --iters 2000000 --seed 1          # deterministic, stable toolchain
cargo run --release --bin diff -- --real 2400 --mutations 3        # testnet blocks + mutations, real BLS
cargo run --release --bin diff -- --real 2400 --write-corpus fuzz/seeds/step_diff    # re-seed from testnet
cargo run --release --bin diff -- --replay divergences/<file>.hex  # replay a saved divergence
ASAN_OPTIONS=detect_leaks=0 cargo +nightly fuzz run step_diff -O fuzz/corpus/step_diff fuzz/seeds/step_diff -- -max_total_time=1200 -fork=3
```

`fuzz/seeds/step_diff` holds 145 seeds made from real testnet certificates: 8-block chains, single certificates and an epoch-boundary window.

On a divergence, `diff` minimizes the candidate list, prints both outputs and writes a replay file (`divergences/`). The fuzz target panics with the same report, and the replay format starts with byte 0xFF, so a report can go back into either runner. Under cargo-fuzz, `build.rs` compiles the Lean-generated C with Lean's bundled clang and SanitizerCoverage, so coverage of the verified core guides libFuzzer. Leak detection must be off because the Lean runtime keeps global objects alive. `KAIZEN_LEAN_DIR` defaults to `..`.
