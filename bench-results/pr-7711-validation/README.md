# PR upload validation

Checks run while preparing the completed benchmark work for PR #7711:

- `node --test contrib/bench/*.test.cjs`: 100 passed.
- `bash contrib/bench/txgen/compile-history-state-paths.sh --test`: 18 passed.
- `cargo test --offline --config contrib/bench/payload-cancel-patches.toml -p tempo-payload-builder --lib -j1`: 26 passed; see `payload-tests.log`.
- In the patched txgen checkout, `cargo test --offline -p txgen-tempo --lib access_list -j1`: 3 passed; see `txgen-access-list-tests.log`.
- `cargo +nightly fmt -p tempo-payload-builder -p tempo-consensus`: completed.
- `cargo metadata --offline --locked --no-deps --format-version 1`: passed with the normal Git dependency pins.
- All top-level benchmark `.cjs` and `.sh` files passed `node --check` and `bash -n`.
- `nu --no-config-file -c 'source bench-e2e.nu'`: passed.
- All three C diagnostic helpers passed strict syntax checks; MDBX diagnostics used the bundled MDBX header and `-Wno-deprecated-declarations`.
- Both complete dependency patches passed `git apply --cached --check` against temporary indexes at their pinned clean bases, including new files. Generated Reth overrides match the measured local configuration.

The long performance runs were not repeated for this packaging change. Their
original correctness audits, test records, and timing boundaries remain in the
individual experiment reports. Rust payload tests used the patched benchmark
Reth dependency; the Cargo metadata check is not a full unpatched workspace build.
