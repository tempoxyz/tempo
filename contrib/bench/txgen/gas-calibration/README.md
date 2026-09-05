# Ordinary hash/copy calibration workloads

These presets compare SHA-256, RIPEMD-160 and identity precompiles with KECCAK256,
memory-copy and transaction/ABI overhead controls. Each call performs one operation.
Inputs are seeded random byte strings of 32, 256 or 1,024 bytes. The separate
arithmetic preset exercises a small straight-line arithmetic expression.

The constructor checks all three precompiles and KECCAK256 against an independently
computed 256-byte fixture before the workload can start. Setup transactions are
handled by txgen's setup barrier and excluded from its measured sending phase.
This does not validate every random input's return value; outer receipt status
and operation-return checks are distinct requirements.

Build settings are solc `0.8.30+commit.73712a01`, optimizer enabled with 200 runs,
and Cancun bytecode. The node's active fork is set independently by bench-e2e.
`compile.cjs /path/to/solc/package` emits the artifact used by these presets.

Use `gas-hash-control-N` alongside hash functions and `gas-copy-N` alongside
`gas-identity-N`, on identical node builds, runner hardware, account state and
telemetry settings. These are whole-transaction measurements: wrapper work,
calldata/intrinsic gas, authentication, fee handling and return-data costs remain
included. Small arithmetic differences may be below run-to-run noise. Do not
convert these ratios directly into a new opcode or precompile tariff.

This study branch requires txgen's `--collect-receipt-outcomes` support. Missing
or inconsistent receipts fail the run; successful outer receipts alone do not
prove every possible nested call succeeded. No protocol gas prices change.

After downloading a comparison artifact, run
`uv run python contrib/bench/gas-study-audit.py RESULTS_DIRECTORY`.
The separate read-only gate rejects missing runs, incomplete/inconsistent counts,
reverts (including warmup), submission failures, empty retained windows and
raw/summary mismatches. A pass establishes report consistency only; it is not a
pricing verdict or proof of workload output correctness. This strict gate targets
ordinary successful workloads, not deliberately reverting conformance tests.

The wider study still needs other inherited precompiles, stateful native methods,
additional opcode groups, repeat-run measurements, and explicit state-growth
accounting. These presets are a coverage increment, not an all-precompile result.
