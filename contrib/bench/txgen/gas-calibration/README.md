# Ordinary precompile/opcode calibration workloads

These presets compare SHA-256, RIPEMD-160 and identity precompiles with KECCAK256,
memory-copy and transaction/ABI overhead controls. Each hash call performs one operation.
Inputs are seeded random byte strings of 32, 256 or 1,024 bytes. The separate
arithmetic preset exercises a small straight-line arithmetic expression.

Additional bounded application-style opcode fixtures (no workload loops):

| Preset | Work performed | Interpretation |
| --- | --- | --- |
| storage-read | Read one existing slot | Cold slot at transaction entry |
| storage-write | Update one existing nonzero slot | Random nonzero values; rare unchanged writes remain possible |
| transient | One TSTORE/TLOAD round trip | No persistent growth; transaction-local use only |
| log-N | Emit one event with a tag and N bytes | LOG2 plus ABI encoding, memory and data costs |
| account-context | Return caller, own balance, chain ID, number and timestamp | Small mixed environment baseline, not isolated opcode timings |
| echo / self-call | Return a value directly / through one self-STATICCALL | Own address is warm; not a cold-account comparison |
| branch | One even/odd branch and arithmetic | Ordinary control-flow sequence, not an exhaustive flow-opcode test |

The constructor initializes one nonzero storage slot outside the measured phase.
None of these workload calls creates an unbounded set of storage keys. State
creation/clearing, cold external-account calls, contract creation and individual
opcode microbenchmarks remain separate coverage obligations. Any artifact change
also changes dispatcher layout; compare only identically compiled artifacts.

`gas-calibration-smoke` is a uniform random mix of all 29 individual presets for
low-rate runtime smoke testing only. It cannot price any individual operation.
`smoke.py` regenerates that YAML from the base template and individual presets;
its output must be regenerated when those presets change. Seed 42 with 1,000
generated workload transactions exercises all 29 template IDs offline, but live
inclusion and per-operation output checks still require runtime evidence.

The 18 `precompile-*` individual presets cover the exact pinned Osaka registry,
using `ethereum-fixtures.json` from the [ordinary fixture generator](../../crypto-fixture-generator/README.md).
`ethereum-presets.py` emits their YAML and `precompile-ethereum-smoke`.
The source-attributed KZG and twelve-round BLAKE2b inputs are also retained in
`crypto-fixtures.json`; the other fixtures include ordinary signatures, bounded
EC operations and RSA-sized modular exponentiation. These are separate from the
29-way hash/opcode mix and do not establish complete input distributions.

Three additional mainnet-sized variants use `mainnet-size-fixtures.json`:
SHA-256 at 448 bytes, MODEXP with three 32-byte operands, and four-pair BN254.
Generate their presets with `ethereum-presets.py --mainnet-sizes`; their
`precompile-mainnet-size-smoke` is separate from the 18-address smoke. The
fixture generator README records the dated aggregate supporting these sizes.
These are generated valid inputs, not mainnet replays or pricing evidence.

`PrecompileCalibration` checks every selected fixture's expected result in its
bounded constructor (one fixture for individual presets, 18 for the smoke), then makes
one precompile invocation per workload transaction and rejects call failures or
empty output. Fixed fixtures do not establish a distribution over cryptographic
inputs, and wrapper, transaction, authentication and fee costs are still included.
The pinned txgen makes expiring-nonce signed payloads unique; offline generation
with one signer verified this for the initial KZG/BLAKE2 fixtures.
Compile this wrapper with `compile.cjs /path/to/solc/package PrecompileCalibration`.
The array-based constructor requires [txgen#198](https://github.com/tempoxyz/txgen/pull/198),
tested at `45240f0090d1419583558534d51c9402992355b2` (which includes receipt collection).
Record that pin separately from earlier `13cb6b3` control runs; do not silently
pool measurements from different generator revisions.

The separate [native public-read fixtures](NATIVE_READS.md) add 15 source-gated
read paths and a low-rate smoke mix. Their runtime validation and broader native
mutation/lifecycle coverage remain separate from the hash/opcode fixtures.

The `GasCalibration` constructor checks all three hash/copy precompiles and KECCAK256 against an independently
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

The wider study still needs runtime checks and multiple-input measurements for
the inherited precompiles, stateful native methods, additional opcode groups,
repeat-run measurements, and explicit state-growth accounting. These presets are
a coverage increment, not an all-precompile pricing result.
