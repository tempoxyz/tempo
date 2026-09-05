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
creation/clearing, contract creation and individual
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

Eight `precompile-native-*` signature presets additionally exercise recover and
verify with fixed-test-key secp256k1, P256 raw/prehashed and WebAuthn signatures.
Generate these and `precompile-native-signature-smoke` using
`ethereum-presets.py --native-signatures`. Their expected outputs have independent
ABI/hash/signer/ECDSA checks (`validate-native-signatures.py`), but native runtime
constructor checks remain mandatory. These explicit calls do not benchmark
implicit transaction authentication or keychain/admin authorization.

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

Seven `gas-access-*` presets add a control, one slot read, two reads of the same
or different slots, and one/two external STATICCALLs to the same or different
probe contracts. All slots/probes are initialized during setup; measured calls
perform at most two reads/calls and no writes. `access-presets.py` emits these
presets and `gas-access-smoke`. Two calls inside one wrapper are not AA batching.
The separate `AccessCalibration` artifact deliberately disables optimization so
the compiler retains repeated SLOADs; do not pool its timings with optimized
`GasCalibration` controls. Use `gas-access-control` for this artifact's overhead.
`node validate-access-fixtures.mjs /path/to/anvil` launches a disposable local
Cancun chain and checks all seven outputs, exact SLOAD counts and cold/warm gas
costs, and exact STATICCALL counts. These Ethereum semantic checks are not Tempo
runtime or pricing evidence; the Tempo smoke and repeated comparisons remain
required. Access warmth resets per transaction, not per block.

Three `gas-aa-access-*-2` presets use two top-level Tempo AA calls to the same
control, single-slot-read, or single-probe-read method. Generate these and their
separate smoke with `access-presets.py --aa-batches`. Compare each with its
`gas-access-*` single-call counterpart; use the two-control-call preset to measure
batch overhead before attributing a difference to storage. These are ordinary
two-call batches, not a batch-size limit test. `validate-aa-access.mjs` takes the
txgen and cast binary paths and checks 100 signed envelopes per preset, their
two exact call targets/selectors, and unique payloads. Offline decoding does not
prove inclusion, warm-state behavior across AA calls, or Tempo execution costs;
runtime checks remain required. No authorization/keychain variants are implied.

The `GasCalibration` constructor checks all three hash/copy precompiles and KECCAK256 against an independently
computed 256-byte fixture before the workload can start. Setup transactions are
handled by txgen's setup barrier and excluded from its measured sending phase.
This does not validate every random input's return value; outer receipt status
and operation-return checks are distinct requirements.

Build settings are solc `0.8.30+commit.73712a01`, optimizer enabled with 200 runs
(except the unoptimized access artifact), and Cancun bytecode. The node's active
fork is set independently by bench-e2e.
`compile.cjs /path/to/solc/package` emits the artifact used by these presets.

Use `gas-hash-control-N` alongside hash functions and `gas-copy-N` alongside
`gas-identity-N`, on identical node builds, runner hardware, account state and
telemetry settings. These are whole-transaction measurements: wrapper work,
calldata/intrinsic gas, authentication, fee handling and return-data costs remain
included. Small arithmetic differences may be below run-to-run noise. Do not
convert these ratios directly into a new opcode or precompile tariff.

For a same-runner comparison, the e2e preset expression
`gas-compare:gas-hash-control-256,gas-sha256-256` assigns the first individual
preset to baseline phases and the second to feature phases. Both sides must use
the same full node SHA, hardfork, build features, node arguments and environment;
both comparison sides are required. Existing run ordering and snapshot restoration
apply unchanged. Use regenerated state until snapshot compatibility is established.
The expression accepts existing individual `gas-*`, `precompile-*` or
`native-read-*` presets, not paths or mixed smoke presets. It does not add workload
batching or change sender rates, concurrency or node limits.

Artifacts preserve both preset files, per-run actual scenario metadata, and the
baseline/feature workload names in `summary.json`. The receipt gate additionally
checks matching node/state/sender metadata and each side's scenario. The summary
labels such comparisons **Unpriced**: descriptive deltas between different
workloads cannot be classified as code improvements or converted into tariff
multipliers. Paired-mode parsing, routing, summary and audit checks are tested
locally; the [first bounded paired smoke](https://github.com/tempoxyz/tempo/actions/runs/33957274123)
also validates runtime routing, matching recorded settings, preserved preset
files and the unpriced report surface, with 38,466 successful captured receipts.
This is one low-rate pair, not a repeatability or pricing result.

The pinned T10 benchmark build leaves the independent TIP-1016 regular/state gas
split disabled. Its zero `state_gas_used` counters therefore do not establish
absence of storage costs, and receipts do not expose a per-operation breakdown.
State-credit, creation, refund, authentication and fee costs still require
explicit accounting; do not subtract a zero state counter and call the remainder
pure execution cost. Deployed mainnet build/source equivalence is a separate
requirement from fixture validation on the pinned comparative baseline.

This study branch requires txgen's `--collect-receipt-outcomes` support. Missing
or inconsistent receipts fail the run; successful outer receipts alone do not
prove every possible nested call succeeded. No protocol gas prices change.

After downloading a comparison artifact, run
`node contrib/bench/gas-study-audit.mjs RESULTS_DIRECTORY` (the existing
`uv run python contrib/bench/gas-study-audit.py RESULTS_DIRECTORY` entrypoint
remains available and delegates to the same Node gate).
The separate read-only gate rejects missing runs, incomplete/inconsistent counts,
reverts (including warmup), submission failures, empty retained windows and
raw/summary mismatches. A pass establishes report consistency only; it is not a
pricing verdict or proof of workload output correctness. This strict gate targets
ordinary successful workloads, not deliberately reverting conformance tests.

The e2e workflow applies this gate to `gas-*`, `precompile-*` and `native-read-*`
presets after generating the summary. A failed gate fails the job and suppresses
the success-result post; raw artifacts and `gas-study-audit.json` are still
uploaded. Other preset families are unchanged. A passing gate is still not a
pricing verdict, semantic proof for every operation, or a saturation check.

The wider study still needs runtime checks and multiple-input measurements for
the inherited precompiles, stateful native methods, additional opcode groups,
repeat-run measurements, and explicit state-growth accounting. These presets are
a coverage increment, not an all-precompile pricing result.
