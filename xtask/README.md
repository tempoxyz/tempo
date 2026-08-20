# tempo-xtask

A polyfill to perform various operations on the codebase.

Subcommands currently supported:

+ `generate-config`: generates a set of validators to run a local network.
+ `add-hardfork --hardfork T11`: generates the mechanical plumbing for a new hardfork and rotates
  the `default`/`next` Foundry profiles.
+ `generate-benchmark-suite`: exports canonical blocks from a populated Tempo node as a
  `tempo-engine-suite/v1` manifest for Benchmarkoor.

## Benchmarkoor suites

Generate workload blocks with txgen or an integration test, leave the source Tempo node running,
then export the chain prefix and the measured range:

```sh
cargo xtask generate-benchmark-suite \
  --rpc-url http://127.0.0.1:8545 \
  --genesis /path/to/genesis.json \
  --out /tmp/tempo-suites/tip20-transfer \
  --name tip20-transfer \
  --from-block 101 \
  --to-block 200 \
  --tag tempo-native \
  --tag tip20 \
  --tag transfer \
  --seed 42 \
  --revision "$(git rev-parse HEAD)" \
  --hardfork presto \
  --chain-id 42431
```

For a workload derived from another repository, override provenance and attach
source-specific dimensions without changing the canonical Tempo block format:

```sh
cargo xtask generate-benchmark-suite \
  ... \
  --origin-kind eest \
  --origin-repository https://github.com/ethereum/execution-specs \
  --generator 'EEST execute remote + Tempo TIP-20 adapter + tempo-xtask export' \
  --metadata source_test=tests/benchmark/compute/instruction/test_arithmetic.py \
  --metadata source_fork=Prague \
  --metadata gas_target_millions=10
```

For a multi-test EEST run, `contrib/bench/eest/run-batch.sh` writes one JSONL
capture record per pytest node. Passing cases can be exported as independent
measured tests on the same canonical chain:

```sh
cargo xtask generate-benchmark-suite \
  --rpc-url http://127.0.0.1:18545 \
  --genesis crates/chainspec/src/genesis/dev.json \
  --out /tmp/tempo-suites/eest-batch \
  --name eest-batch \
  --capture-file /tmp/eest-capture.jsonl \
  --origin-kind eest \
  --tag eest --tag tempo-normalized
```

The exporter measures the final transaction-bearing block of every passing
capture record and includes all intervening canonical blocks as setup. This
preserves parent hashes and state roots even when a failed EEST case produced
blocks between two passing cases.

Blocks `1..100` become setup and blocks `101..200` become the measured test phase. Each exported
block includes raw RLP, its block access list, gas/transaction metadata, the expected payload
status, and a following `reth_forkchoiceUpdated`. Benchmarkoor starts Tempo from the copied genesis,
replays setup, measures the test calls, and reports server execution time separately from HTTP
round-trip time.

Use the same command after each deterministic workload producer. The initial suite matrix should
cover at least these independent dimensions:

1. Ethereum-compatible legacy, EIP-1559, EIP-2930, and EIP-7702 transactions.
2. Tempo AA authorization modes: direct, keychain, and key authorization.
3. TIP-20 transfers, existing/random recipients, and multi-payment processing.
4. Fee-token selection and fee-AMM liquidity/path behavior.
5. Two-dimensional, expiring, and protocol nonce paths.
6. DEX and neobank deposit/swap/withdraw workloads.
7. State-growth, storage-credit, payment-lane, and gas-limit boundary workloads.
8. Subblock, consensus-context, hardfork-transition, invalid-block, and cache/BAL cases.

The presets under `contrib/bench/txgen/presets/` are the starting producers for items 2–6. Keep
workload generation separate from replay: the exported manifest records the seed, revision,
hardfork, tags, and exact bytes, so a performance comparison always executes identical data.

### Starting from an existing Benchmarkoor suite

Benchmarkoor's standard suites contain Ethereum `ExecutionPayload` objects. They cannot be sent
directly to Tempo because Tempo uses an extended header and disables `engine_newPayload*`.
The offline importer below is a structural compatibility tool: it can reuse transaction-free
payloads, or transactions already valid under Tempo's fee schedule and limits. It cannot rewrite a
signed transaction's chain ID, gas price, fee token, or gas limit. In particular, the upstream
100M gas-benchmark corpus uses 7-wei headers and 10-wei signed transactions, so its converted
payloads are useful as a rejection report but not as Tempo performance data.

For transactional EEST benchmarks, regenerate the workload on a published Tempo dev node with the
TIP-20 funding/deployment adapter in `contrib/bench/eest`, then export the canonical blocks with
`generate-benchmark-suite`. That path retains the EEST test definition while producing valid Tempo
signatures, fees, state roots, headers, and block access lists.

Convert either a generated Benchmarkoor result suite or the raw request corpus into Tempo block
RLP first. For the upstream `NethermindEth/gas-benchmarks` repository:

```sh
cargo xtask import-benchmarkoor-suite \
  --requests-dir /path/to/gas-benchmarks \
  --genesis /path/to/gas-benchmarks/scripts/genesisfiles/geth/zkevmgenesis.json \
  --out /tmp/tempo-suites/gas-benchmarks-prague \
  --name gas-benchmarks-prague \
  --tag eest \
  --tag ethereum-compat \
  --revision "$(git -C /path/to/gas-benchmarks rev-parse HEAD)" \
  --skip-incompatible
```

The importer recursively finds each `testing` request file and its optional sibling `setup` and
`cleanup` files. With `--skip-incompatible`, it writes every rejected test and the precise reason
to `conversion-report.json`; without that flag, conversion stops on the first incompatible case.
The generated manifest also records the source corpus hash, source/converted/skipped counts, and
revision so a report can be traced back to exact input bytes.

To convert an already-generated Benchmarkoor result suite instead:

```sh
cargo xtask import-benchmarkoor-suite \
  --suite-dir /path/to/benchmarkoor/results/suites/SUITE_HASH \
  --genesis /path/to/the/suite/genesis.json \
  --out /tmp/tempo-suites/eest-compat \
  --name eest-compat \
  --tag eest \
  --tag ethereum-compat \
  --revision BENCHMARKOOR_OR_EEST_REVISION
```

The adapter preserves transactions, execution roots, gas metadata, and the setup/test/cleanup
boundary, rewrites parent hashes to the corresponding Tempo headers, and emits Tempo RLP plus Reth
forkchoice calls. It deliberately rejects non-empty withdrawals, blob transactions, unknown parent
chains, and non-linear payload streams; those need an explicit Tempo policy rather than a silent
lossy conversion. Start with a small stateless EEST filter, run the converted suite, and keep
failures as compatibility signals in the report before expanding the imported corpus.

### Integration points considered

1. Send Benchmarkoor's standard `engine_newPayload*` requests directly to Tempo. This is the
   smallest runner change, but it cannot represent Tempo's extended header or transaction types.
2. Translate requests inside Benchmarkoor's HTTP executor. This centralizes replay, but couples a
   general benchmark runner to Tempo consensus rules and makes fixture identity harder to audit.
3. Add a versioned semantic suite source to Benchmarkoor. This keeps its lifecycle, isolation,
   metrics, and report pipeline while allowing raw block RLP and explicit Engine API calls.
4. Convert an existing Benchmarkoor suite offline in Tempo. Tempo owns header adaptation and can
   reject unsupported Ethereum cases before a timed run.
5. Export canonical blocks from a populated Tempo node. Existing txgen and integration-test
   workloads can produce AA, TIP-20, fee-token, nonce, DEX, and other Tempo-native suites without
   teaching Benchmarkoor how to construct them.
6. Run workload generators live against the node during measurement. This is useful for end-to-end
   throughput, but mixes transaction submission, block building, and execution latency.
7. Distribute prebuilt Tempo datadirs or snapshots. Startup is fast for large state benchmarks, but
   artifacts are heavier and less portable than a genesis plus deterministic block stream.

The implemented path combines 3, 4, and 5: both imported compatibility cases and Tempo-native
blocks use the same `tempo-engine-suite/v1` replay and Benchmarkoor reporting path. Live generation
and prebuilt snapshots remain complementary modes for later end-to-end and large-state studies.
