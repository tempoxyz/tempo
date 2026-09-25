# txgen

A chain-agnostic transaction generation tool for blockchain load testing and benchmarking.

## Overview

txgen generates signed, RLP-encoded transactions from YAML workload specifications. It outputs transactions as newline-delimited JSON (NDJSON) that can be piped to sending tools or saved for later use.

For end-to-end workflow examples, see the [txgen Cookbook](COOKBOOK.md).

**Key features:**
- **Chain-agnostic**: Plugin architecture supports multiple chains (Ethereum, Tempo)
- **Deterministic**: Seed-based RNG for reproducible transaction generation
- **Flexible**: YAML specs with weighted template mixing, value generators, and account pools
- **Multi-chain scenarios**: Run correlated submit, receipt, and event workflows from one command
- **Fast generation**: Generate transaction streams without network I/O

## Installation

```bash
cargo install --path crates/txgen-ethereum
cargo install --path crates/txgen-tempo
cargo install --path crates/bench-cli
```

Or build from source:

```bash
cargo build --release
```

## CLI Tools

The workspace provides three binaries: `txgen-ethereum` and `txgen-tempo` for chain-specific transaction workflows, and `bench` for benchmarking. Transaction generation remains offline; `scenario run` connects directly to every chain named by a scenario, while `scenario validate` and `scenario render` perform offline checks only.

### `txgen-ethereum` / `txgen-tempo`

#### `generate`

Generate transactions from a workload spec.

```bash
# Generate 1000 Ethereum transactions
txgen-ethereum generate -s workload.yaml -n 1000

# Generate Tempo transactions with reproducible seed
txgen-tempo generate -s workload.yaml -n 1000 --seed 42

# Generate for a bounded wall-clock duration
txgen-tempo generate -s workload.yaml --duration 5m

# Fetch nonces from chain before generating
txgen-ethereum generate -s workload.yaml -n 1000 --rpc http://localhost:8545

# Output to file
txgen-ethereum generate -s workload.yaml -n 1000 -o transactions.ndjson
```

| Flag | Description |
|------|-------------|
| `-s, --spec <PATH>` | Workload specification file (YAML) |
| `-n, --count <N>` | Maximum number of workload transactions to generate; required unless `--duration` is set |
| `--duration <DUR>` | Maximum workload generation duration; setup is emitted first and excluded |
| `-o, --output <PATH>` | Output file (default: stdout) |
| `--rpc <URL>` | RPC endpoint for fetching current nonces |
| `--seed <SEED>` | RNG seed for reproducibility |

**Required RPC methods:** `eth_getTransactionCount` (only when `--rpc` is provided)

#### `scenario run`

Run an asynchronous, multi-chain transaction workflow from one process. A scenario references existing workload templates for transaction construction and adds checkpoints, receipt waits, event waits, cross-step values, concurrency controls, and journey-level reporting. It does not replace the workload specification or change the `generate` output format.

```bash
txgen-tempo scenario run \
  --scenario scenario.yaml \
  --count 100 \
  --starts-per-second 5 \
  --max-in-flight 20 \
  --tx-rate 50 \
  --max-rpc-in-flight 100 \
  --seed 42 \
  --failure-policy continue \
  --report json:scenario-report.json
```

| Flag | Description |
|------|-------------|
| `--scenario <PATH>` | Versioned scenario YAML file |
| `--count <N>` | Maximum scenario instances to start; defaults to `1` when `--duration` is omitted |
| `--duration <DUR>` | Stop starting instances after this run duration; in-flight instances are then completed |
| `--starts-per-second <RATE>` | New scenario journeys started per second, not transaction TPS (`0`, the default, is unlimited) |
| `--max-in-flight <N>` | Maximum active scenario instances (default: `1`) |
| `--step-timeout <DUR>` | Override the scenario's default step timeout; an explicit timeout on a step remains more specific |
| `--seed <SEED>` | Deterministic binding and workload seed |
| `--failure-policy <POLICY>` | `continue` (default) or `fail-fast` |
| `--tx-rate <TPS>` | Separate per-chain transaction-submission limit across scenario instances (`0` = unlimited) |
| `--max-rpc-in-flight <N>` | Upper bound on simultaneous transaction-submission RPC calls per chain (default: `100`) |
| `--report <DESTINATION>` | Report destination; repeat for more than one. A bare path or `json:<path>` writes JSON, and `clickhouse:<url>` publishes to ClickHouse. JSON is written to stdout when omitted |
| `-m, --metadata <KEY=VALUE>` | Metadata for external reporters; repeat for additional fields. ClickHouse requires `git-sha` and `git-ref` |
| `--sample-instances <N>` | Include up to `N` sanitized instance lifecycle records in the report (default: `0`) |

When both `--count` and `--duration` are present, txgen stops starting journeys at the first limit. See [Scenario Specification](#scenario-specification) for the schema, step results, expressions, and execution semantics.

#### `scenario validate`

Resolve and statically validate a scenario without connecting to its RPC endpoints:

```bash
txgen-tempo scenario validate --scenario scenario.yaml
```

Validation expands included fragments first, then loads the referenced workload and ABI files and checks chains, bindings, templates, events, filters, saves, DAG IDs and dependencies, output ancestry, and statically known types. A valid document prints a success message and exits with status zero; invalid input reports its composition or validation context and exits nonzero. Remote chain IDs, nonces, and deployed state are checked only by `scenario run`.

#### `scenario render`

Validate a scenario and print its deterministic, fully expanded YAML form:

```bash
# Print to stdout.
txgen-tempo scenario render --scenario scenario.yaml

# Write to a file instead.
txgen-tempo scenario render \
  --scenario scenario.yaml \
  --output rendered.yaml
```

The rendered document contains ordinary inline steps with resolved workload paths: top-level `include` and `fragments` declarations are removed, fragment `use` steps are replaced in place, and fragment-authored `{ param: name }` expressions are substituted. Literal keys with those names in ordinary application data are preserved. Omitting `--output` writes YAML to stdout. Composition provenance is intentionally not serialized, so loading the rendered file later treats its steps as ordinary inline steps and cannot reproduce the original fragment metadata in reports or errors. Rendering is offline, but environment references are expanded while loading, so rendered RPC URLs may contain credentials and should be handled accordingly.

#### `addresses`

List signer account addresses from a workload spec (useful for funding). Destination-only `address_pools` are intentionally omitted.

```bash
txgen-ethereum addresses -s workload.yaml
txgen-ethereum addresses -s workload.yaml -f json
txgen-ethereum addresses -s workload.yaml -f shell   # space-separated for xargs
```

| Flag | Description |
|------|-------------|
| `-s, --spec <PATH>` | Workload specification file (YAML) |
| `-f, --format <FMT>` | Output format: `plain`, `json`, `shell` (default: `plain`) |

**Required RPC methods:** None (offline)

#### `auth-token-map` (Tempo only)

Generate a Zone private-RPC authorization-token map for the exact logical signers in one account pool. The command loads the pool through the normal `WorkloadSpec` environment expansion and account derivation paths, including the existing `[start, end)` range semantics.

```bash
# Generate a one-shot map
txgen-tempo auth-token-map \
  --spec zones-workload.yml \
  --pool users \
  --zone-id 71 \
  --chain-id 421700071 \
  --ttl-secs 600 \
  --output /run/secrets/zone-auth-tokens.json

# Refresh the complete map before its tokens expire
txgen-tempo auth-token-map \
  --spec zones-workload.yml \
  --pool users \
  --zone-id 71 \
  --chain-id 421700071 \
  --ttl-secs 600 \
  --refresh-before-secs 30 \
  --watch \
  --output /run/secrets/zone-auth-tokens.json
```

| Flag | Description |
|------|-------------|
| `--spec <PATH>` | Workload specification file (YAML); `${ENV_VAR}` values are expanded before parsing |
| `--pool <NAME>` | Non-empty logical/root signer pool to include |
| `--zone-id <ID>` | Nonzero Zone ID encoded in every token |
| `--chain-id <ID>` | Chain ID encoded in every token |
| `--ttl-secs <N>` | Token lifetime in seconds (default: 600; maximum: 2,592,000, or 30 days) |
| `--refresh-before-secs <N>` | Refresh lead time, which must be less than the TTL (default: 30) |
| `--watch` | Keep running and atomically replace the complete map before expiry |
| `--output <PATH>` | Secret output file |
| `--force` | Replace an existing output in one-shot mode |

The compact JSON output is a flat, address-sorted map from normalized lowercase `0x`-prefixed logical sender addresses to 188-character lowercase hex tokens without a `0x` prefix. Every token in one refresh shares the same issue and expiry timestamps. Keychain workloads use the root account pool: access keys do not receive separate entries because the root account token authenticates the logical sender.

Treat the output as a secret. Write it to a runtime secret directory rather than the repository; on Unix, txgen creates replacement files with mode `0600` and atomically renames them so readers do not observe partial content. It does not print the map, mnemonic, private keys, signatures, or tokens. One-shot mode rejects an existing output unless `--force` is supplied, while watch mode retains the last valid file if a refresh fails. A typical 1,000-account map is about 236 KB (230.5 KiB).

The 30-day TTL limit is the protocol maximum; a remote Zone node may enforce a smaller maximum. This command only derives accounts and writes tokens locally—it does not submit RPC requests or distribute the map.

**Required RPC methods:** None (offline)

#### `extract`

Extract raw RLP-encoded blocks from an archive node as NDJSON. Use `--bal` to attach RLP-encoded block access lists for replaying EIP-7928/Amsterdam payloads.

```bash
txgen-ethereum extract --rpc http://localhost:8545 --from 1000 --to 2000 -o blocks.ndjson

# Extract the blocks' signed transactions for replay on transaction basis
txgen-ethereum extract --rpc http://localhost:8545 --from 1000 --to 2000 \
  --format transactions | bench send --rpc-url http://localhost:8545
```

| Flag | Description |
|------|-------------|
| `--rpc <URL>` | RPC endpoint (archive node) |
| `--from <N>` | First block number (inclusive) |
| `--to <N>` | Last block number (inclusive) |
| `-o, --output <PATH>` | Output file (default: stdout) |
| `--buffer-size <N>` | Number of blocks to prefetch ahead (default: 20) |
| `--bal` | Include RLP-encoded block access lists in the `bal` field |
| `--format <FORMAT>` | Output `blocks` (default), `transactions`, `calls`, or `traces`; transaction output is accepted by `bench send`, corpus output by `bench call` |
| `--methods <a,b>` | Methods to emit for `calls` and `traces` (see below) |
| `--top-gas <N>` | For `calls` and `traces`: keep only the N transactions with the highest gas limit per block (ties keep the earlier one); block-level records are unaffected |
| `--tracer <SPEC>` | Tracer for the `debug_trace*` methods, repeatable (default: `callTracer`); see [Tracers](#tracers) |
| `--tracer-config <JSON>` | JSON object merged as `tracerConfig` into every named-tracer record |
| `--trace-options <JSON>` | JSON object merged into the top level of every `debug_trace*` record's tracing options |
| `--block-param <latest\|parent>` | For `calls`: the block parameter of every record, the node's `latest` (default) or the parent of the source block, so already-executed transactions replay against the state their preconditions held in |

`--format transactions` preserves source block and transaction order. Transactions from different
senders may be submitted concurrently by `bench send`; transactions from the same sender use a
shared scheduling key and are submitted in order. The target node must be at the state immediately
before the replay range and configured to build blocks.

**Required RPC methods:** `debug_getRawBlock`; with `--bal`: `eth_getBlockAccessListByBlockNumber`

##### `--format calls`

Turns each transaction of the block range into a read-only call against `latest`, as a replay
corpus for [`bench call`](#bench-call). The call object carries the recovered sender as `from`, the
transaction's `to` (omitted for contract creations), its gas limit, value and input, and its access
list and EIP-7702 authorization list when those are non-empty. It carries no fee fields at all and
no blob fields, so the call runs at a zero gas price on any node and a blob transaction replays as
its plain call. Pinning the gas limit to the source transaction's keeps the result independent of
the node's configured gas cap, which a contract that reads `gasleft()` would otherwise observe.

Point the range at the blocks after the node's head: those transactions are exactly the calls a
mempool-simulating client would have made against the head state. Some of them revert because they
depend on an earlier block in the range; a revert is deterministic and counts as a response.

```bash
# A corpus of eth_call records from the 20 blocks after the node's head
txgen-ethereum extract --rpc http://archive:8545 --from 25490001 --to 25490020 \
  --format calls -o corpus.jsonl

# The same transactions traced with the prestate tracer in diff mode
txgen-ethereum extract --rpc http://archive:8545 --from 25490001 --to 25490020 \
  --format calls --methods debug_traceCall \
  --tracer prestateTracer --tracer-config '{"diffMode":true}' -o traces.jsonl
```

| Method | Emitted parameters |
|--------|--------------------|
| `eth_call` (default) | `[call, "latest"]` |
| `eth_estimateGas` | `[call without gas, "latest"]` |
| `eth_createAccessList` | `[call, "latest"]` |
| `debug_traceCall` | `[call, "latest", options]`, one record per `--tracer` |
| `trace_call` | `[call, ["trace"], "latest"]` and `[call, ["trace","stateDiff"], "latest"]` |

##### `--format traces`

Emits a corpus addressing the transactions and blocks themselves, so the records replay real chain
history. Point the range at blocks the node still has state for.

```bash
txgen-ethereum extract --rpc http://localhost:8545 --from 25489981 --to 25490000 \
  --format traces --methods debug_traceTransaction,trace_transaction -o corpus.jsonl

# The call tracer and the struct logger, from the same transactions
txgen-ethereum extract --rpc http://localhost:8545 --from 25489981 --to 25490000 \
  --format traces --tracer callTracer --tracer structlog \
  --trace-options '{"disableStorage":true,"disableStack":true}' -o corpus.jsonl
```

| Method | Emitted parameters |
|--------|--------------------|
| `debug_traceTransaction` (default) | `[hash, options]`, one record per `--tracer` |
| `trace_transaction` (default) | `[hash]` |
| `trace_replayTransaction` | `[hash, ["trace","stateDiff"]]` |
| `debug_traceBlockByNumber` | `[number, options]`, one record per `--tracer` |
| `trace_block` | `[number]` |
| `trace_replayBlockTransactions` | `[number, ["trace","stateDiff"]]`, label `trace+stateDiff` |

##### Tracers

`--tracer` decides what the `debug_trace*` methods above ask the node to run, and each spec emits its
own record. A spec is one of:

| Spec | Effect | Label |
|------|--------|-------|
| a tracer name | sent as the `tracer` field verbatim | the name |
| `structlog` | no `tracer` field, so the node runs its struct logger | `structlog` |
| `js:<path>` | the file's contents are sent as the `tracer` field | `js:<file stem>` |

Names are not checked against a list: to a node, an unknown tracer string is JavaScript source, so
`callTracer`, `prestateTracer`, `flatCallTracer`, `4byteTracer`, `noopTracer` and `muxTracer` are
all just names passed straight through. A `js:` file must exist and be non-empty.

`--tracer-config` is merged as `tracerConfig` into every named-tracer record and cannot be combined
with `structlog`, which takes its settings from `--trace-options` instead. `--trace-options` is
merged into the top level of the tracing options object of every `debug_trace*` record, which is
where `timeout`, `disableStorage`, `disableStack`, `enableMemory`, `enableReturnData` and `limit`
belong; it may not carry `tracer` or `tracerConfig`, which have their own flags. So the options
object of a record is `{tracer?, tracerConfig?, ...trace-options}`, and with no flags at all it is
exactly `{"tracer":"callTracer"}`.

Both corpus formats write one JSON object per line with `method`, `params` and an opaque `meta`
holding `{block, index, hash}` for transaction records and `{block}` for block records. Records that
are one variant of a method also carry a `meta.label` naming the variant - the tracer spec for the
`debug_trace*` methods, and the requested trace types (`trace`, `trace+stateDiff`) for `trace_call`
and `trace_replayTransaction` - which is what keeps them apart in a replay's per-method outputs. One
transaction contributes one record per method and variant, all sharing the same `meta`. Records are
written in block order and in the fixed method order of the tables above, so the same range and the
same source produce the same corpus regardless of how `--methods` was ordered.

#### `extract-big-blocks`

Generate reth-bb-compatible big-block payloads as NDJSON. Use `--bal` to fetch and merge constituent block access lists into `merged_block_access_list`.

```bash
txgen-ethereum extract-big-blocks \
  --rpc http://archive:8545 \
  --from 910020 \
  --count 25 \
  --target-gas 2G \
  -o big-blocks.ndjson
```

| Flag | Description |
|------|-------------|
| `--rpc <URL>` | RPC endpoint (archive node) |
| `--from <N>` | First source block number |
| `--count <N>` | Number of synthetic big blocks to emit |
| `--target-gas <GAS>` | Target gas per big block; accepts `K`, `M`, `G` suffixes |
| `-o, --output <PATH>` | Output file (default: stdout) |
| `--buffer-size <N>` | Reserved for future prefetching compatibility (default: 20) |
| `--bal` | Include a merged RLP-encoded block access list for each synthetic big block |

**Required RPC methods:** `debug_getRawBlock`; with `--bal`: `eth_getBlockAccessListByBlockNumber`

### `bench`

#### `bench send`

Send pre-generated transactions from NDJSON file or stdin.

After sending completes, queries the node for per-block statistics (transaction count, gas used) and includes them in the report.

```bash
# From file
bench send --input transactions.ndjson --rpc-url http://localhost:8545 --tps 500

# From stdin (pipe from txgen)
txgen-ethereum generate -s workload.yaml -n 1000 | bench send --rpc-url http://localhost:8545

# Target 50,000 TPS and keep at most 50,000 transactions awaiting inclusion
txgen-tempo generate -s workload.yaml --duration 90s | bench send --tps 50000

# Disable the pending cap while retaining the TPS ceiling
txgen-tempo generate -s workload.yaml --duration 90s | bench send --tps 50000 --max-pending 0

# With JSON report and metadata
bench send -i txs.ndjson --rpc-url http://localhost:8545 \
  --report json:report.json \
  -m build-sha=abcdef -m build-profile=perf

# Sender-scoped authentication with a separate unrestricted query RPC
bench send -i txs.ndjson \
  --rpc-url http://submit.example:8544 \
  --query-rpc-url http://query.example:8546 \
  --sender-header-name X-Authorization-Token \
  --sender-header-map /run/secrets/sender-auth.json

# Tempo relative-expiry transactions from a file or a pipe
txgen-tempo generate -s workload.yaml -n 1000 --defer-signing > txs.ndjson
bench send -i txs.ndjson --late-signing-spec workload.yaml
txgen-tempo generate -s workload.yaml -n 1000 --defer-signing | bench send --late-signing-spec workload.yaml
```

| Flag | Description |
|------|-------------|
| `-i, --input <PATH>` | Input NDJSON file (default: stdin) |
| `--late-signing-spec <PATH>` | Workload spec used to sign deferred Tempo transactions at submission time |
| `--rpc-url <URL>` | RPC endpoint URLs, comma-separated or repeated (default: `http://localhost:8545`) |
| `--query-rpc-url <URL>` | Optional RPC endpoint for block, block-receipt, txpool, and other aggregate queries |
| `--sender-header-name <NAME>` | HTTP header populated from the sender map for sender-scoped requests |
| `--sender-header-map <PATH>` | JSON file mapping logical transaction senders to secret header values |
| `--sender-header-reload-interval <DUR>` | How often to check the sender-header map for an atomic replacement (default: 1s) |
| `--tps <N>` | Target transactions per second (0 = unlimited) |
| `--max-concurrent <N>` | Maximum concurrent requests (default: 100) |
| `--retries <N>` | Retry failed transaction submissions N times (0 = never retry, omitted = retry forever) |
| `--timeout <DUR>` | Request timeout (default: 30s) |
| `--report <FORMAT>` | Report destinations, repeatable (see [Reporters](#reporters)) |
| `-m, --metadata <K=V>` | Metadata key=value pairs for the report, repeatable |
| `--metrics-url <URL or NODE:URL,...>` | Prometheus endpoint(s) to scrape during the run (see [Metrics Scraping](#metrics-scraping)) |
| `--scrape-interval-ms <N>` | Scrape interval in milliseconds (default: 500) |
| `--metrics-align <TIMESTAMP>` | Align exported metric timestamps to a benchmark-start Unix timestamp, in seconds or milliseconds |
| `--metrics-forward <URL>` | Forward scraped samples in real time via Prometheus remote write; requires `--metrics-url` |
| `--collect-latencies` | Collect and report aggregate latency stats plus individual request samples under `time_series.latencies` (default: disabled) |
| `--collect-receipt-metrics` | Collect non-system transaction gas and fee metrics with block-level receipt requests after sending |
| `--skip-setup` | Ignore setup-phase transactions in the input stream |
| `--drain-timeout <N>` | Wait for txpool drain after sending, in seconds (default: 0, set >0 to enable) |

**Required RPC methods:** `eth_sendRawTransaction`, `eth_blockNumber`, `eth_getBlockByNumber`; `eth_getBlockReceipts` for setup, sequence inclusion waits, and `--collect-receipt-metrics`; `txpool_status` (for `--drain-timeout`)

Setup and sequence inclusion waits share one lazy receipt tracker per chain. It polls the head every 100 ms while transactions are waiting, fetches `eth_getBlockReceipts` once per new block, and dispatches matching receipts to their waiting sequences. Transactions register before submission so fast inclusion is not missed. Failed or unavailable block receipt requests are retried centrally, and skipped block heights are backfilled. The tracker stops polling when there are no waiting transactions. This preserves inclusion ordering and the existing five-minute inclusion timeout.

##### Per-sender HTTP authentication

`bench send` can select an HTTP credential from the transaction's logical on-chain sender. The sender-header map is a JSON object whose keys are 20-byte addresses. Values are inserted into the header named by `--sender-header-name`:

```json
{
  "0x1111111111111111111111111111111111111111": "example-only-value-for-sender-1",
  "0x2222222222222222222222222222222222222222": "example-only-value-for-sender-2"
}
```

The values above are deliberately fake. `--sender-header-name` and `--sender-header-map` must be supplied together. Treat a real map as a secret: keep it out of process arguments and benchmark metadata, restrict its filesystem permissions, and replace it atomically rather than editing it in place. Bench warns when the map is readable by group or other users on supported platforms. It normalizes address keys and validates the complete replacement before activating it. A malformed replacement produces a sanitized warning and leaves the last valid map active.

Each authenticated transaction must have a `sender` field in its NDJSON record and a matching entry in the map. Selection never uses `submission_keys` or `inclusion_keys`. Standard and sponsored transactions use the transaction sender; Tempo keychain transactions use the authorized user, not the access key. Missing sender metadata or a missing mapping fails before the request is submitted. Legacy NDJSON without `sender` remains accepted when sender authentication is disabled.

Authentication headers are constructed per request while the RPC providers share one HTTP client and connection pool. Submission retries retain the selected header. Setup and sequence inclusion waits use shared block receipts from the aggregate query endpoint.

When `--query-rpc-url` is set, initial and final block-number reads, block statistics, setup and sequence inclusion observation, block-receipt collection, and `txpool_status` drain checks use that endpoint without sender credentials. Aggregate queries never select a sender mapping. Without a query URL, these operations retain the existing behavior of using the first `--rpc-url` provider.

Txgen consumes already-generated credential values; it does not encode, sign, or renew them. Generation-time nonce requests made by `txgen-ethereum generate --rpc` or `txgen-tempo generate --rpc` are not authenticated by these `bench send` options. Use an unrestricted RPC for nonce prefetching, or generate with suitable offline nonce configuration.

For a private Tempo Zone RPC, every authenticated transaction therefore needs an externally generated token mapped to its logical sender.

#### `bench send-blocks`

Submit RLP-encoded blocks or reth-bb big-block payloads via reth Engine API.

Raw-block inputs may include an optional `bal` field produced by `txgen extract --bal`; `bench send-blocks` forwards it to `reth_newPayload` alongside the block RLP. Big-block inputs use the current reth-bb `BigBlockData` format where each NDJSON line contains the constituent execution payloads in `env_switches`, plus `prior_block_hashes`, `block_number`, and optional `merged_block_access_list`.

```bash
bench send-blocks --engine http://localhost:8551 --jwt-secret /path/to/jwt.hex --input blocks.ndjson
bench send-blocks --engine http://localhost:8551 --jwt-secret /path/to/jwt.hex --input big-blocks.ndjson

# Exercise reorg paths by building synthetic side-fork blocks via testing_buildBlockV1.
bench send-blocks \
  --engine http://localhost:8551 \
  --jwt-secret /path/to/jwt.hex \
  --rpc http://localhost:8545 \
  --reorg 8 \
  --input blocks.ndjson
```

| Flag | Description |
|------|-------------|
| `--engine <URL>` | Engine API endpoint |
| `--jwt-secret <PATH>` | Path to JWT secret file |
| `-i, --input <PATH>` | Input NDJSON file (default: stdin) |
| `--wait-for-persistence <POLICY>` | Persistence wait policy: `always`, `never`, or `every:N` (default: `never`) |
| `--wait-time <DURATION>` | Minimum interval between block submissions. Accepts `100ms`, `2s`, or bare milliseconds like `400` |
| `--reorg [DEPTH]` | Build synthetic side-fork blocks and alternate forkchoice updates to exercise reorg paths. If `DEPTH` is omitted, defaults to `8`. Requires raw RLP block input |
| `--reorg-gap <BLOCKS>` | Add `BLOCKS` canonical blocks between resolved side chains (default: `0`; requires `--reorg`) |
| `--rpc <URL>` | Regular HTTP RPC endpoint for `testing_buildBlockV1` when `--reorg` is enabled (default: `http://localhost:8545`) |
| `--report <FORMAT>` | Report destinations, repeatable (see [Reporters](#reporters)) |
| `-m, --metadata <K=V>` | Metadata key=value pairs for the report, repeatable |
| `--metrics-url <URL or NODE:URL,...>` | Prometheus endpoint(s) to scrape during the run (see [Metrics Scraping](#metrics-scraping)) |
| `--scrape-interval-ms <N>` | Scrape interval in milliseconds (default: 500) |
| `--metrics-align <TIMESTAMP>` | Align exported metric timestamps to a benchmark-start Unix timestamp, in seconds or milliseconds |
| `--metrics-forward <URL>` | Forward scraped samples in real time via Prometheus remote write; requires `--metrics-url` |

For `send-blocks`, aggregate run rates use benchmark wall-clock duration. Per-block timestamps remain the original chain timestamps from the input. With `--reorg`, canonical block stats remain canonical-only, but the wall-clock duration includes synthetic fork block build/submission work.

**Required RPC methods:** `reth_newPayload`, `reth_forkchoiceUpdated` (reth custom Engine API). Big-block inputs require a `reth-bb` compatible node. `--reorg` additionally requires `testing_buildBlockV1` on the regular HTTP RPC endpoint. Because synthetic forks intentionally omit transactions, start Reth with `--http --http.api eth,testing --testing.skip-invalid-transactions`. `--rpc-url` and `--local-rpc-url` are accepted as backwards-compatible aliases for `--rpc`.

#### `bench call`

Replay a corpus of read-only RPC requests against a node and report latency, throughput and a
response digest per record. Built for comparing two builds of the same node: run it against each
one and the digests say whether any response changed byte for byte, while the latency distributions
say whether it got slower.

Two phases run against the same corpus and report separately. The open-loop cell paces requests at
`--rps` regardless of how fast the node answers and counts anything that would exceed
`--max-concurrent` as dropped rather than delaying it, so the offered rate stays the configured one
and queueing shows up as latency. The closed-loop passes walk the corpus in order with `--concurrency`
workers, which measures per-call service time. Set `--rps 0` or `--passes 0` to run only the other.

```bash
# Warm the node, then measure
bench call --input corpus.jsonl --rpc-url http://localhost:8545 \
  --phase warmup --rps 200 --duration 60s

bench call --input corpus.jsonl --rpc-url http://localhost:8545 \
  --responses responses.ndjson \
  --record-csv record_timings.csv \
  --requests-csv requests.csv \
  --report json:report.json

# Replay captured traffic that names blocks this node does not have
bench call --input captured.jsonl.gz --block-tag latest --strip-fees \
  --methods eth_call,eth_estimateGas --timeout 120s
```

| Flag | Description |
|------|-------------|
| `-i, --input <PATH>` | Corpus file, NDJSON or gzip-compressed NDJSON |
| `--rpc-url <URL>` | RPC endpoint (default: `http://localhost:8545`) |
| `--phase <PHASE>` | `measure` (default) or `warmup` |
| `--rps <N>` | Open-loop target rate (default: 100; 0 skips the phase) |
| `--duration <DUR>` | Open-loop wall clock (default: 120s) |
| `--requests <N>` | Fixed open-loop request count instead of `--duration` |
| `--max-concurrent <N>` | Open-loop in-flight cap (default: 256) |
| `--passes <N>` | Closed-loop passes over the corpus (default: 20; 0 skips the phase) |
| `--concurrency <N>` | Closed-loop workers (default: 16) |
| `--seed <N>` | Seed of the open-loop record sequence (default: 1) |
| `--block-tag <TAG>` | Replace the block parameter of every record that has a rewritable one, appending it when the optional block parameter is omitted |
| `--strip-fees` | Drop fee fields from the call object of call-shaped records |
| `--methods <a,b>` | Replay only these methods; other records are skipped and counted |
| `--timeout <DUR>` | Per-request timeout (default: 30s; raise it for tracing corpora) |
| `--responses <PATH>` | Write per-record response digests as NDJSON |
| `--record-csv <PATH>` | Write closed-loop per-record timings as CSV |
| `--requests-csv <PATH>` | Write open-loop per-request timings as CSV |
| `--max-fail-rate-pct <F>` | Exit non-zero above this HTTP and transport failure rate (default: 1.0) |
| `--report <FORMAT>` | Report destinations, repeatable (see [Reporters](#reporters)) |
| `-m, --metadata <K=V>` | Metadata key=value pairs for the report, repeatable |
| `--metrics-url <URL or NODE:URL,...>` | Prometheus endpoint(s) to scrape during the run (see [Metrics Scraping](#metrics-scraping)) |
| `--scrape-interval-ms <N>` | Scrape interval in milliseconds (default: 500) |
| `--metrics-align <TIMESTAMP>` | Align exported metric timestamps to a benchmark-start Unix timestamp |
| `--metrics-forward <URL>` | Forward scraped samples in real time via Prometheus remote write; requires `--metrics-url` |

**Required RPC methods:** `eth_chainId` and `eth_getBlockByNumber` for the identity check, plus
whichever of the corpus methods below the corpus uses.

##### Corpus format

One JSON object per line, `.jsonl` or `.jsonl.gz`. `params` is sent as is; `meta` is optional and
opaque, and its `block` and `index` are passed through to the outputs.

```json
{"method":"eth_call","params":[{"from":"0x..","to":"0x..","gas":"0x5208","input":"0x.."},"latest"],"meta":{"block":25490001,"index":3}}
```

`meta.label` is optional and names the variant a record replays, one tracer against another say. A
record is reported under `method:label` when it has one and under `method` when it does not, and
that key is what every per-method output is grouped by, so two tracers of the same method never pool
their latencies or their digests. A label must match `^[A-Za-z0-9._+:-]{1,48}$`; anything else is a
load error naming the line. `--methods` still selects by the bare method name.

A record's identity is its 1-based line number, which every output row keys on. A corpus may mix
methods; the open-loop rate then applies to the stream as a whole, so replaying one class of method
per run keeps the rate meaningful. `txgen extract --format calls` and `--format traces` produce this
format, and captured traffic is accepted verbatim as long as it parses and every method is on the
allowlist:

| Method | Call object | Block parameter |
|--------|-------------|-----------------|
| `eth_call`, `eth_estimateGas`, `eth_createAccessList` | `params[0]` | `params[1]` |
| `debug_traceCall` | `params[0]` | `params[1]` |
| `trace_call` | `params[0]` | `params[2]` |
| `debug_traceTransaction`, `trace_transaction`, `trace_replayTransaction` | none | none |
| `debug_traceBlockByNumber`, `trace_block`, `trace_replayBlockTransactions` | none | `params[0]`, never rewritten |

`--block-tag` replaces the block parameter of every record that has a rewritable one, which is what
makes captured traffic replayable against a node that does not have the original blocks.
`--strip-fees` removes `gasPrice`, `maxFeePerGas`, `maxPriorityFeePerGas` and `maxFeePerBlobGas`
from the top-level call object only. Both rewrites are off by default and both are recorded in the
report.

##### Outputs

`responses.ndjson` carries one row per record: `{"record_index":1,"method":"eth_call","kind":"ok",
"digest":"0x..","len":1152}`. The digest is `keccak256` of the raw `result` bytes exactly as
received, with no re-serialisation or normalisation, so whitespace and key order are part of the
comparison; a JSON-RPC error digests its code and message instead and is tagged `rpc_error`.
Responses are hashed as they stream in, so a trace response of tens of megabytes costs a fixed
amount of memory. `len` is the number of bytes digested, which is how a response-size change shows
up even when a parity break is intentional.

The reference digest for a record is the one from the first closed-loop pass. If a later pass or
the open-loop cell disagrees, the record is counted under `nondeterministic` with its index: that is
the node or the corpus being nondeterministic inside a single run, and it makes any cross-run
comparison of that record inconclusive.

`record_timings.csv` is `record_index,method,pass,latency_us,status` and `requests.csv` is
`offset_ms,record_index,method,latency_us,status`, where `status` is one of `ok`, `rpc_error`,
`http_error`, `transport_error` or `timeout`. The JSON report adds a `call` section with the corpus
counts, the node identity, the replay configuration, the open-loop latency block, `closed_loop_rps`,
per-status counts and the nondeterministic list, all repeated per method under `call.methods`. The
`method` of every one of those - the CSV column, the `responses.ndjson` field, and the keys of
`call.methods`, `call.corpus.records_per_method` and `call.corpus.skipped_per_method` - is the
record's reporting key, so a labelled corpus reports `debug_traceTransaction:callTracer` and
`debug_traceTransaction:structlog` as two separate entries.

Request and response bodies are never logged or written to any output at any log level. Failures are
reported as counts and record indexes, which is what makes a corpus of third-party traffic usable in
a public CI log.

#### `bench view`

Print an existing JSON report to the console.

```bash
bench view
bench view report.json
```

| Argument | Description |
|----------|-------------|
| `<INPUT>` | JSON report file (default: `report.json`) |

**Required RPC methods:** None (offline)

### Pending transaction limit

`bench send --max-pending 50000` reserves a slot before each workload submission
and refills it when the shared block scanner observes inclusion (including a revert),
the RPC definitively rejects the transaction, or a Tempo transaction's signed expiry
has passed on chain. It counts this sender's outstanding
transactions, including RPC requests in flight, not unrelated transactions in the node's
pool. When omitted, `--max-pending` defaults to the value of `--tps`. Pass
`--max-pending 0` to disable the cap, or a positive value to override it. If `--tps`
is omitted or zero, the pending cap is disabled unless explicitly set.
`--tps` remains the submission ceiling and `--max-concurrent` independently limits
RPC requests. Logs and report metadata record the effective pending limit (zero
when disabled).

One head poller and one `eth_getBlockByNumber` request (transaction hashes only) per
observed block serve all pending transactions. Full block receipts are fetched only
when a block includes a transaction with a setup or explicit receipt dependency;
waiting workers never poll individual receipts.
Registration happens before submission, so fast inclusion is not missed. A lost RPC
response retains its slot until inclusion or signed expiry. Expiry is checked against
observed block timestamps after scanning inclusions, not the local wall clock. Unknown
evictions or a transaction missing for five minutes fail the run rather than forgetting
outstanding transactions. Flush waits for final inclusion/expiry observations; this
measures inclusion, not finality. Hash-only tracking does not report transaction revert status.

### Live Progress

During `bench send`, the console reporter displays a live progress line:

```
  Sent: 5000 | OK: 4800 | Fail: 50 | Inflight: 150/200 | Rate: 980/1000 tps
```

| Field | Description |
|-------|-------------|
| `Sent` | Total transactions submitted to the sender |
| `OK` | Successful RPC responses |
| `Fail` | Failed RPC responses |
| `Inflight` | Transactions sent but not yet resolved (current/`--max-concurrent`) |
| `Rate` | Actual send rate (current/`--tps` target) |

**Reading backpressure:**

- **Concurrency-bound**: `Inflight` is at or near `--max-concurrent`. The RPC endpoint can't keep up — responses are slow relative to the send rate. Increase `--max-concurrent` or reduce `--tps`.
- **Rate-limited**: `Rate` matches the `--tps` target and `Inflight` is well below `--max-concurrent`. The rate limiter is the bottleneck (working as intended).
- **Source-bound**: `Rate` is below `--tps` and `Inflight` is low. The transaction source (file I/O or stdin pipe) is the bottleneck.

### Reporters

Report destinations are specified with `--report` and can be repeated:

| Format | Description |
|--------|-------------|
| `console` | Print summary to stderr (default if no reporters specified) |
| `json:<path>` | Write JSON report to file |
| `clickhouse:<url>` | Push benchmark data to ClickHouse |
| `prometheus:<url>` | Push samples via Prometheus remote write (`/api/v1/write`) |
| `victoriametrics:<url>` | Alias for Prometheus remote write, intended for VictoriaMetrics |

### Metrics Scraping

All bench commands support built-in Prometheus metrics scraping via `--metrics-url`. When enabled, one or more background scrapers periodically fetch node `/metrics` endpoints and include all samples in the JSON report.

```bash
# Scrape node metrics alongside the benchmark
bench send -i txs.ndjson --metrics-url http://127.0.0.1:9001/metrics --report json:report.json

# Custom scrape interval (default: 500ms)
bench send -i txs.ndjson --metrics-url http://127.0.0.1:9001/metrics --scrape-interval-ms 200

# Scrape multiple nodes and tag each scraped sample with node=<label>
bench send -i txs.ndjson --metrics-url a:http://node-a:9001/metrics,b:http://node-b:9001/metrics

# Attach canonical validator labels to a scrape endpoint
bench send -i txs.ndjson \
  --metrics-url 'validator=v0;validator_pubkey=0xabc;region=us-east-1@http://node-a:9001/metrics'
```

For a single endpoint, pass the URL directly. Legacy multiple-endpoint entries use
`node_label:URL` and add `node=<node_label>`. Rich entries use
`key=value;key=value@URL` and add each supplied label to the scraped samples.

Internal txgen metrics are snapshotted on the same interval and included alongside node metrics. In `send` mode: `txgen_transactions_sent_total`, `txgen_transactions_success_total`, etc. In `send-blocks` mode: `txgen_blocks_sent_total`, `txgen_blocks_success_total`, `txgen_blocks_failed_total`.

Metadata key=value pairs (`-m key=value`) are applied as labels to all samples, useful for tagging runs with build SHAs, profiles, or experiment IDs.

Use `--metrics-align <TIMESTAMP>` to shift exported sample timestamps while preserving each sample's offset within the run. The timestamp is treated as benchmark start time and may be Unix seconds or milliseconds; after conversion to milliseconds, exported sample `unix_ms` values become `TIMESTAMP + offset_ms`.

`bench send` and `bench send-blocks` can also forward the scrape stream to a
Prometheus-compatible remote write endpoint while the run is still active:

```bash
bench send -i txs.ndjson \
  --metrics-url http://127.0.0.1:9001/metrics \
  --report json:report.json \
  --metrics-forward http://victoriametrics:8428 \
  -m scenario=tip20-10k -m run_id=$(uuidgen)
```

This uses the same Prometheus remote write payload and `PROMETHEUS_*` environment variables as the Prometheus reporter, but uploads each scrape batch as it is archived. The JSON reporter still writes the compressed `.samples.ndjson.gz` sidecar at finalization.

### ClickHouse Reporting

The ClickHouse reporter stores common run metadata in `txgen_runs`. Bench runs additionally use `txgen_blocks` and `txgen_metric_samples`; scenario runs use `txgen_scenario_runs` and `txgen_scenario_steps` and do not write `txgen_blocks`. Both `send` and scenario runs write one exact outer-transaction gas row per confirmed non-system receipt to `txgen_receipt_gas`; `send-blocks` writes none. Block data is factual chain data, while metric samples are point-in-time scrape snapshots with no block attribution. Bench reporting requires four metadata keys:

```bash
bench send -i txs.ndjson \
  --metrics-url http://127.0.0.1:9001/metrics \
  --report clickhouse:https://host:8443 \
  -m scenario=tip20-10k \
  -m platform=tempo \
  -m git-sha=abc123 \
  -m git-ref=main
```

| Required Metadata | Description |
|-------------------|-------------|
| `scenario` | Benchmark scenario name (e.g. `tip20-10k`) |
| `platform` | Target platform: `ethereum` or `tempo` |
| `git-sha` | Node commit SHA being benchmarked |
| `git-ref` | Node git branch/ref |

Authentication and insert batching are configured via environment variables: `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`, `CLICKHOUSE_DATABASE`, and `CLICKHOUSE_SAMPLE_BATCH_SIZE` (default: `50000`). See [`scripts/clickhouse/README.md`](scripts/clickhouse/README.md) for schema setup and example queries.

Scenario report destinations use the same `--report` flag and can be repeated. A bare path remains an alias for a JSON file:

```bash
CLICKHOUSE_USER=default \
CLICKHOUSE_PASSWORD=secret \
CLICKHOUSE_DATABASE=benchmarks \
txgen-tempo scenario run \
  --scenario scenario.yaml \
  --count 100 \
  --report scenario-report.json \
  --report clickhouse:https://host:8443 \
  -m git-sha=abc123 \
  -m git-ref=main \
  -m github-run-url=https://github.com/example/actions/runs/123
```

The scenario name, platform, and `mode=scenario` are derived from the finalized report; those metadata keys are reserved and conflicting user values are rejected. `git-sha` and `git-ref` are required metadata for the common `txgen_runs` row. Every destination receives the same client-generated `run_id`. JSON destinations are finalized before ClickHouse publication, so an upload error is returned without deleting a report file that was already written.

Deploy migrations through `009_txgen_scenario_causal_metrics.sql` before publishing scenario report schema version 2. Detail rows are synchronously acknowledged before `txgen_runs` is inserted as the visibility marker. Queries for complete benchmark or scenario reports must begin at `txgen_runs` and join detail tables by `run_id`; an interrupted publication can leave child rows without a visible common run row.

The bench JSON report includes:
- `samples` — point-in-time metric snapshots (internal + node), stored as a time series
- `blocks` — factual chain data for each block in the run (tx count, gas used, etc.)
- `receipt_metrics` — confirmed-transaction `gas_used`, `effective_gas_price`, and `fee_paid` distributions grouped by workload input
- `total_fees_paid` — exact total paid by confirmed non-system transactions in the benchmark block range, encoded as a decimal base-unit string

Receipts without `effectiveGasPrice` or legacy `gasPrice` still contribute gas usage to `receipt_metrics`, but are excluded from `total_fees_paid`.

### Prometheus Reporting

The Prometheus reporter forwards every sample in the unified time series (internal `txgen_*` counters plus scraped node Prometheus metrics) to a Prometheus-compatible endpoint via the `/api/v1/write` endpoint. The same endpoint works with VictoriaMetrics, Cortex, Thanos, etc. Samples are sent in Prometheus Remote Write format with their original `unix_ms` timestamps, so backfilling at the end of the run does not lose fidelity.

```bash
bench send -i txs.ndjson \
  --metrics-url http://127.0.0.1:9001/metrics \
  --report prometheus:http://prometheus:8428 \
  -m scenario=tip20-10k \
  -m platform=tempo \
  -m git-sha=abc123 \
  -m git-ref=main
```

Each `-m key=value` pair from `--metadata` is encoded as a label on every sample (perfect for `run_id`, `scenario`, `git_sha`, `platform`, …). Label keys are sanitized to match the Prometheus identifier rules (`-`, `.`, etc. become `_`).

Connection knobs are read from environment variables to keep secrets off the command line:

| Env var | Purpose |
|---------|---------|
| `PROMETHEUS_BEARER_TOKEN` | Sent as `Authorization: Bearer …` (e.g. for VM Cloud / vmauth) |
| `PROMETHEUS_USER` / `PROMETHEUS_PASSWORD` | HTTP basic auth credentials |
| `PROMETHEUS_TENANT_ID` | Cluster VM `accountID` query parameter |
| `PROMETHEUS_BATCH_SIZE` | Samples per HTTP request (default: `50000`) |
| `PROMETHEUS_ENCODE_WORKERS` | Parallel workers used to build and compress final report requests (default: up to `8`) |
| `PROMETHEUS_TIMEOUT_SECS` | Per-request HTTP timeout in seconds (default: `60`) |
| `PROMETHEUS_QUEUE_SIZE` | Real-time forwarder queue size in scrape batches (default: `16`) |

Example with auth:

```bash
PROMETHEUS_BEARER_TOKEN=$(cat ~/.prometheus-token) \
bench send -i txs.ndjson \
  --metrics-url http://127.0.0.1:9001/metrics \
  --report prometheus:https://prometheus.example.com \
  -m scenario=tip20-10k -m run_id=$(uuidgen)
```

## Scenario Specification

Scenarios describe complete journeys across asynchronous RPC boundaries. Each named chain points to an ordinary txgen workload spec; `submit` selects a template from that workload and applies the same deep-merge behavior used by workload sequences. Existing workload specs, templates, `generate` commands, and NDJSON formats remain valid.

Scenario files use `version: 1`. Environment references such as `${ORIGIN_RPC_URL}` are expanded before parsing. Relative `workload` and request-auth map paths are resolved from the file that declares the chain; because included fragment libraries cannot declare chains, that is the root scenario file. Paths inside a workload, including ABI artifacts, remain relative to the workload file.

Each binary supplies one network adapter for the whole run: every chain in a `txgen-tempo` scenario must use `network: tempo`, and every chain in a `txgen-ethereum` scenario must use `network: ethereum`. The endpoints may still represent independent chains with different chain IDs and workload files. Named chains must use distinct normalized submission RPC URLs so they cannot maintain conflicting nonce state for one endpoint.

Before starting measured instances, the runner checks every chain ID and pending nonce source, then materializes every workload setup without submission. Only after those checks succeed does it materialize, submit, and confirm each setup transaction just in time, retaining `setup.<id>.*` bindings for scenario templates. A setup failure aborts initialization. Initialization RPC operations and each setup transaction have a five-minute safety timeout. Point a scenario at a workload without setup steps when the target chain is already prepared.

### Schema v1

This generic example sends a message on one chain, observes its delivery on another chain, submits an acknowledgement, and observes the acknowledgement back on the first chain. The ABI names, event names, addresses, and templates are supplied by the referenced workloads; the engine itself has no application-specific assumptions.

```yaml
version: 1

chains:
  origin:
    network: tempo
    rpc_url: ${ORIGIN_RPC_URL}
    chain_id: auto
    workload: ./origin-workload.yaml

  destination:
    network: tempo
    rpc_url: ${DESTINATION_RPC_URL}
    chain_id: auto
    workload: ./destination-workload.yaml

scenario:
  name: message-roundtrip
  timeout: 45s

  bindings:
    user:
      account:
        pool: users
        select: lease

  steps:
    - checkpoint:
        chain: destination
      save: destination_before_message

    - submit:
        chain: origin
        template: publish_message
        with:
          from: { var: user.ref }
      save: publish

    - wait_receipt:
        chain: origin
        transaction_hash: { var: publish.tx_hash }
        confirmations: 1
      save: publish_receipt

    - wait_log:
        chain: origin
        transaction_hash: { var: publish.tx_hash }
        abi: Relay
        event: MessagePublished
      save: message_published

    - wait_log:
        chain: destination
        from_block: { var: destination_before_message.block_number }
        address: ${DESTINATION_RELAY_ADDRESS}
        abi: Relay
        event: MessageDelivered
        where:
          messageId: { var: message_published.args.messageId }
        poll_interval: 250ms
        confirmations: 2
        max_block_range: 1000
      save: message_delivered
      timeout: 2m

    - checkpoint:
        chain: origin
      save: origin_before_acknowledgement

    - submit:
        chain: destination
        template: acknowledge_message
        with:
          from: { var: user.ref }
          call:
            args:
              - { var: message_delivered.args.messageId }
        await: receipt
      save: acknowledgement

    - wait_log:
        chain: origin
        from_block: { var: origin_before_acknowledgement.block_number }
        address: ${ORIGIN_RELAY_ADDRESS}
        abi: Relay
        event: AcknowledgementRecorded
        where:
          acknowledgementId:
            keccak256_packed:
              types: [bytes32, bytes32]
              values:
                - { var: message_delivered.args.messageId }
                - { var: acknowledgement.tx_hash }
      save: acknowledgement_recorded
```

Omit `scenario.execution` to retain the ordered, strictly sequential behavior of existing specifications. Set `execution: dag` to make dependencies explicit and start every ready step immediately:

```yaml
scenario:
  name: concurrent-observation
  execution: dag
  steps:
    - id: before_delivery
      checkpoint:
        chain: destination
      save: destination_cursor

    - id: publish
      depends_on: [before_delivery]
      submit:
        chain: origin
        template: publish_message
      save: publication

    - id: observe_receipt
      depends_on: [publish]
      wait_receipt:
        chain: origin
        transaction_hash: { var: publication.tx_hash }
      save: publication_receipt

    - id: observe_delivery
      depends_on: [before_delivery, publish]
      wait_log:
        chain: destination
        from_block: { var: destination_cursor.block_number }
        abi: Relay
        event: MessageDelivered
      save: delivery

    - id: after_both
      depends_on: [observe_receipt, observe_delivery]
      checkpoint:
        chain: origin
```

Every DAG step has a stable, unique `id`; `depends_on` may be omitted for a root step. A runtime output may be referenced only by a dependency descendant: `observe_delivery` depends on `before_delivery` for its cursor and on `publish` for the causal edge. Validation rejects missing dependencies, cycles, and references to outputs that are not dependency ancestors. A journey completes after every required terminal branch completes. Independent ready steps run concurrently, while `after_both` cannot start until both observation branches finish.

`chain_id: auto` queries the endpoint and uses the returned chain ID for signing. An explicit integer may be used instead and is validated against the endpoint. When one account binding is used to submit on multiple chains, its named pool must derive the same ordered addresses in each consuming workload.

`rpc_url` is the submission endpoint. `query_rpc_url` optionally selects a separate unauthenticated endpoint for chain ID and nonce initialization, checkpoints, confirmation heights, and log queries; it defaults to `rpc_url`. A chain can authenticate sender-scoped submission traffic with the same sender map used by `bench send`:

```yaml
chains:
  zone:
    network: tempo
    rpc_url: ${ZONE_SUBMISSION_RPC_URL}
    query_rpc_url: ${ZONE_QUERY_RPC_URL}
    observation:
      mode: auto
      websocket_url: ${ZONE_WEBSOCKET_URL}
      poll_interval: 50ms
    request_auth:
      sender_header:
        name: X-Authorization-Token
        map: ./zone-sender-auth.json
        reload_interval: 1s
    chain_id: auto
    workload: ./zone-workload.yaml
```

The selected header is attached only to `eth_sendRawTransaction` and sender-scoped transaction/receipt lookups on the submission endpoint. It is recomputed for each request so atomically replaced maps can take effect. `submit await: receipt` already carries its materialized sender; standalone `wait_receipt` and transaction-hash-only `wait_log` steps must supply `sender`, commonly from the saved submit result:

```yaml
- wait_receipt:
    chain: zone
    transaction_hash: { var: publish.tx_hash }
    sender: { var: publish.sender }
```

`observation.mode` is `auto`, `subscription`, or `poll`. `auto` prefers WebSocket new-head wakeups when `websocket_url` is available, performs canonical backfill and verification around subscription setup, and falls back to polling. `subscription` requires the WebSocket transport. `poll` always uses RPC polling. `poll_interval` is the chain fallback interval for scenario waits and defaults to `50ms`; an individual `wait_receipt` or `wait_log` may override the interval. Subscription wakeups are paired with canonical backfill so receipts and logs produced before or during setup are not lost.

### Reusable fragments and composition

A scenario document may add top-level `include` and `fragments` sections. Both are optional, so existing version 1 documents with one inline `scenario.steps` list parse and run as before. The root document may contain `version`, `include`, `fragments`, `chains`, and `scenario`. An included document is a fragment library and may contain only `version`, `include`, and `fragments`; an included file cannot replace or contribute `chains` or the root `scenario`.

Includes are traversed depth-first in their listed order. Each include path is relative to the file that declares it, not the process working directory or the root scenario. Canonical paths are used to detect a file reached again on the active include stack; that is an include cycle. Reaching the same file again after its earlier traversal completed is not silently deduplicated: it is traversed again, and any repeated fragment contribution is reported as a duplicate declaration. Fragment names must be unique across the complete include graph and the root document, and there is no implicit precedence or override mechanism. Include cycles, missing files, and a non-version-1 `version` in any document are errors.

Each fragment defines typed parameters, optional typed outputs, and an ordered list containing normal steps or nested fragment uses:

```yaml
fragments:
  submit-and-confirm:
    parameters:
      chain: string
      sender: account_ref
      recipient: address
      amount: u256
    outputs:
      submission: submit
      receipt: receipt
    steps:
      - submit:
          chain: { param: chain }
          template: transfer
          with:
            from: { param: sender }
            call:
              args:
                - { param: recipient }
                - { param: amount }
        save: submission

      - wait_receipt:
          chain: { param: chain }
          transaction_hash: { var: submission.tx_hash }
        save: receipt
```

Supported parameter types are:

| Type | Accepted value |
|------|----------------|
| `string` | A string literal or string-valued runtime expression |
| `account_ref` | An account reference such as `{ var: user.ref }` |
| `address` | An address literal or address-valued runtime expression |
| `u256` | An unsigned integer literal or compatible runtime expression |
| `bytes` | A variable-length byte string or compatible runtime expression |
| `bytes32` | A 32-byte value or compatible runtime expression |
| `bool` | A Boolean literal or Boolean-valued runtime expression |
| `value` | Any supported YAML value or txgen runtime expression |

Parameter substitution uses the exact single-key form `{ param: name }`; it replaces that whole YAML node. Parameters are not interpolated into strings. Arguments may be literals, environment-expanded values, runtime references, or other supported txgen value expressions. Every fragment use must provide exactly the declared keys in `with`: missing and unknown parameters are rejected, and statically knowable values must match their declared types. A parameter does not make a normally static schema field dynamic; values substituted into fields such as `chain`, `template`, `abi`, or `event` must resolve during expansion rather than at runtime.

Use a fragment anywhere an inline step is allowed:

```yaml
- use: submit-and-confirm
  as: first_transfer
  with:
    chain: primary
    sender: { var: user.ref }
    recipient: { var: user.address }
    amount: 1
```

`as` is required. It must be one valid, non-dotted name segment and must be unique within its containing scenario or fragment. The same fragment may be used repeatedly under different aliases. Its local saves are placed below the alias, so `submission` and `receipt` above become `first_transfer.submission` and `first_transfer.receipt`. Fragment-authored `{ var: submission.tx_hash }` references resolve to the local save before caller-supplied parameter values are injected; a runtime expression passed through `with` therefore keeps the caller's scope. A nested use adds another segment: an inner alias `confirm` under an outer alias `batch` produces names such as `batch.confirm.receipt`. Report provenance uses the local save as the local step name when present and a deterministic action/index-derived name for an unsaved step.

In a DAG scenario, a fragment use may also declare `depends_on` beside `use` and `as`. Expansion adds those caller dependencies to every root of the fragment's internal DAG, so the complete fragment waits for the declared prerequisites while independent roots inside it may still start together:

```yaml
- use: submit-and-confirm
  as: transfer
  depends_on: [fund_account]
  with:
    chain: primary
    sender: { var: user.ref }
    recipient: { var: user.address }
    amount: 1
```

An `outputs` entry names a save declared by the fragment and its required result kind. The supported result kinds are `checkpoint`, `invoke`, `submit`, `receipt`, and `log`; expansion rejects missing output saves and result-kind mismatches. Local saves omitted from `outputs` remain private: callers may reference only declared outputs below the instance alias. A parent fragment must likewise re-export a nested output before its own caller can access it. Fragment uses may nest to any acyclic depth, while direct and indirect fragment recursion is rejected with the use chain.

Expansion is deterministic and occurs before the existing chain, binding, save, forward-reference, template, ABI, event-filter, and type validation. Duplicate aliases, expanded saves, and invalid names are therefore checked together with surrounding inline steps. Errors identify the declaring source file and, when applicable, the fragment, instance alias, local step, and expanded step index.

Composition stops on missing include files or fragment names, include cycles, fragment recursion, missing or unknown parameters, duplicate fragment names or aliases, conflicting expanded saves, invalid output declarations, and unresolved parameter or variable references. Fragment dependency and output contracts are checked even when a fragment is not instantiated by the root scenario. These errors are reported before execution begins.

#### Complete multi-file example

This layout keeps the entry point and workload together while the fragment library uses a nested relative include:

```text
scenario.yaml
primary-workload.yaml
fragments/
  common.yaml
  transfers.yaml
```

`fragments/common.yaml` declares one fragment and includes another file relative to itself:

```yaml
version: 1
include:
  - transfers.yaml

fragments:
  capture-head:
    parameters:
      chain: string
    outputs:
      cursor: checkpoint
    steps:
      - checkpoint:
          chain: { param: chain }
        save: cursor
```

`fragments/transfers.yaml` contains the reusable transaction pair:

```yaml
version: 1

fragments:
  submit-and-confirm:
    parameters:
      chain: string
      sender: account_ref
      recipient: address
      amount: u256
    outputs:
      submission: submit
      receipt: receipt
    steps:
      - submit:
          chain: { param: chain }
          template: transfer
          with:
            from: { param: sender }
            call:
              args:
                - { param: recipient }
                - { param: amount }
        save: submission

      - wait_receipt:
          chain: { param: chain }
          transaction_hash: { var: submission.tx_hash }
        save: receipt
```

`scenario.yaml` instantiates the same fragment twice, combines those uses with another fragment, and then references an exported result from a later inline step:

```yaml
version: 1

include:
  - fragments/common.yaml

chains:
  primary:
    network: tempo
    rpc_url: "${RPC_URL}"
    chain_id: auto
    workload: ./primary-workload.yaml

scenario:
  name: composed-transfers
  timeout: 5m
  bindings:
    user:
      account:
        pool: users
        select: lease
  steps:
    - use: capture-head
      as: before_transfers
      with:
        chain: primary

    - use: submit-and-confirm
      as: first_transfer
      with:
        chain: primary
        sender: { var: user.ref }
        recipient: { var: user.address }
        amount: 1

    - use: submit-and-confirm
      as: second_transfer
      with:
        chain: primary
        sender: { var: user.ref }
        recipient: { var: user.address }
        amount: 2

    - wait_receipt:
        chain: primary
        transaction_hash: { var: first_transfer.receipt.transaction_hash }
      save: first_transfer_rechecked
```

The expanded order is the `capture-head` step, both steps from `first_transfer`, both steps from `second_transfer`, and the final inline receipt wait. The corresponding fragment saves are `before_transfers.cursor`, `first_transfer.submission`, `first_transfer.receipt`, `second_transfer.submission`, and `second_transfer.receipt`.

### Steps

Every step selects one named chain. `id`, `depends_on`, `save`, and `timeout` are sibling keys of the step action. `id` and `depends_on` are used by DAG scenarios; legacy sequential scenarios continue to derive identity and ordering from list position.

#### `checkpoint`

Captures the chain's current canonical block cursor. Use it immediately before an action that will cause an event on another chain, then pass its `block_number` to `wait_log`. This closes the gap between transaction submission and registration of the event wait.

```yaml
- checkpoint:
    chain: destination
  save: before_delivery
```

#### `invoke`

Runs a query-only action supplied by the selected network adapter. `with` values may use runtime expressions, and the adapter's structured result can be saved and passed to later steps. Unsupported action names are rejected before any journey starts.

The Tempo adapter provides `prepare_encrypted_deposit`, which reads the current ZonePortal encryption key and creates a fresh secp256k1/AES-GCM payload for each invocation. `sender` is required and must be the address that will call `ZonePortal.deposit`; it is bound into the encryption key derivation. Cryptographic material always comes from the operating system and is intentionally not controlled by the scenario seed. `portalAddress` is optional for Zone IDs known to viem; supply it for other deployments. `memo` is an optional `bytes32` and defaults to zero.

```yaml
- invoke:
    chain: l1
    action: prepare_encrypted_deposit
    with:
      sender: { var: user.address }
      recipient: { var: user.address }
      zoneId: 9
      portalAddress: ${ZONE_PORTAL_ADDRESS}
  save: prepared

- submit:
    chain: l1
    template: encrypted_deposit
    with:
      from: { var: user.ref }
      call:
        args:
          - ${TOKEN_ADDRESS}
          - 1000000
          - { var: prepared.keyIndex }
          - { var: prepared.encrypted }
```

The saved result contains viem's `chainId`, `encrypted`, `keyIndex`, `portalAddress`, and `zoneId` fields. `encrypted` contains `ciphertext`, `ephemeralPubkeyX`, `ephemeralPubkeyYParity`, `nonce`, and `tag` and can be used directly as the named tuple argument of `depositEncrypted`.

#### `submit`

Loads a named template from the selected chain's workload, deep-merges `with`, resolves runtime expressions, signs with that chain's adapter, and submits it through the in-process sender. The step completes after RPC acceptance and exposes the transaction hash. Set `await: receipt` to keep the step open until a successful receipt is observed; a reverted receipt fails the step.

```yaml
- submit:
    chain: origin
    template: publish_message
    with:
      from: { var: user.ref }
    await: receipt
  save: publish
```

#### `wait_receipt`

Observes a supplied transaction hash using the chain's configured observation mode. By default a reverted receipt fails the step; set `allow_revert: true` only when a revert is an expected result. The default fallback poll interval is `50ms`, and the default is zero additional confirmations. `confirmations: 0` verifies the canonical receipt without waiting for another block.

```yaml
- wait_receipt:
    chain: origin
    transaction_hash: { var: publish.tx_hash }
    sender: { var: publish.sender }
    poll_interval: 50ms
    confirmations: 2
  save: publish_receipt
```

#### `wait_log`

Loads an ABI artifact from the selected chain's workload and resolves `event` by name or exact signature. It decodes indexed and unindexed arguments, then returns the first canonical match in block-number/log-index order.

A log wait must provide `from_block` or `transaction_hash`. Optional `address`, `transaction_hash`, and `where` fields narrow the match. Each `where` entry compares one decoded argument to a resolved, typed runtime value. The default fallback poll interval is `50ms`, with zero additional confirmations and at most 1,000 blocks per `eth_getLogs` request. The waiter backfills from the starting cursor, uses the chain's configured subscription or polling mode, honors confirmations, and discards removed or reorged candidates after canonical verification.

```yaml
- wait_log:
    chain: destination
    from_block: { var: before_delivery.block_number }
    address: ${DESTINATION_RELAY_ADDRESS}
    abi: Relay
    event: "MessageDelivered(bytes32,address)"
    where:
      messageId: { var: message_published.args.messageId }
    max_block_range: 1000
  save: delivered
```

For multiple required events emitted by one transaction, use receipt-scoped `events` instead of separate waits:

```yaml
- wait_log:
    chain: origin
    transaction_hash: { var: withdrawal.tx_hash }
    sender: { var: withdrawal.sender }
    confirmations: 0
    events:
      withdrawal:
        address: ${PORTAL_ADDRESS}
        abi: Portal
        event: WithdrawalProcessed
        where:
          withdrawalId: { var: withdrawal_requested.args.withdrawalId }
      callback:
        address: ${CALLBACK_ADDRESS}
        abi: Callback
        event: WithdrawalCallback
        where:
          withdrawalId: { var: withdrawal_requested.args.withdrawalId }
  save: processed
```

The grouped form requires `transaction_hash`, rejects `from_block`, and requires every named event. `events` is mutually exclusive with the legacy top-level `abi`, `event`, `address`, and `where` fields. The saved result contains common receipt fields plus `events.withdrawal` and `events.callback`; each child retains its exact decoded arguments and log index for downstream expressions. Events from the same receipt share one inclusion and observation milestone, rather than appearing as independent near-zero-duration protocol steps.

### Saved values

`save: <name>` adds an immutable typed result to the current scenario instance. Saved values are not shared between concurrent instances, and a name cannot be reused. Sequential scenarios reject forward references; DAG scenarios require the producing step to be a dependency ancestor. Fragment-local save names remain simple names in their declarations; expansion qualifies them with the complete instance alias path so callers can use expressions such as `{ var: first_transfer.receipt.block_number }`.

| Step | Saved fields |
|------|--------------|
| `checkpoint` | `chain`, `block_number`, optional `block_hash`, `captured_at` |
| `invoke` | adapter-defined result plus `chain` and `action` |
| `submit` | `chain`, `template`/`id`, `sender`, `tx_hash`, `submitted_at`, `acceptance_latency`, optional `receipt` |
| `submit.receipt` | `chain`, `transaction_hash`, `block_hash`, `block_number`, `transaction_index`, `status`, `gas_used`, `block_timestamp_ms`, `first_observed_at`, `confirmed_at`, `confirmation_depth` |
| `wait_receipt` | `chain`, `transaction_hash`, `block_hash`, `block_number`, `transaction_index`, `status`, `gas_used`, `block_timestamp_ms`, `first_observed_at`, `confirmed_at`, `confirmation_depth` |
| `wait_log` | `chain`, `address`, `transaction_hash`, `block_hash`, `block_number`, `transaction_index`, `log_index`, `event`, typed `args`, `first_observed_at`, `confirmed_at`, `confirmation_depth`, canonical `block_timestamp_ms` |
| grouped `wait_log` | Common receipt timing and confirmation fields plus `events.<id>` children containing each event's address, log index, event name, and typed `args` |

The compatibility aliases `tx_hash`, `contract_address`, `event_name`, and `observed_at` may be used where applicable. Saved results and reports never include private keys, mnemonics, authorization headers, or other signer secrets.

`captured_at`, `submitted_at`, `observed_at`, `first_observed_at`, and `confirmed_at` are Unix timestamps in milliseconds. Canonical block timestamps retain Tempo's millisecond timestamp part when the RPC supplies it. `acceptance_latency` is an integer number of milliseconds.

### Runtime expressions

Use `{ var: path.to.value }` anywhere a step accepts a runtime expression. Account bindings expose `<name>.ref` for a workload `from`/`sponsor` field and `<name>.address` for an address value. Step results expose the fields listed above.

```yaml
from: { var: user.ref }
transaction_hash: { var: publish.tx_hash }
messageId: { var: delivered.args.messageId }
```

The initial deterministic transformations are:

```yaml
# Hash raw bytes, a string, bytes32, an address, or a uint8 array.
digest:
  keccak256: { var: delivered.args.payload }

# Solidity abi.encode(...).
encoded:
  abi_encode:
    types: [address, uint256]
    values:
      - { var: user.address }
      - 100

# Solidity abi.encodePacked(...).
packed:
  abi_encode_packed:
    types: [address, bytes32]
    values:
      - { var: user.address }
      - { var: delivered.args.messageId }

# keccak256(abi.encodePacked(...)).
correlation:
  keccak256_packed:
    types: [address, bytes32]
    values:
      - { var: user.address }
      - { var: delivered.args.messageId }
```

`abi_encode` supports Solidity tuple declarations with member names, including nested tuples and arrays; provide those values as YAML objects keyed by the member names. ABI expressions run only while an individual scenario instance materializes runtime expressions, after referenced values are available. `abi_encode_packed` and `keccak256_packed` also accept an inferred list, for example `keccak256_packed: [{ var: user.address }, { var: publish.tx_hash }]`. Prefer the typed form when integer widths or another Solidity type distinction matters. Transformations are deterministic; arbitrary scripting is not supported.

### Rate, concurrency, leases, and failures

`--starts-per-second` controls journeys: a value of `5` starts at most five new scenario instances per second, regardless of how many transactions each instance submits. `--max-in-flight` limits whole instances. These controls are independent from `--tx-rate` and `--max-rpc-in-flight`, which limit individual transaction submissions on each chain across all active instances.

An account binding with `select: lease` holds one pool account for the entire instance and returns it on success, failure, timeout, or cancellation. Two active instances do not receive the same leased account. `select: random` and `select: { index: N }` retain their non-exclusive workload-style behavior.

Independent DAG submits may use the same account concurrently when every affected transaction uses an expiring nonce; nonce reservations are atomic and deterministic for a fixed seed. If independent regular-nonce submits from one account attempt to share an ordered nonce lane, the journey is rejected even when the first RPC finishes before its sibling reaches submission. Add an explicit dependency to order those submits.

The effective timeout for a step is its explicit sibling `timeout`, otherwise the CLI `--step-timeout` override when supplied, otherwise `scenario.timeout`, and finally five minutes when none is configured. A timeout fails that instance and is counted separately in the report. If transaction acceptance is still unknown at a submit deadline, further submissions on that chain are disabled to avoid reusing an uncertain nonce. Receipt reverts fail unless explicitly allowed. Under `continue`, later instances continue to start after a failure. Under `fail-fast`, the runner stops starting new instances after the first failure while allowing instances that already started to finish. A scenario counts as completed successfully only after every required submit and wait step succeeds, and the command exits nonzero after writing its report when any instance failed or timed out.

The seed controls deterministic account/template/value choices. Each instance has isolated saved values, timing, failure state, and leases, so concurrent completion order cannot leak data between journeys.

### Scenario reports

The scenario runner accepts repeatable report destinations. A bare `--report report.json` is the backward-compatible JSON form; `--report json:report.json` is the explicit form, and `--report clickhouse:<url>` publishes the same finalized report to ClickHouse. When `--report` is omitted, JSON is written to stdout. All destinations share the report's client-generated `run_id`, and JSON files are written before ClickHouse publication so a publication failure does not remove the local report.

Report schema version 2 adds stable step IDs and dependencies, explicitly labeled per-step command duration, client-observed end-to-end latency, per-instance observed critical-path latency, and causal-edge latency aggregates. The original completed-journey latency field remains as a backward-compatible alias for the client-observed E2E distribution. Critical-path P50/P95/P99 values are calculated from completed per-instance traces; txgen never constructs a path percentile by adding aggregate step or edge percentiles.

The protocol timing fields distinguish:

- **Chain inclusion latency:** elapsed time between relevant canonical protocol milestones, using block timestamps when both ends are available.
- **Client observation latency:** delay from canonical destination inclusion to the client's first observation.
- **Causal-edge latency:** the observed source-milestone to destination-milestone interval for one declared dependency edge.
- **Total journey latency:** monotonic client elapsed time from starting one instance until every required terminal branch completes.

Command duration measures how long the runner spent executing a step, including local orchestration and RPC work. It is reported separately and is not described as protocol latency.

The report also includes the configured scenario name and execution configuration; started, completed, failed, and timed-out instance counts; completed scenarios per second; observed maximum in-flight instances; receipt gas metrics grouped by chain, input template, and scenario step; and failures grouped by stage and sanitized error class. Counts, minima, maxima, and means are exact; percentile estimates use a deterministic reservoir capped at 65,536 observations per distribution so duration-based runs use bounded memory.

`--sample-instances` optionally retains bounded, secret-free lifecycle traces. A sampled trace includes the critical-path step IDs and raw submission, acceptance, receipt, and log milestones with monotonic run offsets, wall-clock observation times, transaction and canonical block identity, transaction/log indices, canonical block timestamps, and confirmation depth. Grouped events from one receipt share one inclusion milestone. Traces never include calldata, signed transaction bytes, private keys, mnemonics, authorization headers or maps, template overlays, decoded event values, or other runtime secrets.

Receipt metrics come only from confirmed outer-transaction receipts; txgen does not trace or split gas across internal calls. Each distribution reports `count`, `min`, `mean`, `p50`, `p95`, and `p99`. When a receipt omits both `effectiveGasPrice` and legacy `gasPrice`, its gas usage is still counted while its effective-price and fee distributions remain empty.

When ClickHouse reporting is configured, txgen writes causal-edge aggregates to `txgen_scenario_causal_edges` and optional samples to `txgen_scenario_instance_traces`, `txgen_scenario_trace_steps`, and `txgen_scenario_trace_milestones`. It also writes the exact transaction hash, sender, canonical labels, optional scenario instance, receipt status and block identity, gas used, optional effective gas price, and optional fee paid for each collected receipt to `txgen_receipt_gas`. Apply `scripts/clickhouse/009_txgen_scenario_causal_metrics.sql` before publishing report schema version 2.

Steps expanded from fragments carry an optional `provenance` object in aggregate step reports, failure records, and sampled lifecycle steps. It records `source_file`, `fragment`, `instance_alias`, `local_step_name`, and the zero-based `local_step_index`. Inline steps omit it. Consumers can group command duration by fragment and local step across instances, or include the alias to compare individual fragment uses. Because `scenario render` omits this source metadata, a later run of rendered YAML reports those flattened steps as inline steps.

Client-observed and critical-path distributions use monotonic elapsed time. Wall-clock timestamps are included only for correlation with external chain and node data. Chain timestamp deltas remain signed so clock skew between independent chains is visible. Transaction acceptance alone never marks a journey successful.

## Output Format

Transactions are output as NDJSON with scheduling keys split by release policy:

```json
{
  "phase": "workload",
  "id": "transfer",
  "raw": "0x02f86c01...",
  "sender": "0x1111111111111111111111111111111111111111",
  "submission_keys": [
    "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
  ],
  "inclusion_keys": []
}
```

| Field | Description |
|-------|-------------|
| `phase` | `setup` or `workload`; missing phase is treated as `workload` by `bench` |
| `id` | Diagnostic identifier; required and unique for setup transactions |
| `depends_on` | Setup transaction IDs whose successful receipts are required before submission; omitted/empty means no explicit prerequisites |
| `raw` | RLP-encoded signed transaction (EIP-2718 envelope); empty when `late_sign` is present |
| `late_sign` | Optional network-specific signing instructions for materializing `raw` at submission time |
| `sender` | Logical on-chain transaction sender used for request-scoped authentication |
| `submission_keys` | 20-byte ordering constraints released after RPC submission succeeds |
| `inclusion_keys` | 20-byte ordering constraints released after the transaction is included in a block |

**Scheduling rule:** Transactions that share any scheduling key must be sent sequentially until that key's release condition is met. Normal transactions carry their natural nonce-lane key in `submission_keys`, because the chain enforces nonce order after admission. Sequence steps on the same nonce lane are submitted back-to-back; txgen only adds synthetic `inclusion_keys` at cross-lane sequence boundaries where nonce order cannot guarantee execution order.

The `sender` is independent of scheduling metadata. Txgen emits it for newly generated transactions. Older NDJSON may omit it and can still be sent without sender authentication.

## Workload Specification

Workload specs are YAML files that define accounts, transaction templates, optional transaction sequences, and mix ratios.

### Composable Specs

Specs can be assembled from reusable YAML pieces with `include`, `merge`, and
`append`. Includes are applied in order and are resolved relative to the file
that declares them. Artifact paths inside included files are also resolved
relative to the file that declares the artifact.

```yaml
include:
  - tip20/base.yml
  - tip20/recipient-random.yml
  - tip20/fee-token-any-tip20.yml
  - tip20/auth-keychain.yml
  - tip20/nonce-expiring.yml
```

Piece files can use `merge` for normal recursive object overlays. Mapping
values are merged recursively; scalar and sequence values replace the previous
value.

```yaml
merge:
  templates:
    tip20_transfer:
      gas_limit: 3000000
```

Use `append` when a piece needs to add to a sequence without replacing earlier
entries. The leaves of an `append` section must be lists.

```yaml
append:
  setup:
    steps:
      - id: authorize_keychain_users
        keychain_authorize_pool:
          accounts:
            pool: users
          access_keys:
            mnemonic: "${ACCESS_KEY_MNEMONIC}"
            range: [100000, 101000]
```

### Structure

```yaml
# Chain ID for transaction signing
chain_id: 1

# Default gas configuration
gas:
  max_fee_per_gas: 1000000000      # 1 gwei
  max_priority_fee_per_gas: 1000000000

# Signer account pools derived from mnemonics
accounts:
  users:
    mnemonic: "${MNEMONIC}"  # Supports environment variable expansion
    range: [0, 100]          # Derive accounts 0-99
  
  deployer:
    mnemonic: "${MNEMONIC}"
    index: 0                 # Single account

# Destination-only address pools. These are usable as recipients/arguments,
# but cannot be used for `from`/`sponsor` signing and are omitted by `addresses`.
# Mnemonic-backed address pools are derived lazily and cached on first use.
address_pools:
  existing_users:
    mnemonic: "${RECIPIENT_MNEMONIC}"
    range: [0, 10000]
  bloated_state_users:
    fast:
      seed: "${STATE_BLOAT_SEED}"
      range: [10000, 1000000]
  known_contracts:
    addresses:
      - "0x0000000000000000000000000000000000000001"
      - "0x0000000000000000000000000000000000000002"

# ABI/deployment artifacts for contract calls and setup deploys
artifacts:
  erc20: "./abis/ERC20.json"
  token:
    abi: "./out/Token.sol/Token.json"
    bytecode: "./out/Token.sol/Token.json"
  bytecode_only:
    bytecode: "./out/Contract.bin" # ABI defaults to empty when omitted

# Optional deterministic setup transactions emitted before workload txs
setup:
  steps:
    - id: token
      deploy:
        type: eip1559
        artifact: token
        from:
          pool: deployer
          select: { index: 0 }
        gas_limit: 5000000
        constructor_args: ["Benchmark Token", "BENCH"]

# Transaction templates
templates:
  transfer:
    type: eip1559
    from:
      pool: users
      select: random
    to:
      address_pool:
        pool: existing_users
        select: random
    value: 1000
    gas_limit: 21000

# Optional multi-transaction sequences
sequences:
  two_transfers:
    bindings:
      sender:
        account:
          pool: users
          select: random
      recipient:
        account:
          pool: users
          select: random
      amount:
        u256:
          uniform: [1, 100]
    steps:
      - template: transfer
        with:
          from: { var: sender.ref }
          to: { var: recipient.address }
          value: { var: amount }
      - template: transfer
        with:
          from: { var: sender.ref }
          to: { var: recipient.address }
          value: { var: amount }

# Weighted mix for generation
mix:
  - template: transfer
    weight: 90
  - sequence: two_transfers
    weight: 10
```

### Account Selection

Accounts are selected from signer pools using `select`. Only `accounts` pools can be used in signing positions such as `from` and `sponsor`; `address_pools` are destination-only values.

```yaml
from:
  pool: users
  select: random    # Random signer account from pool
```

### Destination-only Address Pools

Use `address_pools` when you want to send to known users without making those users available for signing. Mnemonic-backed pools are lazy: txgen derives and caches an address only when it is selected, so large ranges such as `[0, 1000000]` do not add startup cost. Fast pools derive deterministic non-signable addresses as `last20(keccak256(keccak256(seed) || index_be_u64))`, matching Tempo state-bloat addresses beyond the signable range.

```yaml
accounts:
  senders:
    mnemonic: "${SENDER_MNEMONIC}"
    range: [0, 100]

address_pools:
  existing_users:
    mnemonic: "${RECIPIENT_MNEMONIC}"
    range: [0, 1000000]
  state_bloat_users:
    fast:
      seed: "${STATE_BLOAT_SEED}"
      range: [10000, 1000000]
  fixed_recipients:
    addresses:
      - "0x0000000000000000000000000000000000000001"
      - "0x0000000000000000000000000000000000000002"
```

Reference an address pool from any address-valued field:

```yaml
to:
  address_pool:
    pool: existing_users
    select: random
```

or select a specific derivation/list index:

```yaml
to:
  address_pool:
    pool: existing_users
    select: { index: 12345 }
```

`txgen addresses` intentionally omits `address_pools`; it only lists signer account addresses for funding.

### Value Generators

Dynamic values can be generated using expressions:

```yaml
# Uniform random in range
value:
  uniform: [1000, 10000]

# Random choice from list
to:
  choice:
    - "0x0000000000000000000000000000000000000001"
    - "0x0000000000000000000000000000000000000002"

# Account address from signer pool
to:
  pool: users
  select: random

# Destination-only address from address pool
to:
  address_pool:
    pool: existing_users
    select: random

# Random address
to: random

# Random address in an ABI argument
call:
  to: "0x..."
  abi: erc20
  function: transfer
  args:
    - random
    - 1000000

# Destination-only address in an ABI argument
call:
  to: "0x..."
  abi: erc20
  function: transfer
  args:
    - address_pool:
        pool: existing_users
        select: random
    - 1000000

# Random bytes
input:
  random_bytes: 32
```

`random` generates a value of the target field type. It is supported for fixed-size
numeric and hash/address-like values (`u64`, `u128`, `u256`, `address`,
`bytes32`). Use `random_bytes` when you need dynamically sized byte payloads.

### Contract Calls

Use the `call` field for ABI-encoded contract calls:

```yaml
templates:
  erc20_transfer:
    type: eip1559
    from:
      pool: users
      select: random
    gas_limit: 65000
    call:
      to: "0x..."           # Contract address
      abi: erc20            # Artifact name
      function: transfer    # Function name
      args:
        - address_pool:
            pool: existing_users
            select: random  # recipient from destination-only pool
        - 1000000           # amount
      value: 0
```

For correlated call arguments, `args` can define local variables and then use
them in `values`. Variables are resolved once per call, so dependent values can
reuse the same random choices:

```yaml
call:
  to: "0x..."
  abi: dex
  function: placeFlip
  args:
    vars:
      amount:
        uniform: { min: 100000000, max: 500000000 }
      is_bid:
        choice: [true, false]
      tick:
        if:
          cond: { var: is_bid }
          then: { uniform: { min: -30, max: 0, step: 10 } }
          else: { uniform: { min: 0, max: 30, step: 10 } }
      flip_tick:
        if:
          cond: { var: is_bid }
          then: { uniform: { min: { var: tick }, max: 30, step: 10 } }
          else: { uniform: { min: -30, max: { var: tick }, step: 10 } }
    values:
      - "0x20c0000000000000000000000000000000000001"
      - { var: amount }
      - { var: is_bid }
      - { var: tick }
      - { var: flip_tick }
```

Call argument variables reuse normal txgen generators such as `choice` and
`uniform`. The `var` and `if` expressions are local to the call argument block and let
arguments depend on earlier resolved variables.

Solidity tuple arguments may be written as a list in component order or as a mapping keyed by the component names in the ABI. Tuple arrays use a list of tuple values. For example:

```yaml
args:
  - token: "0x..."
    amount: 1000000
```

### Setup Transactions

Use `setup.steps` for deterministic transactions that prepare the chain before the measured workload, such as contract deployments and mint/configuration calls. `txgen` emits all setup transactions first with `phase: "setup"`; workload transactions are emitted afterwards with `phase: "workload"`.

`bench send` treats the first workload transaction as a setup barrier: it requires all setup transactions to succeed, resets benchmark timing/metrics, and only then sends workload transactions. Use `bench send --skip-setup` to ignore setup transactions when the target chain is already prepared.

**Breaking change:** setup no longer infers receipt barriers from sender or nonce-lane
changes. Independent setup transactions submit concurrently, subject to TPS, RPC
concurrency, and `--max-pending`. Transactions on the same ordered nonce lane still
submit in nonce order, without waiting for receipts. Expiring nonces provide no
implicit execution ordering.

Declare real receipt dependencies with `depends_on`, referencing setup **step IDs**:

```yaml
setup:
  steps:
    - id: deploy_token
      deploy: # existing deployment fields
        # ...
    - id: configure_token
      depends_on: [deploy_token]
      tx: # existing transaction fields
        # ...
```

Every transaction emitted by a dependent step waits for **all** transactions from
every prerequisite step to have successful receipts. Independent transactions,
including transactions expanded from `keychain_authorize_pool`, do not wait for
one another. A `setup.<id>.address` binding resolves an address; it does not create
a receipt dependency. Add dependencies for deployment/configuration/funding that
must be complete before another lane can submit or execute.

Generation materializes and validates the complete setup before emitting it.
`bench send` buffers the setup prefix and validates it before submitting any of it.
Validation rejects missing or duplicate IDs, unknown dependencies, and cycles in
the combined explicit-dependency and nonce/scheduling-key graph. Forward receipt
references are supported when they do not contradict nonce order; forward value
bindings remain unsupported. NDJSON `depends_on` contains concrete transaction IDs
(e.g. `setup.authorize_users[0]`), expanded from the YAML step dependencies.

A failed setup transaction cancels queued setup and prevents workload startup;
already submitted transactions may still execute. The final barrier requires
every setup transaction to succeed, even when no other step depends on it.
Nonce ordering guarantees execution order, but accounts must already meet node
admission requirements, including funding and key authorization.

This scheduling model applies to `generate | bench send`. `scenario run` keeps
its existing just-in-time serial initialization; dependencies there must refer
to earlier setup steps, and invalid or forward references fail before submission.

For a timed workload with a long setup, run setup separately so pipe backpressure
does not consume `generate --duration` or age short-lived workload signatures:

```bash
set -o pipefail
txgen-tempo generate -s workload.yml --rpc "$RPC_URL" -n 0 \
  --setup-state-out setup.json | bench send --rpc-url "$RPC_URL" &&
txgen-tempo generate -s workload.yml --rpc "$RPC_URL" --duration 30s \
  --setup-state-in setup.json | bench send --rpc-url "$RPC_URL" --drain-timeout 300
```

`--setup-state-out` requires `--count 0` and saves public setup outputs such as
contract addresses and transaction hashes. Reuse that file only after every setup
transaction succeeds, with the same spec and chain. `--setup-state-in` emits only
workload transactions, retains the original `setup.<id>.*` bindings, and requires
`--rpc` to fetch current nonces without reserving setup nonces again. Chain IDs,
state versions, and setup step IDs are checked. Keychain setup extensions are not
supported by this state file because they also initialize adapter state.

```yaml
artifacts:
  token:
    abi: ./out/Token.sol/Token.json
    bytecode: ./out/Token.sol/Token.json

setup:
  steps:
    - id: token
      bindings:
        deployer:
          account: { pool: deployer, select: { index: 0 } }
      deploy:
        type: eip1559
        artifact: token
        from: { var: deployer.ref }
        gas_limit: 5000000
        constructor_args: ["Benchmark Token", "BENCH"]

    - id: mint_user0
      bindings:
        deployer:
          account: { pool: deployer, select: { index: 0 } }
        user:
          account: { pool: users, select: { index: 0 } }
      tx:
        type: eip1559
        from: { var: deployer.ref }
        gas_limit: 100000
        call:
          to: { var: setup.token.address }
          abi: token
          function: mint
          args:
            - { var: user.address }
            - 1000000000000000000000

templates:
  transfer_token:
    type: eip1559
    from: { pool: users, select: random }
    gas_limit: 65000
    call:
      to: { var: setup.token.address }
      abi: token
      function: transfer
      args:
        - { pool: users, select: random }
        - 1000000000000000000
```

Setup outputs are deterministic only. Supported references are:

| Reference | Description |
|-----------|-------------|
| `setup.<id>.address` | Contract address for deployment steps |
| `setup.<id>.tx_hash` | Signed transaction hash |
| `setup.<id>.sender` | Sender address |
| `setup.<id>.nonce` | Sender nonce used by the setup transaction |

Setup does not support using contract call return values, logs, or receipt fields as later inputs.

### Transaction Sequences

Use `sequences` when one generated workload item should emit multiple ordered transactions. Bindings are resolved once per sequence instance and can be referenced from any step with `{ var: ... }`.

```yaml
sequences:
  approve_then_transfer_from:
    bindings:
      owner:
        account: { pool: users, select: random }
      spender:
        account: { pool: users, select: random }
      recipient:
        account: { pool: users, select: random }
      amount:
        u256: { uniform: [1, 1000] }

    steps:
      - template: erc20_approve
        with:
          from: { var: owner.ref }
          call:
            args:
              - { var: spender.address }
              - { var: amount }

      - template: erc20_transfer_from
        with:
          from: { var: spender.ref }
          call:
            args:
              - { var: owner.address }
              - { var: recipient.address }
              - { var: amount }
```

Supported binding references:

| Binding | References |
|---------|------------|
| `account` | `<name>.ref`, `<name>.address` |
| `address` | `<name>` |
| `bytes32` | `<name>` |
| `abi_hash` | `<name>` |
| `u256` | `<name>` |
| `u64` | `<name>` |
| `string` | `<name>` |

Sequences also expose `{ var: chain_id }` as the top-level workload `chain_id` unless a binding named `chain_id` is defined.

Hash bindings can reference other sequence bindings and are resolved once per sequence instance. For deterministic IDs that contracts compute with `keccak256(abi.encode(...))` (such as Tempo MPP channel IDs), use `abi_hash`:

```yaml
bindings:
  payer:
    account: { pool: users, select: random }
  ephemeral_recipient:
    address: random
  amount:
    u256: random
  salt:
    bytes32: { random_bytes: 32 }
  channel_id:
    abi_hash:
      types: [address, address, address, bytes32, address, address, uint256]
      values:
        - { var: payer.address } # payer
        - { var: payer.address } # payee
        - "0x20c0000000000000000000000000000000000000" # token
        - { var: salt }
        - "0x0000000000000000000000000000000000000000" # authorizedSigner
        - "0x0000000000000000000000000000000000000000" # channel contract
        - { var: chain_id }
```

Each emitted sequence step gets its natural nonce-lane key as a `submission_key`. Txgen then groups adjacent sequence steps by lane. Steps in the same lane rely on nonce order and can be submitted back-to-back. When a sequence crosses lanes, txgen adds a synthetic boundary key: the previous run releases it after inclusion, and the next run requires it as a `submission_key`. This preserves cross-lane ordering without receipt-gating same-lane nonce chains.

When set, `txgen generate -n` counts emitted transactions, not sequence instances. txgen never emits a partial sequence; if no remaining mix entry fits the remaining transaction budget or `--duration` elapses before the next workload item starts, generation stops early.

See `examples/sequence.yaml` for a small syntax example, `examples/tip20-sequence.yaml` for a Tempo TIP20 `approve -> transferFrom` sequence whose second transaction depends on the first, and `examples/tip20-mpp.yaml` for TIP20 transfers mixed with deterministic MPP channel `open -> close` sequences.

## Supported Chains

### Ethereum (`txgen-ethereum`)

Standard Ethereum transaction types:

| Type | Description |
|------|-------------|
| `legacy` | Pre-EIP-1559 transactions |
| `eip2930` | Access list transactions |
| `eip1559` | Dynamic fee transactions |

### Tempo (`txgen-tempo`)

All Ethereum types plus Tempo-native transactions:

| Type | Description |
|------|-------------|
| `tempo` | Native 0x76 transactions with protocol, 2D, or expiring nonces |

#### Access lists

`txgen-tempo` accepts `access_list` on `tempo`, `eip2930`, and `eip1559`
templates. Legacy transactions reject nonempty lists. Each entry has an
`address` and `storage_keys`, which can be an explicit array of 32-byte keys
or a consecutive range expanded before signing:

```yaml
access_list:
  - address: "0x1111111111111111111111111111111111111111"
    storage_keys:
      range:
        start: { var: start }
        count: 128
```

Bind `start` once in a sequence to reuse the exact value in calldata. Using two
independent random generators would produce unrelated values. Explicit keys
and addresses also support normal generators and sequence substitution. The
list is retained for both immediate and deferred signing. Range counts must
be positive and cannot overflow uint256; generated lists are limited to 65,536
keys as an allocation guard. Chain and transaction-pool limits still apply
(for example, Tempo currently allows 256 storage keys per account). Access
lists mark EVM accesses warm; physical disk prefetch depends on the node.


**Tempo-specific fields:**

```yaml
templates:
  tempo_transfer:
    type: tempo
    from:
      pool: users
      select: random
    to: "0x..."
    value: 1000
    gas_limit: 21000
    max_fee_per_gas: 1000000000
    max_priority_fee_per_gas: 1000000000
    
    # Tempo-specific replay protection
    nonce_key: "42"              # 2D nonce lane (0 = protocol nonce)
    expiring_nonce: true         # TIP-1009 expiring nonce mode
    valid_for_secs: 25           # Relative expiry window for standard/sponsored txs
    valid_before: 1700100000     # Absolute expiry timestamp (alternative to valid_for_secs)
    fee_token: "0x..."           # Pay gas in stablecoin
    valid_after: 1700000000      # Scheduled: valid after timestamp
    
    # Batched calls
    calls:
      - to: "0x..."
        abi: erc20
        function: transfer
        args: ["0x...", 1000]
      - to: "0x..."
        abi: erc20
        function: approve
        args: ["0x...", 5000]
```

**2D nonces:** Using different `nonce_key` values allows transactions from the same sender to be sent in parallel without nonce conflicts.

**Expiring nonces:** Set `expiring_nonce: true` to generate TIP-1009 transactions. txgen will set `nonce_key = U256::MAX` and `nonce = 0` automatically. You must provide either:

- `valid_before`: an absolute Unix timestamp in seconds
- `valid_for_secs`: a relative TTL in seconds for standard/sponsored transactions, resolved immediately before submission

`valid_for_secs` must be `<= 30`, matching Tempo's expiring nonce validity window.

With `--defer-signing`, relative expiry on standard or sponsored transactions emits a deferred-signing record with an empty `raw` field. `bench send --late-signing-spec workload.yaml` resolves the account references and signs each record immediately before the RPC request. The same option works for a pre-generated file and for a pipe; the workload spec supplies signing keys and is never embedded in the NDJSON output. Without `--defer-signing`, generation retains the existing signed output. Txgen still applies a deterministic per-transaction bump to `max_fee_per_gas` before the final sender and sponsor signatures, so otherwise identical expiring transactions have unique signed payloads. `max_priority_fee_per_gas` remains exactly as configured, including zero. Tempo keychain-auth records retain the existing generation-time signing path.

Recommended benchmark setting: `valid_for_secs: 25`. This matches `tempo-bench`'s default behavior and stays inside Tempo's 30-second protocol limit while leaving some propagation slack.

**Benchmarking caveat:** Expiring nonce transactions are still time-bounded by `valid_before <= now + 30s`. Relative-expiry records can be pre-generated and replayed later because the validity window starts when `bench send` signs them; absolute `valid_before` records retain their existing pre-signed behavior and must be submitted before their timestamp.

**Keychain access keys:** Tempo templates can sign workload transactions with an AccountKeychain access key while keeping the logical sender as `from`. Add a setup step to pre-authorize one deterministic access key per account, then reference that setup step from workload templates:

```yaml
setup:
  steps:
    - id: authorize_keychain_users
      keychain_authorize_pool:
        accounts: { pool: users }
        access_keys:
          mnemonic: "test test test test test test test test test test test junk"
          range: [100000, 100003]
        key_type: secp256k1
        limits:
          - token: "0x20c0000000000000000000000000000000000000"
            amount: "1000000000000000000000000"
            period: 0
        allowed_calls: unrestricted

templates:
  keychain_tip20_transfer:
    type: tempo
    auth:
      mode: keychain
      access_key:
        from_setup: authorize_keychain_users
        pair: same_index
    from: { pool: users, select: random }
    gas_limit: 400000
    call:
      to: "0x20c0000000000000000000000000000000000000"
      abi: ERC20
      function: transfer
      args:
        - { pool: users, select: random }
        - 1
```

Access keys derived by `keychain_authorize_pool.access_keys` are hidden signing keys. They are not added to `accounts` and are not printed by `txgen addresses`.

For inline provisioning workloads, use `auth.mode: key_authorization`. txgen derives a deterministic per-transaction secp256k1 access key, signs the `key_authorization` with the root `from` account, attaches it to the Tempo transaction, and signs the transaction with a keychain signature:

```yaml
auth:
  mode: key_authorization
  access_key:
    derive: per_tx
    mnemonic: "${TXGEN_ACCESS_KEY_MNEMONIC}"
    range: [1000000, 1001000]
  key_type: secp256k1
  limits:
    - token: "0x20c0000000000000000000000000000000000000"
      amount: "1000000000000000000000000"
      period: 0
  witness:
    random_bytes: 32
```

Inline `access_key.mnemonic` is a hidden signing seed for generated access keys; it does not need funded accounts and is not listed by `txgen addresses`. Omit it only for disposable benchmark specs, where txgen falls back to the public benchmark mnemonic at index `1000000`.

`allowed_calls` may be `unrestricted`, `deny_all`, or a list of scopes with `target` and `selectors` entries. Selector values are 4-byte `0x` hex strings.

**Prefetch caveat:** `txgen-tempo generate --rpc` only prefetches constant 2D nonce keys that are fixed in the spec. Dynamic/generated `nonce_key` values (`uniform`, `choice`, etc.) are resolved per transaction and are not prefetched automatically.

## RPC Methods

Summary of which RPC methods are required by each feature:

| RPC Method | Required By |
|------------|-------------|
| `eth_chainId` | `bench call` (identity check), `scenario run` (`chain_id: auto` and explicit-ID validation) |
| `eth_getTransactionCount` | `txgen-ethereum generate --rpc`, `txgen-tempo generate --rpc`, `scenario run` (query RPC; pending nonce initialization) |
| `eth_getStorageAt` | `txgen-tempo scenario run` (Tempo parallel nonce lanes) |
| `eth_sendRawTransaction` | `bench send`, `scenario run` (workload setup and `submit`), optionally sender-authenticated |
| `eth_getTransactionByHash` | `scenario run` (sender-scoped submission RPC; reconcile a rejected or uncertain submission) |
| `eth_getTransactionReceipt` | `scenario run` (workload setup, `submit await: receipt`, `wait_receipt`, and transaction-hash `wait_log`), optionally sender-authenticated |
| `eth_getBlockReceipts` | Shared setup/sequence inclusion tracking in `bench send`, inclusion-key tracking in `scenario run`, and `bench send --collect-receipt-metrics` (post-run non-system receipt gas and fee metrics) |
| `eth_blockNumber` | `bench send` (query RPC when configured; benchmark block range and shared inclusion tracking), `scenario run` (`checkpoint`, confirmations, and block-range log polling) |
| `eth_getBlockByNumber` | `bench send` (query RPC when configured; per-block stats collection), `bench call` (identity check), `scenario run` (`checkpoint`) |
| `eth_getLogs` | `scenario run` (block-range `wait_log`) |
| `eth_call` | `bench call` (when the corpus uses it), `txgen-tempo scenario run` (`prepare_encrypted_deposit` and other adapter `invoke` actions) |
| `eth_estimateGas`, `eth_createAccessList` | `bench call` (when the corpus uses them) |
| `debug_traceCall`, `debug_traceTransaction`, `debug_traceBlockByNumber` | `bench call` (when the corpus uses them) |
| `trace_call`, `trace_transaction`, `trace_replayTransaction`, `trace_block`, `trace_replayBlockTransactions` | `bench call` (when the corpus uses them) |
| `debug_getRawBlock` | `txgen extract`, `txgen-ethereum extract-big-blocks` |
| `eth_getBlockAccessListByBlockNumber` | `txgen extract --bal`, `txgen-ethereum extract-big-blocks --bal` |
| `reth_newPayload` | `bench send-blocks` |
| `reth_forkchoiceUpdated` | `bench send-blocks` |
| `testing_buildBlockV1` | `bench send-blocks --reorg` |
| `txpool_status` | `bench send` (query RPC when configured; pool drain wait) |

> **Note:** `debug_*` methods require a node with the debug namespace enabled (typically archive nodes), and `trace_*` methods the trace namespace. `reth_*` methods are custom reth Engine API extensions.

## Examples

See the `examples/` directory:

- `simple.yaml` — Basic Ethereum transfers
- `tempo.yaml` — Tempo transactions with 2D and expiring nonces
- `tempo-mainnet-spam.yaml` — Tempo mainnet workload
- `bench-spec.yaml` — Bench workload specification
- `erc20.abi.json` — ERC-20 ABI artifact

```bash
# Run the simple example
txgen-ethereum generate -s examples/simple.yaml -n 10 --seed 42

# Run the Tempo example
txgen-tempo generate -s examples/tempo.yaml -n 10 --seed 42
```

## Architecture

```
txgen/
├── crates/
│   ├── txgen-core/       # Core library: spec parsing, account management, output
│   ├── txgen-cli/        # Shared CLI framework and NetworkAdapter trait
│   ├── txgen-ethereum/   # Ethereum binary: legacy, eip2930, eip1559
│   ├── txgen-tempo/      # Tempo binary: 0x76 + delegates to ethereum
│   ├── bench-core/       # Benchmarking: metrics, sender, reporters, replay corpus
│   └── bench-cli/        # Bench CLI binary (bench)
└── examples/             # Example workload specs
```

### NetworkAdapter Trait

Each chain binary implements the `NetworkAdapter` trait from `txgen-cli`:

```rust
pub trait NetworkAdapter: Send + Sync {
    type Template: DeserializeOwned + Send;
    type Network: Network;
    type SignContext: RequestSignContext<Self::Network>;

    fn build_request(
        &self,
        template: Self::Template,
        ctx: &mut BuildContext<'_>,
    ) -> Result<TxRequest<<Self::Network as Network>::TransactionRequest, Self::SignContext>>;

    fn expand_setup_extension(
        &mut self,
        step_id: &str,
        extension_name: &str,
        value: serde_yaml::Value,
        ctx: &mut BuildContext<'_>,
    ) -> Result<Option<Vec<serde_yaml::Value>>> {
        Ok(None)
    }

    fn prefetch_nonces(/* ... */) -> impl Future<Output = Result<()>> { ... }
}
```

## License

MIT OR Apache-2.0
