# EEST benchmarks on Tempo

This adapter runs Ethereum Execution Spec Tests (EEST) benchmark definitions
against a published Tempo node and turns the resulting canonical blocks into
Benchmarkoor replay suites.

Tempo rejects native-value transfers. EEST normally uses those transfers to
fund the generated transaction senders, so `tempo_eest_adapter.py` rewrites
plain `pre.fund_eoa` setup transactions to pathUSD TIP-20 transfers. A new EOA
has no user token preference, so pathUSD is the protocol fallback used for its
legacy Ethereum benchmark transaction. The test
definitions, generated contracts, workload transactions, and assertions remain
owned by EEST. It also raises generated contract-deployment setup transactions
to Tempo's 30M per-transaction ceiling because Tempo's state-gas and storage-
credit accounting is not part of EEST's Ethereum-only deployment estimate.

`run-batch.sh` is the normal path for suite conversion. It executes the source
tests serially on one fresh Tempo chain, records the canonical block interval
for every pytest node, and exports each passing case as one Benchmarkoor test.
The last transaction-bearing block in a case is measured; all earlier blocks
are replay setup. This recreates the blocks from the EEST-provided bytecode and
transaction input instead of attempting to mutate already-signed Ethereum
payloads.

The adapter currently supports compute benchmarks which use plain funded EOAs.
Stateful fixtures and tests which require EIP-7702 delegation or storage on a
generated EOA need additional Tempo-specific setup handling.

## Generate a batch suite

```sh
EEST_REPO=/path/to/execution-specs \
SUITE_OUT=/path/to/tempo/contrib/bench/suites/eest/arithmetic-10m \
SUITE_NAME=eest-prague-arithmetic-10m \
BLOCK_TIME=100ms \
./contrib/bench/eest/run-batch.sh \
  tests/benchmark/compute/instruction/test_arithmetic.py
```

Multiple source files can be passed to one invocation. A single invocation
uses a single canonical chain, so its generated manifest can be replayed from
genesis without resetting the client between tests:

```sh
EEST_REPO=/path/to/execution-specs \
SUITE_OUT=/path/to/tempo/contrib/bench/suites/eest/stack-memory-10m \
SUITE_NAME=eest-prague-stack-memory-10m \
./contrib/bench/eest/run-batch.sh \
  tests/benchmark/compute/instruction/test_stack.py \
  tests/benchmark/compute/instruction/test_memory.py
```

The batch command prints EEST pass/fail counts and records them in the suite
metadata. Only cases which pass EEST post-state checks and contain a workload
transaction become measured tests. Blocks created by an intervening failed
case remain setup for the next passing case, preserving canonical ancestry.

Replay the generated suite with Benchmarkoor and the published Tempo image:

```sh
cd /path/to/benchmarkoor
USER_UID=$(id -u) USER_GID=$(id -g) \
TEMPO_SUITE_DIR=/absolute/path/to/generated-suite \
TEMPO_IMAGE=docker.io/tempoxyz/tempo:latest \
docker compose -f docker-compose.tempo.yaml run --rm benchmarkoor
```

## Merge and run every production suite

The production suites are independent canonical chains. `merge-all-suites.sh`
creates one logical manifest and marks the first test of each source suite as a
state-reset boundary. It references the existing RLP/BAL files, so it does not
duplicate roughly 280 MB of block data:

```sh
./contrib/bench/eest/merge-all-suites.sh
```

Run the merged 962-test suite with the boundary-aware Benchmarkoor runner. Mount
the common suites directory, select the nested manifest, and enable container
recreation; boundary metadata limits recreation to the 15 transitions between
the 16 source suites:

```sh
cd /path/to/benchmarkoor
USER_UID=$(id -u) USER_GID=$(id -g) \
TEMPO_SUITE_DIR=/absolute/path/to/tempo/contrib/bench/suites \
TEMPO_SUITE_MANIFEST=/app/tempo-suite/all/manifest.json \
TEMPO_ROLLBACK_STRATEGY=container-recreate \
TEMPO_IMAGE=docker.io/tempoxyz/tempo:latest \
docker compose -f docker-compose.tempo.yaml run --rm benchmarkoor
```

Do not concatenate manifests without these boundaries: each source suite starts
from genesis, and its first block is not a child of the preceding suite's head.
The merged names are prefixed with their source suite so overlapping Keccak
cases remain independently reportable.

`run-one.sh` remains useful for debugging a single-test capture. It starts an ephemeral node from
the published Tempo image, runs EEST in the published `uv` image, finds the
last transaction-bearing block as the measured workload, exports all earlier
blocks as setup, and removes the generator container. It never builds a Tempo
node image.

```sh
EEST_REPO=/path/to/execution-specs \
SUITE_OUT=/path/to/tempo/contrib/bench/suites/eest/add-10m \
EEST_TEST=tests/benchmark/compute/instruction/test_arithmetic.py \
EEST_FILTER='opcode_ADD and not ADDMOD' \
GAS_MILLIONS=10 \
./contrib/bench/eest/run-one.sh
```

The filter must select exactly one benchmark. Repeat the command with an
independent output directory for every test/gas dimension; this keeps setup
state and measured blocks isolated and gives each case a stable suite hash.
If you override the decimal `EOA_START`, also set the matching
`EOA_START_HEX` so provenance records the full 256-bit seed without shell
integer truncation.

## Run one benchmark

Start the published Tempo image (no source build):

```sh
docker run -d --name tempo-eest-generator \
  -p 18545:8545 -p 18551:8551 \
  docker.io/tempoxyz/tempo:latest \
  node --dev --dev.block-time=1s \
  --datadir=/tmp/tempo-eest \
  --http --http.addr=0.0.0.0 --http.api=all --http.port=8545 \
  --authrpc.addr=0.0.0.0 --authrpc.port=8551 \
  --disable-discovery --no-persist-peers --builder.max-tasks=1
```

Run EEST from its checkout with the published `uv` image. On macOS,
`host.docker.internal` reaches the Tempo RPC published on the host:

```sh
docker run --rm \
  -e PYTHONPATH=/tempo/contrib/bench/eest \
  -e PYTEST_PLUGINS=tempo_eest_adapter \
  -v /path/to/execution-specs:/work \
  -v /path/to/tempo:/tempo:ro \
  -v tempo-eest-uv-cache:/root/.cache/uv \
  -w /work ghcr.io/astral-sh/uv:python3.11-bookworm \
  uv run execute remote -v \
  --fork=Prague --chain-id=1337 \
  --rpc-endpoint=http://host.docker.internal:18545 \
  --rpc-seed-key=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --gas-benchmark-values=10 --tx-wait-timeout=30 --skip-cleanup \
  tests/benchmark/compute/instruction/test_arithmetic.py \
  -k 'opcode_ADD and not ADDMOD'
```

Record the block number immediately before and after the command. Export the
chain prefix and use the first workload block as `--from-block`:

```sh
cargo xtask generate-benchmark-suite \
  --rpc-url http://127.0.0.1:18545 \
  --genesis crates/chainspec/src/genesis/dev.json \
  --out contrib/bench/suites/eest/add-10m \
  --name eest-add-10m \
  --from-block FIRST_WORKLOAD_BLOCK \
  --to-block LAST_WORKLOAD_BLOCK \
  --tag eest --tag ethereum-derived --tag tempo-normalized \
  --seed EEST_EOA_START --revision EEST_GIT_REVISION \
  --hardfork dev-all --chain-id 1337
```

The exported `manifest.json`, `genesis.json`, block RLP, and block access lists
are the portable benchmark data. Benchmarkoor replays setup calls without
timing them and reports the test-phase Engine API server execution time, HTTP
round-trip time, gas, transaction count, payload size, and opcode data.
