# TIP-20 Engine API suites

These fixtures exercise direct `TIP20.transfer(address,uint256)` execution through Tempo's
authenticated Engine API. Each suite contains the source genesis, the exact Tempo block RLP and
block access list, and a semantic manifest that separates untimed setup blocks from one measured
workload block.

## Cases

| Suite | Measured block | Workload | Gas used |
| --- | ---: | --- | ---: |
| `shared-existing-recipient` | 4 | 10 fresh funded dev accounts transfer one unit each to funded dev account 19 | 3,168,760 |
| `new-recipients` | 5 | 10 fresh funded dev accounts transfer one unit to distinct previously untouched addresses `0x1000...0001` through `0x1000...000a` | 5,410,300 |
| `existing-recipients` | 12 | The same 10 initialized senders transfer another unit to the recipients created by setup block 5 | 417,300 |

The token is the dev-genesis TIP-20 at `0x20c0000000000000000000000000000000000000`.
All ten transactions in every measured block succeeded in the source chain. Successful replay
requires both `reth_newPayload` and the following `reth_forkchoiceUpdated` call to succeed, and the
payload must return `VALID`; this validates Tempo's computed block hash/state root against the
recorded canonical block.

The source chains were produced from Tempo revision
`a41e3184a2f1a50a4a0b60fcdd536c1a4cc2dae0`, chain ID 1337, with seed `20260819`.
`shared-existing-recipient` and `new-recipients` use independent fresh source chains so their
prestates do not include another measured workload. `existing-recipients` intentionally shares the
new-recipient chain and includes its first-touch block in setup. Empty blocks are retained so every
suite is independently replayable from genesis.

## Replay locally

Start a fresh Tempo node for each manifest. Reusing a node would make the tests stateful and cause
the next suite's setup chain to conflict with the existing head.

```sh
tempo node \
  --dev \
  --dev.block-time 1h \
  --chain crates/chainspec/src/genesis/dev.json \
  --datadir /tmp/tempo-tip20-replay \
  --http --http.api all \
  --authrpc.addr 127.0.0.1 --authrpc.port 8551 \
  --debug.startup-sync-state-idle
```

From the Benchmarkoor repository, replay one suite against that process:

```sh
go run -tags containers_image_openpgp ./cmd/benchmarkoor replay \
  --manifest /path/to/tempo/contrib/bench/suites/tip20/new-recipients/manifest.json \
  --engine-endpoint http://127.0.0.1:8551 \
  --jwt-file /tmp/tempo-tip20-replay/jwt.hex \
  --results-dir /tmp/benchmarkoor-tip20-results \
  --run-id tip20-new-recipients
```

Benchmarkoor records HTTP round-trip time, Tempo's server-side execution time, persistence wait,
execution-cache wait, sparse-trie wait, gas, and derived MGas/s. Use server execution time for EVM
comparisons and keep wait metrics visible when diagnosing end-to-end latency.

## Regenerate

Produce the transaction blocks on a deterministic dev node, then export each measured block with
`cargo xtask generate-benchmark-suite`. For example:

```sh
cargo xtask generate-benchmark-suite \
  --rpc-url http://127.0.0.1:8545 \
  --genesis crates/chainspec/src/genesis/dev.json \
  --out contrib/bench/suites/tip20/new-recipients \
  --name tip20-new-recipients \
  --description 'Ten direct TIP-20 transfers from distinct senders to distinct new recipients' \
  --from-block 5 --to-block 5 \
  --tag tempo-native --tag tip20 --tag transfer --tag new-recipient --tag state-growth \
  --seed 20260819 --revision "$(git rev-parse HEAD)" \
  --hardfork dev-all --chain-id 1337 --force
```

The manifest records fixture provenance. Performance reports should additionally record the Tempo
and Benchmarkoor revisions, build profile, host, and repeated-run statistics; a single local replay
is a correctness smoke test and only a directional performance sample.
