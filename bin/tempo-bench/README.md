# `tempo-bench`

`tempo-bench` is benchmarking suite for Tempo node components.

## Installation

Install `tempo` and `tempo-bench`

```bash
cargo install --path bin/tempo-bench --profile maxperf
cargo install --path bin/tempo --profile maxperf

```

### Overview

```
Usage: tempo-bench <COMMAND>

Commands:
  run-max-tps       Run maximum TPS throughput benchmarking
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### `run-max-tps`

High throughput tx load testing

```
Usage: tempo-bench run-max-tps [OPTIONS] --tps <TPS>

Options:
  -t, --tps <TPS>
          Target transactions per second

  -d, --duration <DURATION>
          Test duration in seconds

          [default: 30]

  -a, --accounts <ACCOUNTS>
          Number of accounts for pre-generation

          [default: 100]

  -m, --mnemonic <MNEMONIC>
          Mnemonic for generating accounts

          [default: random]

  -f, --from-mnemonic-index <FROM_MNEMONIC_INDEX>
          [default: 0]

      --fee-token <FEE_TOKEN>
          [default: 0x20C0000000000000000000000000000000000001]

      --target-urls <TARGET_URLS>
          Target URLs for network connections

          [default: http://localhost:8545/]

      --max-concurrent-requests <MAX_CONCURRENT_REQUESTS>
          A limit of the maximum number of concurrent requests, prevents issues with too many connections open at once

          [default: 100]

      --max-concurrent-transactions <MAX_CONCURRENT_TRANSACTIONS>
          A number of transaction to send, before waiting for their receipts, that should be likely safe.

          Large amount of transactions in a block will result in system transaction OutOfGas error.

          [default: 10000]

      --fd-limit <FD_LIMIT>
          File descriptor limit to set

      --node-commit-sha <NODE_COMMIT_SHA>
          Node commit SHA for metadata

      --build-profile <BUILD_PROFILE>
          Build profile for metadata (e.g., "release", "debug", "maxperf")

      --benchmark-mode <BENCHMARK_MODE>
          Benchmark mode for metadata (e.g., "max_tps", "stress_test")

      --tip20-weight <TIP20_WEIGHT>
          A weight that determines the likelihood of generating a TIP-20 transfer transaction

          [default: 1]

      --place-order-weight <PLACE_ORDER_WEIGHT>
          A weight that determines the likelihood of generating a DEX place transaction

          [default: 0]

      --swap-weight <SWAP_WEIGHT>
          A weight that determines the likelihood of generating a DEX swapExactAmountIn transaction

          [default: 0]

      --erc20-weight <ERC20_WEIGHT>
          A weight that determines the likelihood of generating an ERC-20 transfer transaction

          [default: 0]

      --sample-size <SAMPLE_SIZE>
          An amount of receipts to wait for after sending all the transactions

          [default: 100]

      --faucet
          Fund accounts from the faucet before running the benchmark.

          Calls tempo_fundAddress for each account.

      --clear-txpool
          Clear the transaction pool before running the benchmark.

          Calls admin_clearTxpool.

      --use-2d-nonces
          Use 2D nonces instead of expiring nonces.

          By default, tempo-bench uses expiring nonces (TIP-1009) which use a circular buffer
          for replay protection, avoiding state bloat. Use this flag to switch to 2D nonces.

      --use-standard-nonces
          Use standard sequential nonces instead of expiring nonces.

      --expiring-batch-secs <SECS>
          Batch size for signing transactions when using expiring nonces.

  -h, --help
          Print help (see a summary with '-h')
```

**Examples:**

Run 15 second benchmark with 20k TPS:

```bash
tempo-bench run-max-tps --duration 15 --tps 20000
```

Run benchmark on MacOS:

```bash
tempo-bench run-max-tps --duration 15 --tps 20000 --disable-thread-pinning
```

Run benchmark with more accounts than the default:

```bash
tempo-bench run-max-tps --duration 15 --tps 1000 -a 1000
```

Run benchmark against more than one node:

```bash
tempo-bench run-max-tps --duration 15 --tps 20000 --target-urls http://node-1:8545 --target-urls http://node-2:8545
```

### Scenarios & Load Profiles

tempo-bench supports **multi-phase load profiles** — each run can ramp up, sustain,
spike, crash, and recover over arbitrary time windows.

#### Built-in scenarios (`--scenario`)

Use `--scenario` to run a predefined profile. Scenario defaults (accounts, weights,
concurrency) can be overridden with individual flags.

| Scenario | Profile | Description |
|---|---|---|
| `sustained-max` | 10k TPS × 5 min | Sustained load. Tests txpool backlog and drain. |
| `mixed-workload` | 5k TPS × 5 min | 80% TIP-20 / 15% MPP / 5% ERC-20. |
| `burst-spike` | 0→10k→25k→1k→5k | Multi-phase ramp/spike/recovery over 10 min. |
| `fat-batch` | 100 TPS × 2 min | Placeholder for future fat-batch txs. |
| `state-heavy` | 5k TPS × 2 min | Cold SSTOREs via random new recipients. |
| `txpool-flood` | 50k TPS × 60s | Tests memory limits and OOM resilience. |
| `conflicting` | 5k TPS × 2 min | Existing recipients. Placeholder for hot-spot. |
| `rpc-saturation` | 10k TPS × 5 min | 500 concurrent requests. |
| `full-stress-cycle` | 0→2k→10k→25k→1k→10k→0 | ~58 min full stress cycle. |

```bash
# Run the full stress cycle
tempo-bench run-max-tps --scenario full-stress-cycle --target-urls https://rpc.tempo.xyz --faucet

# Simple constant-TPS run (backwards compatible)
tempo-bench run-max-tps --tps 10000 --duration 300 --target-urls https://rpc.tempo.xyz --faucet
```

#### Custom profiles (`--profile`)

Define your own multi-phase profile in YAML:

```yaml
# my-profile.yaml
phases:
  - name: warm-up
    target_tps: 2000
    duration: 120
    ramp: true        # linear ramp from previous phase (or 0)

  - name: sustain
    target_tps: 5000
    duration: 600     # duration in seconds

  - name: spike
    target_tps: 15000
    duration: 30
    ramp: true

  - name: recover
    target_tps: 2000
    duration: 300
    ramp: true
```

```bash
tempo-bench run-max-tps --profile my-profile.yaml --target-urls https://rpc.tempo.xyz --faucet
```

See `profiles/` for example profiles.

#### Burst spikes

Any phase can overlay periodic burst spikes on top of its base TPS:

```yaml
- name: spikey-baseline
  target_tps: 3000         # base TPS between bursts
  duration: 300
  burst:
    tps: 20000             # spike to 20k during burst
    duration: 5            # each burst lasts 5 seconds
    interval: 30           # burst every 30 seconds
```

This produces a square-wave pattern: 25 seconds at 3k TPS, then 5 seconds at
20k TPS, repeating. Useful for simulating bursty real-world traffic patterns
without needing dozens of micro-phases.

#### Multi-RPC saturation

When multiple `--target-urls` are provided, each RPC gets its own independent
concurrency budget of `--max-concurrent-requests`. Load is distributed via
round-robin, so 3 RPCs with `--max-concurrent-requests 200` = 600 total
concurrent connections (200 per RPC).

```bash
# Saturate 3 RPCs independently with 200 concurrent requests each
tempo-bench run-max-tps --scenario sustained-max \
  --target-urls http://node-1:8545 \
  --target-urls http://node-2:8545 \
  --target-urls http://node-3:8545 \
  --max-concurrent-requests 200 --faucet
```

#### How it works

The load profile controls **TPS over time**. For ramp phases, TPS is linearly
interpolated between the previous phase's end TPS and the target TPS. A
credit-based pacer dispatches transactions at the target rate with 50ms
granularity. The transaction mix (weights) stays constant across phases.

## Quick Start

### 1. Generate genesis.json

```bash
cargo x generate-genesis --accounts 50000 --output genesis.json
```

### 2. Start the Node

```bash
just localnet 50000
```

### 3. Run max TPS benchmark

```bash
tempo-bench run-max-tps --duration 15 --tps 20000 --faucet
```

### Sampling
Use the following commands to run the node with [sampling](https://github.com/mstange/samply):
```bash
	samply record --output tempo.samply -- just localnet 50000
```
