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

      --disable-2d-nonces
          Disable 2D nonces

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

Run benchmark with less workers than the default:

```bash
tempo-bench run-max-tps --duration 15 --tps 20 -w 1
```

Run benchmark with more accounts than the default:

```bash
tempo-bench run-max-tps --duration 15 --tps 1000 -a 1000
```

Run benchmark against more than one node:

```bash
tempo-bench run-max-tps --duration 15 --tps 20000 --target-urls http://node-1:8545 --target-urls http://node-2:8545
```

The benchmark will continuously output performance metrics including transaction generation rates, network throughput, queue lengths, and response times. As the total transaction count increases, the rate limiter will automatically scale up according to your configured thresholds.

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
