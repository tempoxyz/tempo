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
  generate-genesis  Generate genesis allocation file for testing
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Commands

### `generate-genesis`

Generate pre-funded test accounts for benchmarking:

```
Usage: tempo-bench generate-genesis [OPTIONS]

Options:
  -a, --accounts <ACCOUNTS>  Number of accounts to generate [default: 50000]
  -o, --output <OUTPUT>      Output file path [default: genesis.json]
  -m, --mnemonic <MNEMONIC>  Mnemonic to use for account generation [default: "test test test test test test test test test test test junk"]
  -b, --balance <BALANCE>    Balance for each account (in hex) [default: 0xD3C21BCECCEDA1000000]
  -h, --help                 Print help
```

**Examples:**

```bash
# Generate 50,000 accounts with default settings
tempo-bench generate-genesis

# Generate 25,000 accounts with custom output file
tempo-bench generate-genesis --accounts 25000 --output test-genesis.json

# Generate accounts with custom balance (1M ETH in hex)
tempo-bench generate-genesis --balance 0xD3C21BCECCEDA1000000
```

### `run-max-tps`

High throughput tx load testing

```
Usage: tempo-bench run-max-tps [OPTIONS] --tps <TPS>

Options:
  -t, --tps <TPS>
          Target transactions per second
  -d, --duration <DURATION>
          Test duration in seconds [default: 30]
  -a, --accounts <ACCOUNTS>
          Number of accounts for pre-generation [default: 100]
  -w, --workers <WORKERS>
          Number of workers to send transactions [default: 10]
  -m, --mnemonic <MNEMONIC>
          Mnemonic for generating accounts [default: "test test test test test test test test test test test junk"]
      --chain-id <CHAIN_ID>
          Chain ID [default: 1337]
      --token-address <TOKEN_ADDRESS>
          Token address used when creating TIP20 transfer calldata [default: 0x20c0000000000000000000000000000000000000]
      --target-urls <TARGET_URLS>
          Target URLs for network connections [default: http://localhost:8545]
      --total-connections <TOTAL_CONNECTIONS>
          Total network connections [default: 100]
      --disable-thread-pinning
          Disable binding worker threads to specific CPU cores, letting the OS scheduler handle placement
      --fd-limit <FD_LIMIT>
          File descriptor limit to set
  -h, --help
          Print help
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
tempo-bench generate-genesis --accounts 50000 --output genesis.json
```

### 2. Start the Node

```bash
  tempo node \
    --http \
    --http.addr 0.0.0.0 \
    --http.port 8545 \
    --http.api all \
    --datadir ./data \
    --dev \
    --dev.block-time 1s \
    --chain genesis.json \
    --engine.disable-precompile-cache \
    --engine.legacy-state-root \
    --builder.gaslimit 3000000000 \
    --builder.max-tasks 8 \
    --builder.deadline 4 \
    --txpool.pending-max-count 10000000000000 \
    --txpool.basefee-max-count 10000000000000 \
    --txpool.queued-max-count 10000000000000 \
    --txpool.pending-max-size 10000 \
    --txpool.basefee-max-size 10000 \
    --txpool.queued-max-size 10000 \
    --txpool.max-new-pending-txs-notifications 10000000 \
    --txpool.max-account-slots 500000 \
    --txpool.max-pending-txns 10000000000000 \
    --txpool.max-new-txns 10000000000000 \
    --txpool.disable-transactions-backup \
    --txpool.additional-validation-tasks 8 \
    --txpool.minimal-protocol-fee 0 \
    --txpool.minimum-priority-fee 0 \
    --rpc.max-connections 429496729 \
    --rpc.max-request-size 1000000 \
    --rpc.max-response-size 1000000 \
    --max-tx-reqs 1000000
```

### 3. Run max TPS benchmark

```bash
tempo-bench run-max-tps --duration 15 --tps 20000
```

For the most accurate results, make sure to clear the datadir after each run.

```bash
# Linux (default: $XDG_DATA_HOME/reth/ or $HOME/.local/share/reth/)
rm -rf $HOME/.local/share/reth/

# macOS (default: $HOME/Library/Application Support/reth/)
rm -rf "$HOME/Library/Application Support/reth/"

# Windows (default: %APPDATA%/reth/)
rmdir /s "%APPDATA%\reth"
```




### Sampling
Use the following commands to run the node with [sampling](https://github.com/mstange/samply):
```bash
	samply record --output tempo.samply -- tempo node \
    --http \
    --http.addr 0.0.0.0 \
    --http.port 8545 \
    --http.api all \
    --datadir ./data \
    --dev \
    --dev.block-time 1s \
    --chain genesis.json \
    --engine.disable-precompile-cache \
    --engine.legacy-state-root \
    --builder.gaslimit 3000000000 \
    --builder.max-tasks 8 \
    --builder.deadline 4 \
    --txpool.pending-max-count 10000000000000 \
    --txpool.basefee-max-count 10000000000000 \
    --txpool.queued-max-count 10000000000000 \
    --txpool.pending-max-size 10000 \
    --txpool.basefee-max-size 10000 \
    --txpool.queued-max-size 10000 \
    --txpool.max-new-pending-txs-notifications 10000000 \
    --txpool.max-account-slots 500000 \
    --txpool.max-pending-txns 10000000000000 \
    --txpool.max-new-txns 10000000000000 \
    --txpool.disable-transactions-backup \
    --txpool.additional-validation-tasks 8 \
    --txpool.minimal-protocol-fee 0 \
    --txpool.minimum-priority-fee 0 \
    --rpc.max-connections 429496729 \
    --rpc.max-request-size 1000000 \
    --rpc.max-response-size 1000000 \
    --max-tx-reqs 1000000
```
