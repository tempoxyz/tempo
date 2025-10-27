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
cargo x generate-genesis --accounts 50000 --output genesis.json
```

### 2. Start the Node

```bash
just localnet 50000
```

### 3. Run max TPS benchmark

```bash
tempo-bench run-max-tps --duration 15 --tps 20000
```

### Sampling
Use the following commands to run the node with [sampling](https://github.com/mstange/samply):
```bash
	samply record --output tempo.samply -- just localnet 50000
```
