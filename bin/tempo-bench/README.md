# `tempo-bench`

`tempo-bench` is benchmarking suite for Tempo node components.

## Installation

Install `tempo-bench`

```bash
cargo install --path bin/tempo-bench --profile maxperf
```

## Commands

### Overview

```
Usage: tempo-bench <COMMAND>

Commands:
  crescendo         Run Crescendo benchmarking
  generate-genesis  Generate genesis allocation file for testing
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### generate-genesis - Create Test Accounts

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

### crescendo - Run Load Tests

Execute high throughput tx load testing:

```
Usage: tempo-bench crescendo --config <CONFIG>

Options:
  -c, --config <CONFIG>  Path to the configuration file
  -h, --help             Print help
```

**Examples:**

```bash
# Run with default balanced configuration
tempo-bench crescendo --config configs/default.toml

# Run with aggressive high-throughput settings
tempo-bench crescendo --config configs/aggressive.toml

# Run with maximum stress test settings
tempo-bench crescendo --config configs/max.toml
```

## Configuration

Crescendo uses TOML configuration files located in `crescendo/configs/`. You can either run with a preconfigured TOML or create your own.

- `default.toml` - Balanced settings for general benchmarking
- `aggressive.toml` - High-performance settings for maximum throughput
- `max.toml` - Extreme settings for stress testing

### Network settings

```toml
[network_worker]
target_url = "http://127.0.0.1:8545"  # RPC endpoint to benchmark
total_connections = 10_000            # Total connections across all network workers
batch_factor = 1                      # Max transactions per JSON-RPC batch request
error_sleep_ms = 100                  # Sleep duration after network errors
tx_queue_empty_sleep_ms = 25          # Sleep when transaction queue is empty
```

### Transaction generation

```toml
[tx_gen_worker]
chain_id = 1337
mnemonic = "test test test test test test test test test test test junk"
num_accounts = 25_000                 # Must not exceed genesis allocation
gas_price = 100000000000              # 100 gwei
gas_limit = 100_000
token_contract_address = "0x2000000000000000000000000000000000000001"
recipient_distribution_factor = 20    # 1/20 of accounts receive transfers
max_transfer_amount = 10              # Maximum token transfer amount
batch_size = 1_000                    # Txs to generate before pushing to queue
```

### Rate limiting

```toml
[rate_limiting]
initial_ratelimit = 100  # Starting transactions per second
ratelimit_thresholds = [
    [1_562, 250],     # After 1,562 total txs, scale to 250 TPS
    [3_125, 500],     # After 3,125 total txs, scale to 500 TPS
    [25_000, 1_000],  # After 25,000 total txs, scale to 1,000 TPS
    # ... additional thresholds for higher loads
]
```

### Worker allocation

```toml
[workers]
thread_pinning = true
tx_gen_worker_percentage = 0.1        # 10% of cores for transaction generation
network_worker_percentage = 0.9       # 90% of cores for network I/O
```

### Example Output

```
[~] Loading config from crescendo/configs/default.toml...
[*] Detected 8 effective cores.
[+] Spawning 7 workers:
- TxGen: 1 (core 0)
- Network: 6 (cores 1-6)
[*] Connections per network worker: 1666
[*] Starting workers...
[*] Starting reporters...
[*] TxQueue +/s: 1,000, -/s: 250, Δ/s: 750, Length: 15,234, Rate limit: 250/s
[*] NetworkStats - Pending: 156, Success: 1,245, Errors: 0, Avg Response: 45ms
```

The benchmark will continuously output performance metrics including transaction generation rates, network throughput, queue lengths, and response times. As the total transaction count increases, the rate limiter will automatically scale up according to your configured thresholds.

## Quick Start

### 1. Generate genesis.json

```bash
tempo-bench generate-genesis --accounts 50000 --output genesis.json
```

### 2. Start Tempo

```bash
just start-tempo <path_to_genesis_json>
```

### 3. Run crescendo

```bash
tempo-bench crescendo --config configs/default.toml
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
