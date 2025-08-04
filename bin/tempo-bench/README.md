# Benchmarking Ethereum networks with `crescendo`

The binary contained in this directory, `crescendo`, is a high-performance tool for load testing Ethereum-compatible networks. It generates and sends large volumes of ERC-20 token transfer transactions to benchmark network throughput and identify performance bottlenecks.

## Installation

Install Reth

```bash
git clone https://github.com/paradigmxyz/reth
cd reth
cargo install --path bin/reth --profile maxperf
```

Install `crescendo`

```bash
cd bin/tempo-bench
cargo install --path crescendo --profile maxperf
```

## Generate test accounts

Before running benchmarks, generate pre-funded accounts for the `genesis.json`

```bash
cargo run --bin generate-genesis-alloc
```

This creates `genesis.json` with 50_000 accounts, each funded with 1_000_000 ETH.

## Running the Benchmarks

Start `reth` with optimized settings

```bash
just start-reth
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

## Running the Benchmarks

Start crescendo with your chosen configuration:

```bash
crescendo <path_to_config> --chain <path_to_genesis.json>
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
