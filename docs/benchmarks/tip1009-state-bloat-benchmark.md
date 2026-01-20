# TIP-1009 Expiring Nonces: State Bloat Benchmark Report

## Benchmark Environment

| Parameter | Value |
|-----------|-------|
| Host | reth5 (ubuntu) |
| Branch | `tanishk/state-bloat-benchmarks` |
| Build Profile | release (jemalloc, asm-keccak) |
| Node Mode | dev (single node, 1s block time) |
| Gas Limit | 3,000,000,000 |
| Date | 2026-01-20 |

## Benchmark Configuration

| Parameter | Value |
|-----------|-------|
| Target TPS | 5,000 |
| Duration | 20 seconds |
| Total Transactions | 100,000 |
| Accounts | 500 |
| Transaction Type | TIP-20 transfers |
| Expiry Window | 25 seconds (protocol max: 30s) |

## Benchmark Procedure

1. Clean data directory (`~/tempo/localnet/reth`)
2. Start fresh dev node with genesis state
3. Fund 500 accounts via faucet
4. Generate and sign 100k TIP-20 transfer transactions
5. Send transactions at 5,000 TPS rate limit
6. Wait for all receipts
7. Measure final DB size with `du -sb`
8. Repeat for both nonce types

## Results (100k Transactions)

| Metric | 2D Nonces | Expiring Nonces | Difference |
|--------|-----------|-----------------|------------|
| Final DB Size | 4,141.66 MB | 4,131.48 MB | -10.17 MB |
| Success Rate | 100% | 100% | - |
| Per-TX Nonce Overhead | ~100 bytes | ~0 bytes | -100 bytes |

## Per-Transaction Savings

| Metric | Value |
|--------|-------|
| Measured savings | ~100 bytes/tx |
| Savings for 100k txs | 10.17 MB |
| Savings per 1M txs | ~100 MB |

### Storage Breakdown

Each 2D nonce entry stores:
- **Slot key**: 32 bytes (keccak256 of address + nonce_key)
- **Slot value**: 8 bytes (u64 nonce)
- **Raw total**: 40 bytes

Measured overhead (~100 bytes) includes:
- Merkle Patricia Trie node overhead (branch/extension/leaf nodes)
- MDBX database key-value pair metadata
- RLP encoding overhead

## Time-Based Scaling (at 5,000 TPS)

| Time Period | Transactions | State Savings |
|-------------|--------------|---------------|
| 1 second | 5,000 | 500 KB |
| 1 minute | 300,000 | 30 MB |
| 1 hour | 18 million | 1.8 GB |
| 1 day | 432 million | 43 GB |
| 1 week | 3 billion | 300 GB |
| 1 month | 13 billion | 1.3 TB |
| 1 year | 158 billion | 15.8 TB |

## TPS-Based Scaling (per year)

| TPS | Daily Savings | Monthly Savings | Yearly Savings |
|-----|---------------|-----------------|----------------|
| 5,000 | 43 GB | 1.3 TB | 15.8 TB |
| 10,000 | 86 GB | 2.6 TB | 31.5 TB |
| 50,000 | 430 GB | 13 TB | 158 TB |

## Scaling Formula

```
State Savings (bytes) = TPS × 100 × time_in_seconds
```

## Key Findings

1. **Expiring nonces eliminate per-transaction nonce storage** (~100 bytes/tx saved)
2. **No transaction failures** with 25-second expiry window
3. **Linear scaling** - savings grow proportionally with transaction volume
4. **Significant long-term impact** - 1.3 TB/month at 5k TPS, 13 TB/month at 50k TPS

## How to Reproduce

### Prerequisites

- Rust toolchain with nightly features
- [Nushell](https://www.nushell.sh/) (`nu`) for running `tempo.nu` scripts
- Access to a machine with sufficient resources (recommended: 8+ cores, 32GB+ RAM)

### Option 1: Using the Benchmark Script

The benchmark script automates running both tests and comparing results:

```bash
# SSH into the benchmark machine
ssh ubuntu@reth5

# Ensure you're on the correct branch
cd ~/tempo
git checkout tanishk/state-bloat-benchmarks
git pull

# Rebuild the binaries (important after code changes)
source ~/.cargo/env
cargo build --release --features jemalloc,asm-keccak --bin tempo --bin tempo-bench

# Run the full benchmark
bash ~/run_state_bloat_bench.sh 2>&1 | tee ~/bench_results.log
```

The script will:
1. Run 2D nonces benchmark → measure DB size
2. Clean state and run expiring nonces benchmark → measure DB size
3. Output comparison summary

### Option 2: Manual Benchmarking with tempo.nu

```bash
cd ~/tempo

# Build binaries
cargo build --release --features jemalloc,asm-keccak --bin tempo --bin tempo-bench

# Clean any previous state
rm -rf localnet/reth

# Run 2D nonces benchmark (default)
nu tempo.nu bench --mode dev --preset tip20 --duration 20 --tps 5000 --accounts 500 --profile release

# Measure DB size
du -sb localnet/reth

# Clean state for next test
pkill -f tempo
rm -rf localnet/reth

# Run expiring nonces benchmark (TIP-1009)
nu tempo.nu bench --mode dev --preset tip20 --duration 20 --tps 5000 --accounts 500 --profile release --bench-args "--expiring-nonces"

# Measure DB size
du -sb localnet/reth
```

### Option 3: Direct tempo-bench CLI

For more control, use `tempo-bench` directly:

```bash
# Start a dev node first
./target/release/tempo node \
  --chain localnet/genesis.json \
  --datadir localnet/reth \
  --http --http.addr 0.0.0.0 --http.port 8545 --http.api all \
  --dev --dev.block-time 1sec \
  --builder.gaslimit 3000000000 \
  --faucet.enabled \
  --faucet.private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# In another terminal, run the benchmark

# 2D nonces (default random nonce keys)
./target/release/tempo-bench run-max-tps \
  --tps 5000 \
  --duration 20 \
  --accounts 500 \
  --target-urls http://localhost:8545 \
  --faucet \
  --clear-txpool \
  --tip20-weight 1.0

# Expiring nonces (TIP-1009)
./target/release/tempo-bench run-max-tps \
  --tps 5000 \
  --duration 20 \
  --accounts 500 \
  --target-urls http://localhost:8545 \
  --faucet \
  --clear-txpool \
  --tip20-weight 1.0 \
  --expiring-nonces
```

### Benchmark Parameters

| Parameter | Flag | Description |
|-----------|------|-------------|
| TPS | `--tps` | Target transactions per second |
| Duration | `--duration` | Test duration in seconds (keep ≤20s for expiring nonces) |
| Accounts | `--accounts` | Number of sender accounts to use |
| Expiring | `--expiring-nonces` | Use expiring nonces instead of 2D nonces |

**Important**: For expiring nonces, keep `--duration` ≤ 20 seconds. The expiry window is 25 seconds, and transactions are signed before sending, so longer durations may cause transactions to expire before inclusion.

### Interpreting Results

After each benchmark:

1. **Check success rate**: Look for `Finished sending transactions success=X failed=0`
2. **Measure DB size**: `du -sb localnet/reth` or `du -h localnet/reth`
3. **Compare sizes**: The difference represents nonce storage overhead

Expected results for 100k transactions:
- 2D nonces: ~4,142 MB
- Expiring nonces: ~4,131 MB
- Difference: ~10 MB (~100 bytes/tx)

## Implementation Details

The `ExpiringNonceFiller` in `crates/alloy/src/fillers/nonce.rs` sets:
- `nonce_key = U256::MAX` (TEMPO_EXPIRING_NONCE_KEY)
- `nonce = 0`
- `valid_before = current_time + 25 seconds`

This triggers the circular buffer replay protection path instead of 2D nonce storage.

## Benchmark Script Source

The benchmark script used on reth5 (`~/run_state_bloat_bench.sh`):

```bash
#!/bin/bash
set -e
cd ~/tempo
source ~/.cargo/env

# Configuration - use same duration and tx count for fair comparison
DURATION=20
TPS=5000
ACCOUNTS=500
DATA_DIR=~/tempo/localnet/reth

echo "=== State Bloat Benchmark (Fair Comparison) ==="
echo "Duration: ${DURATION}s, TPS: ${TPS}, Accounts: ${ACCOUNTS}"
echo "Expected transactions: $((DURATION * TPS))"

get_db_size() {
    if [ -d "$DATA_DIR" ]; then
        du -sb $DATA_DIR 2>/dev/null | cut -f1
    else
        echo "0"
    fi
}

# Clean any previous runs
pkill -f "tempo" 2>/dev/null || true
sleep 3

echo ""
echo "========================================"
echo "BENCHMARK 1: 2D NONCES (default)"
echo "========================================"
rm -rf $DATA_DIR

nu tempo.nu bench --mode dev --preset tip20 --duration $DURATION --tps $TPS \
  --accounts $ACCOUNTS --profile release 2>&1 | tee bench_2d_nu.log

sleep 3
FINAL_SIZE_2D=$(get_db_size)
echo "Final DB size (2D): $FINAL_SIZE_2D bytes ($(echo "scale=2; $FINAL_SIZE_2D/1024/1024" | bc) MB)"

pkill -f "tempo" 2>/dev/null || true
sleep 5
rm -rf $DATA_DIR

echo ""
echo "========================================"
echo "BENCHMARK 2: EXPIRING NONCES (TIP-1009)"
echo "========================================"

nu tempo.nu bench --mode dev --preset tip20 --duration $DURATION --tps $TPS \
  --accounts $ACCOUNTS --profile release --bench-args "--expiring-nonces" 2>&1 | tee bench_exp_nu.log

sleep 3
FINAL_SIZE_EXP=$(get_db_size)
echo "Final DB size (Expiring): $FINAL_SIZE_EXP bytes ($(echo "scale=2; $FINAL_SIZE_EXP/1024/1024" | bc) MB)"

pkill -f "tempo" 2>/dev/null || true

echo ""
echo "========================================"
echo "RESULTS SUMMARY"
echo "========================================"
TX_COUNT=$((DURATION * TPS))
echo "Both tests: $TX_COUNT transactions"
echo ""
echo "2D Nonces:       $FINAL_SIZE_2D bytes ($(echo "scale=2; $FINAL_SIZE_2D/1024/1024" | bc) MB)"
echo "Expiring Nonces: $FINAL_SIZE_EXP bytes ($(echo "scale=2; $FINAL_SIZE_EXP/1024/1024" | bc) MB)"
echo ""

DIFF=$((FINAL_SIZE_2D - FINAL_SIZE_EXP))
DIFF_MB=$(echo "scale=2; $DIFF/1024/1024" | bc)
echo "State Savings: $DIFF bytes ($DIFF_MB MB)"
echo "Per-TX Savings: $(echo "scale=2; $DIFF / $TX_COUNT" | bc) bytes"
echo ""
echo "Benchmark complete!"
```
