# Tempo vs Reth TPS Benchmark Guide

This guide explains how to run a fair TPS comparison between Tempo and Reth nodes.

## Prerequisites

1. Access to a reth dev box (request in #reth-infra if needed)
2. `tempo-bench` built with `--profile maxperf`
3. Both Tempo and Reth running in dev mode on the same machine

## Setup

### 1. Build tempo-bench

```bash
cd /path/to/tempo
cargo install --path bin/tempo-bench --profile maxperf
```

### 2. Start Reth in Dev Mode

```bash
# Start Reth with dev mode (pre-funded accounts, instant sealing)
reth node --dev --dev.block-time 100ms --http --http.port 8546

# Note the mnemonic used by Reth dev mode:
# "test test test test test test test test test test test junk"
```

### 3. Start Tempo in Dev Mode

```bash
# Generate genesis with pre-funded accounts
cargo x generate-genesis --accounts 50000 --output genesis.json

# Start Tempo localnet
just localnet 50000
```

## Running the Benchmark

### Option A: Use the Comparison Script

```bash
# Set environment variables
export TEMPO_RPC="http://localhost:8545"
export RETH_RPC="http://localhost:8546"
export DURATION=60
export TARGET_TPS=10000
export ACCOUNTS=200

# Run comparison
./bin/tempo-bench/scripts/tempo-vs-reth-bench.sh
```

### Option B: Manual Benchmark

**Benchmark Tempo:**
```bash
tempo-bench run-max-tps \
  --target-urls http://localhost:8545 \
  --tps 10000 \
  --duration 60 \
  --accounts 200 \
  --faucet \
  --erc20-weight 1 \
  --tip20-weight 0 \
  > tempo_results.json
```

**Benchmark Reth:**
```bash
# First, fund accounts using Reth dev mode mnemonic
tempo-bench run-max-tps \
  --target-urls http://localhost:8546 \
  --tps 10000 \
  --duration 60 \
  --accounts 200 \
  --reth-mode \
  --mnemonic "test test test test test test test test test test test junk" \
  > reth_results.json
```

## Fair Comparison Notes

1. **Same transaction type**: Both use ERC-20 transfers only (no Tempo-specific TIP-20/DEX)
2. **Same hardware**: Run both on the same machine
3. **Same parameters**: Use identical TPS, duration, and account count
4. **Pre-funded accounts**: Reth dev mode comes with funded accounts; use the dev mnemonic

## Interpreting Results

The JSON output contains:
- `metadata.target_tps`: Requested TPS
- `blocks[].tx_count`: Transactions per block
- `blocks[].ok_count`: Successful transactions
- Actual TPS = sum(tx_count) / duration

Key metrics to compare:
- **Actual TPS achieved**: Higher is better
- **Success rate**: ok_count / tx_count
- **Block latency**: Time between blocks

## Known Limitations

- Reth dev mode uses instant sealing, while Tempo uses consensus
- For production comparison, both should run with realistic block times
- Network conditions vary; run multiple trials and average results
