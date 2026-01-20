# TIP-1009 Expiring Nonces: State Bloat Benchmark Report

## Summary

Expiring nonces (TIP-1009) save **~100 bytes per transaction** by avoiding unbounded 2D nonce storage growth. The circular buffer caps nonce storage at 300,000 entries regardless of transaction volume.

## Benchmark Environment

| Parameter | Value |
|-----------|-------|
| Host | reth5 (ubuntu) |
| Branch | `tanishk/state-bloat-benchmarks` |
| Build Profile | release (jemalloc, asm-keccak) |
| Node Mode | dev (single node, 1s block time) |
| Gas Limit | 3,000,000,000 |
| Date | 2026-01-20 |

## Controlled Benchmark (100k Transactions, 20 seconds)

This benchmark uses identical conditions for both nonce types to isolate nonce storage overhead.

### Configuration

| Parameter | Value |
|-----------|-------|
| Target TPS | 5,000 |
| Duration | 20 seconds |
| Total Transactions | 100,000 |
| Accounts | 500 |
| Transaction Type | TIP-20 transfers |
| Expiry Window | 25 seconds (protocol max: 30s) |

### Results

| Metric | 2D Nonces | Expiring Nonces | Difference |
|--------|-----------|-----------------|------------|
| Final DB Size | 4,342.85 MB | 4,332.18 MB | -10.67 MB |
| Transactions | 100,000 | 100,000 | - |
| Success Rate | 100% | 100% | - |

**Per-Transaction Nonce Savings: ~107 bytes**

### Storage Breakdown

Each 2D nonce entry stores:
- **Slot key**: 32 bytes (keccak256 of address + nonce_key)
- **Slot value**: 8 bytes (u64 nonce)
- **Raw total**: 40 bytes

The measured overhead (~100 bytes) includes:
- Merkle Patricia Trie node overhead (branch/extension/leaf nodes)
- MDBX database key-value pair metadata
- RLP encoding overhead

## Extended Benchmark (3M Transactions, 10 minutes)

A longer benchmark was run to observe behavior after the circular buffer fills.

### Results

| Metric | 2D Nonces | Expiring Nonces |
|--------|-----------|-----------------|
| Final DB Size | 9,476.60 MB | 4,755.94 MB |
| Transactions | 3,000,000 | 3,000,000 |
| Blocks | 597 | 361 |
| Success Rate | 100% | 100% |

**Observed Difference: 4,720.66 MB**

### Analysis

The 4.7 GB difference is NOT purely from nonce storage. The tests had different block counts (597 vs 361), which introduces confounding factors:

1. **Nonce-specific savings**: 2.7M entries × 100 bytes = ~270 MB
2. **Block count difference**: 236 extra blocks in 2D test
3. **Per-block overhead**: (4,720 MB - 270 MB) / 236 blocks ≈ 18.9 MB/block

The large per-block overhead suggests the 2D nonces test ran differently (lower tx packing efficiency, more blocks for same tx count).

**Conservative estimate for nonce savings: ~100 bytes per unique nonce entry**

## Scaling Projections

Based on the controlled measurement of ~100 bytes per nonce entry:

### Time-Based Scaling (at 5,000 TPS)

| Time Period | Transactions | Nonce Entries Saved | State Savings |
|-------------|--------------|---------------------|---------------|
| 1 minute | 300,000 | 300,000 | 30 MB |
| 10 minutes | 3,000,000 | 2,700,000* | 270 MB |
| 1 hour | 18,000,000 | 17,700,000* | 1.77 GB |
| 1 day | 432,000,000 | 431,700,000* | 43.2 GB |

*After buffer fills (300k entries), savings = total_txs - 300,000

### TPS-Based Scaling (per day)

| TPS | Transactions/Day | Nonce Savings/Day |
|-----|------------------|-------------------|
| 5,000 | 432M | 43.2 GB |
| 10,000 | 864M | 86.4 GB |
| 50,000 | 4.32B | 432 GB |

### Scaling Formula

```
Nonce Savings (bytes) = (total_transactions - 300,000) × 100
```

After the circular buffer fills (~60 seconds at 5k TPS), expiring nonces maintain constant nonce storage while 2D nonces grow by 100 bytes per transaction.

## Key Findings

1. **~100 bytes saved per unique 2D nonce entry**
2. **Bounded state growth** - circular buffer caps nonce storage at 300,000 entries
3. **No transaction failures** with 25-second expiry window
4. **At 5k TPS**: ~43 GB/day saved, ~1.3 TB/month saved

## How to Reproduce

### Prerequisites

- Rust toolchain with nightly features
- [Nushell](https://www.nushell.sh/) (`nu`) for running `tempo.nu` scripts
- Access to a machine with sufficient resources (recommended: 8+ cores, 32GB+ RAM)

### Running the Controlled Benchmark (Recommended)

```bash
cd ~/tempo

# Build binaries
cargo build --release --features jemalloc,asm-keccak --bin tempo --bin tempo-bench

# Clean any previous state
rm -rf localnet/reth

# Run 2D nonces benchmark (20 seconds)
nu tempo.nu bench --mode dev --preset tip20 --duration 20 --tps 5000 --accounts 500 --profile release

# Record DB size
du -sb localnet/reth

# Clean state
pkill -f tempo
rm -rf localnet/reth

# Run expiring nonces benchmark (20 seconds)
nu tempo.nu bench --mode dev --preset tip20 --duration 20 --tps 5000 --accounts 500 --profile release --bench-args "--expiring-nonces"

# Record DB size
du -sb localnet/reth
```

### Running Extended Benchmarks (10+ minutes)

For expiring nonces with durations longer than 20 seconds, use the `--expiring-nonces` flag which automatically batches transaction signing to avoid expiry:

```bash
# 10-minute benchmark with expiring nonces (batched signing)
nu tempo.nu bench --mode dev --preset tip20 --duration 600 --tps 5000 --accounts 500 --profile release --bench-args "--expiring-nonces"
```

The benchmark will generate/sign/send transactions in 15-second batches to stay within the 25-second expiry window.

### Interpreting Results

1. **Check success rate**: Look for `Finished sending transactions success=X failed=0`
2. **Measure DB size**: `du -sb localnet/reth`
3. **Compare sizes**: Difference ÷ transactions ≈ 100 bytes/tx for nonce storage

## Implementation Details

The `ExpiringNonceFiller` in `crates/alloy/src/fillers/nonce.rs` sets:
- `nonce_key = U256::MAX` (TEMPO_EXPIRING_NONCE_KEY)
- `nonce = 0`
- `valid_before = current_time + 25 seconds`

This triggers the circular buffer replay protection path instead of 2D nonce storage.

### Circular Buffer

- **Capacity**: 300,000 entries (`EXPIRING_NONCE_SET_CAPACITY`)
- **Storage**: `mapping(bytes32 => uint64)` for seen tx hashes
- **Behavior**: Wraps around, overwriting oldest entries when full
- **State size**: Fixed regardless of transaction volume
