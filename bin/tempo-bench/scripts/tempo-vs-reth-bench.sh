#!/bin/bash
set -euo pipefail

# Tempo vs Reth TPS Comparison Script
# Runs tempo-bench against both nodes and generates a comparison report

TEMPO_RPC="${TEMPO_RPC:-http://localhost:8545}"
RETH_RPC="${RETH_RPC:-http://localhost:8546}"
DURATION="${DURATION:-30}"
TARGET_TPS="${TARGET_TPS:-10000}"
ACCOUNTS="${ACCOUNTS:-200}"
RESULTS_DIR="${RESULTS_DIR:-./benchmark-results}"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Benchmark Tempo and Reth nodes and compare TPS performance.

Environment Variables:
  TEMPO_RPC      Tempo node RPC URL (default: http://localhost:8545)
  RETH_RPC       Reth node RPC URL (default: http://localhost:8546)
  DURATION       Test duration in seconds (default: 30)
  TARGET_TPS     Target TPS to attempt (default: 10000)
  ACCOUNTS       Number of accounts to use (default: 200)
  RESULTS_DIR    Output directory (default: ./benchmark-results)

Example:
  TEMPO_RPC=http://tempo:8545 RETH_RPC=http://reth:8545 $0
EOF
    exit 1
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TEMPO_OUT="$RESULTS_DIR/tempo_${TIMESTAMP}.json"
RETH_OUT="$RESULTS_DIR/reth_${TIMESTAMP}.json"
REPORT="$RESULTS_DIR/comparison_${TIMESTAMP}.md"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Tempo vs Reth TPS Benchmark                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║ Tempo RPC:  $TEMPO_RPC"
echo "║ Reth RPC:   $RETH_RPC"
echo "║ Duration:   ${DURATION}s"
echo "║ Target TPS: $TARGET_TPS"
echo "║ Accounts:   $ACCOUNTS"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

run_bench() {
    local name="$1"
    local rpc="$2"
    local output="$3"
    local extra_args="${4:-}"
    
    echo "▶ Benchmarking $name at $rpc..."
    
    if ! tempo-bench run-max-tps \
        --duration "$DURATION" \
        --tps "$TARGET_TPS" \
        --target-urls "$rpc" \
        --accounts "$ACCOUNTS" \
        --benchmark-mode "max_tps" \
        $extra_args \
        > "$output" 2>&1; then
        echo "  ✗ $name benchmark failed"
        cat "$output"
        return 1
    fi
    
    echo "  ✓ $name benchmark complete → $output"
}

extract_metrics() {
    local file="$1"
    local name="$2"
    
    if [[ ! -f "$file" ]]; then
        echo "0 0 0 0 0"
        return
    fi
    
    jq -r '
        .blocks as $blocks |
        ($blocks | map(.tx_count) | add // 0) as $total_tx |
        ($blocks | map(.ok_count) | add // 0) as $ok_tx |
        ($blocks | map(.err_count) | add // 0) as $err_tx |
        ($blocks | map(.gas_used) | add // 0) as $total_gas |
        .metadata.run_duration_secs as $duration |
        ($total_tx / ($duration // 1)) as $actual_tps |
        "\($total_tx) \($ok_tx) \($err_tx) \($total_gas) \($actual_tps | floor)"
    ' "$file" 2>/dev/null || echo "0 0 0 0 0"
}

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Phase 1: Benchmark Tempo"
echo "═══════════════════════════════════════════════════════════════"
# Use ERC-20 only for fair comparison with Reth (no TIP-20/DEX advantage)
run_bench "Tempo" "$TEMPO_RPC" "$TEMPO_OUT" "--faucet --erc20-weight 1 --tip20-weight 0"

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Phase 2: Benchmark Reth"
echo "═══════════════════════════════════════════════════════════════"
# Use --reth-mode which auto-configures for vanilla Ethereum:
# - Disables 2D nonces
# - Forces ERC-20 only transactions
# - Skips Tempo-specific setup
run_bench "Reth" "$RETH_RPC" "$RETH_OUT" "--reth-mode"

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Phase 3: Generate Comparison Report"
echo "═══════════════════════════════════════════════════════════════"

read -r tempo_tx tempo_ok tempo_err tempo_gas tempo_tps <<< "$(extract_metrics "$TEMPO_OUT" "Tempo")"
read -r reth_tx reth_ok reth_err reth_gas reth_tps <<< "$(extract_metrics "$RETH_OUT" "Reth")"

if [[ "$reth_tps" -gt 0 ]]; then
    speedup=$(echo "scale=2; $tempo_tps / $reth_tps" | bc)
    diff_pct=$(echo "scale=1; (($tempo_tps - $reth_tps) / $reth_tps) * 100" | bc)
else
    speedup="N/A"
    diff_pct="N/A"
fi

cat > "$REPORT" <<EOF
# Tempo vs Reth TPS Benchmark Report

**Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")

## Configuration

| Parameter | Value |
|-----------|-------|
| Tempo RPC | \`$TEMPO_RPC\` |
| Reth RPC | \`$RETH_RPC\` |
| Duration | ${DURATION}s |
| Target TPS | $TARGET_TPS |
| Accounts | $ACCOUNTS |

## Results

| Metric | Tempo | Reth | Difference |
|--------|-------|------|------------|
| **Actual TPS** | $tempo_tps | $reth_tps | ${diff_pct}% |
| Total Transactions | $tempo_tx | $reth_tx | - |
| Successful Txs | $tempo_ok | $reth_ok | - |
| Failed Txs | $tempo_err | $reth_err | - |
| Total Gas Used | $tempo_gas | $reth_gas | - |

## Summary

- **Tempo TPS:** $tempo_tps tx/s
- **Reth TPS:** $reth_tps tx/s
- **Speedup:** ${speedup}x

## Raw Data

- Tempo results: \`$TEMPO_OUT\`
- Reth results: \`$RETH_OUT\`
EOF

echo
cat "$REPORT"
echo
echo "═══════════════════════════════════════════════════════════════"
echo "Report saved to: $REPORT"
echo "═══════════════════════════════════════════════════════════════"
