#!/bin/bash

# Test full network shutdown and restart scenario
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Full Network Failure Test ==="

# Function to get current block number
get_block_number() {
  local rpc_url="$1"
  curl -s -X POST "$rpc_url" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' |
    jq -r '.result // "0x0"' | xargs printf "%d\n" 2>/dev/null || echo "0"
}

# Function to monitor block production for a specified duration
monitor_blocks() {
  local rpc_url="$1"
  local duration="$2"
  local description="$3"

  echo "$description"

  local start_block=$(get_block_number "$rpc_url")
  echo "  Starting block: $start_block"

  sleep "$duration"

  local end_block=$(get_block_number "$rpc_url")
  echo "  Ending block: $end_block"

  if [ "$end_block" -gt "$start_block" ]; then
    echo "  Blocks produced: $((end_block - start_block))"
    return 0
  else
    echo "  No blocks produced"
    return 1
  fi
}

# Function to check if network is unreachable
check_network_unreachable() {
  local rpc_url="$1"
  echo "Checking network is unreachable..."

  if curl -s -m 2 -X POST "$rpc_url" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' >/dev/null 2>&1; then
    echo "  ERROR: Network is still reachable"
    return 1
  else
    echo "  ✓ Network is unreachable"
    return 0
  fi
}

# Function to stop all validators
stop_all_validators() {
  echo "Stopping ALL validators..."
  for i in {0..3}; do
    echo "  Stopping tempo-validator-$i..."
    docker stop "tempo-validator-$i" >/dev/null 2>&1 || true
  done
  echo "  All validators stopped"
}

# Function to start all validators
start_all_validators() {
  echo "Starting all validators..."
  for i in {0..3}; do
    echo "  Starting tempo-validator-$i..."
    docker start "tempo-validator-$i" >/dev/null 2>&1 || true
  done
  echo "  All validators started"
}

# Function to start transaction generator
start_tx_generator() {
  local duration="${1:-10}"
  echo "Starting transaction generator (${duration}s)..."
  "$SCRIPT_DIR/tx-generator.sh" --duration "$duration" >/dev/null 2>&1 &
  local tx_gen_pid=$!
  echo "  Transaction generator started (PID: $tx_gen_pid)"
  echo "$tx_gen_pid"
}

# Main test
main() {
  local rpc_url="http://localhost:8545"
  local tx_gen_pid=""

  # Start the network
  echo "Starting consensus network..."
  "$SCRIPT_DIR/start-network.sh"
  echo ""

  # Wait for network to produce blocks
  echo "Waiting 3 seconds for network to produce blocks..."
  sleep 3
  echo ""

  # Start transaction generator and assert block production
  tx_gen_pid=$(start_tx_generator 10)
  echo ""

  echo "Checking initial block production with tx generator..."
  if ! monitor_blocks "$rpc_url" 5 "  Monitoring for 5 seconds:"; then
    echo "Test FAILED: Initial block production not working"
    exit 1
  fi
  echo ""

  # Wait for tx generator to complete naturally
  echo "Waiting for transaction generator to complete..."
  wait "$tx_gen_pid" 2>/dev/null || true
  echo "  Transaction generator completed"
  echo ""

  # Kill all nodes
  stop_all_validators
  echo ""

  # Ensure you can't reach the network
  if ! check_network_unreachable "$rpc_url"; then
    echo "Test FAILED: Network should be unreachable with all validators down"
    exit 1
  fi
  echo ""

  # Restart all nodes
  start_all_validators
  echo ""

  # Wait for recovery
  echo "Waiting 20 seconds for full network recovery..."
  sleep 20
  echo ""

  # Start transaction generator and ensure block production comes back up
  tx_gen_pid=$(start_tx_generator 10)
  echo ""

  echo "Checking block production after full restart..."
  if ! monitor_blocks "$rpc_url" 5 "  Monitoring for 5 seconds:"; then
    echo "Test FAILED: Network should resume block production after full restart"
    exit 1
  fi
  echo ""

  # Wait for tx generator to complete naturally
  echo "Waiting for transaction generator to complete..."
  wait "$tx_gen_pid" 2>/dev/null || true
  echo "  Transaction generator completed"
  echo ""

  echo "Test PASSED: Full network restart working correctly"
  echo ""

  # Stop the network
  echo "Stopping network..."
  "$SCRIPT_DIR/stop-network.sh"
}

# Run the test
main "$@"

