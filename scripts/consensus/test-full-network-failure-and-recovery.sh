#!/bin/bash

# Test full network shutdown and restart scenario
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source test utilities
source "$SCRIPT_DIR/test-utils.sh"

echo "=== Full Network Failure Test ==="

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

# Main test
main() {
  local rpc_url="http://localhost:8545"
  local tx_gen_pid=""

  # Start the network and wait for it to be ready
  start_network "$SCRIPT_DIR"
  echo ""

  # Wait for network to be ready and producing blocks
  if ! wait_for_network_ready "$rpc_url" 30 5; then
    echo "Test FAILED: Network failed to start properly"
    exit 1
  fi
  echo ""

  # Start transaction generator and assert block production
  tx_gen_pid=$(start_tx_generator 10 "$SCRIPT_DIR")
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
  echo "Waiting 10 seconds for full network recovery..."
  sleep 10
  echo ""

  # Start transaction generator and ensure block production comes back up
  tx_gen_pid=$(start_tx_generator 10 "$SCRIPT_DIR")
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
  stop_network "$SCRIPT_DIR"
}

# Run the test
main "$@"
