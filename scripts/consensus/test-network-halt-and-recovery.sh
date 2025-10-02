#!/bin/bash

# Test network halt and recovery scenario
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source test utilities
source "$SCRIPT_DIR/test-utils.sh"

echo "=== Network Halt and Recovery Test ==="

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
    stop_tx_generator "$tx_gen_pid" || true
    exit 1
  fi
  echo ""

  # Wait for tx generator to complete naturally
  echo "Waiting for transaction generator to complete..."
  wait "$tx_gen_pid" 2>/dev/null || true
  echo "  Transaction generator completed"
  echo ""

  # Halt 2 nodes (majority failure)
  echo "Halting 2 validators (majority failure)..."
  stop_validator 1
  stop_validator 2
  echo ""

  # Confirm blocks do not progress
  echo "Confirming network has halted..."
  if monitor_blocks "$rpc_url" 5 "  Monitoring for 5 seconds:"; then
    echo "Test FAILED: Network should be halted with majority validators down"
    exit 1
  else
    echo "   Network correctly halted"
  fi
  echo ""

  # Start nodes back up
  echo "Starting validators back up..."
  start_validator 1
  start_validator 2
  echo ""

  # Wait for recovery
  echo "Waiting 10 seconds for network recovery..."
  sleep 10
  echo ""

  # Start transaction generator and assert block production
  tx_gen_pid=$(start_tx_generator 10 "$SCRIPT_DIR")
  echo ""

  echo "Checking block production after recovery..."
  if ! monitor_blocks "$rpc_url" 5 "  Monitoring for 5 seconds:"; then
    echo "Test FAILED: Network should resume block production after recovery"
    stop_tx_generator "$tx_gen_pid" || true
    exit 1
  fi
  echo ""

  # Wait for tx generator to complete naturally
  echo "Waiting for transaction generator to complete..."
  wait "$tx_gen_pid" 2>/dev/null || true
  echo "  Transaction generator completed"
  echo ""

  echo "Test PASSED: Network halt and recovery working correctly"
  echo ""

  # Stop the network
  stop_network "$SCRIPT_DIR"
}

# Run the test
main "$@"
