#!/bin/bash

# Test validator recovery scenario
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source test utilities
source "$SCRIPT_DIR/test-utils.sh"

echo "=== Partial Network Failure Test ==="

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

  # Start transaction generator (perpetually)
  tx_gen_pid=$(start_tx_generator 999999 "$SCRIPT_DIR")
  echo ""

  # Stop one validator (validator-2)
  echo "Stopping one validator..."
  stop_validator 2
  echo ""

  # Check blocks still being produced
  echo "Checking block production with one validator down..."
  if ! monitor_blocks "$rpc_url" 5 "  Monitoring for 5 seconds:"; then
    echo "Test FAILED: Network should continue producing blocks with one validator down"
    stop_tx_generator "$tx_gen_pid" || true
    exit 1
  fi
  echo ""

  # Restart the validator
  echo "Restarting the validator..."
  start_validator 2
  echo ""

  # Wait for validator to rejoin
  echo "Waiting 3 seconds for validator to rejoin..."
  sleep 3
  echo ""

  # Check blocks still being produced
  echo "Checking block production after validator recovery..."
  if ! monitor_blocks "$rpc_url" 5 "  Monitoring for 5 seconds:"; then
    echo "Test FAILED: Network should continue producing blocks after validator recovery"
    stop_tx_generator "$tx_gen_pid" || true
    exit 1
  fi
  echo ""

  # Stop transaction generator and check for failures
  if ! stop_tx_generator "$tx_gen_pid"; then
    echo "Test FAILED: Transaction generator encountered failures"
    exit 1
  fi
  echo ""

  echo "Test PASSED: Validator recovery working correctly"
  echo ""

  # Stop the network
  stop_network "$SCRIPT_DIR"
}

# Run the test
main "$@"
