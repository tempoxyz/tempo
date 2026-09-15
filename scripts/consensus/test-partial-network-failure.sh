#!/bin/bash

# Test validator recovery scenario
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source test utilities
source "$SCRIPT_DIR/test-utils.sh"

tx_gen_pid=""
cleanup_tx_generator() {
  if [[ "$tx_gen_pid" =~ ^[0-9]+$ ]]; then
    stop_tx_generator "$tx_gen_pid" || true
    tx_gen_pid=""
  fi
}
trap cleanup_tx_generator EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "=== Partial Network Failure Test ==="

# Main test
main() {
  local rpc_url="http://localhost:8545"

  # Start the network and wait for it to be ready
  start_network "$SCRIPT_DIR"
  echo ""

  # Wait for network to be ready and producing blocks
  if ! wait_for_network_ready "$rpc_url" 30 3; then
    echo "Test FAILED: Network failed to start properly"
    exit 1
  fi
  echo ""

  # Start transaction generator (perpetually)
  start_tx_generator tx_gen_pid 999999 "$SCRIPT_DIR"
  echo ""

  # Stop one validator (validator-2)
  echo "Stopping one validator..."
  stop_validator 2
  echo ""

  # Check blocks still being produced
  echo "Checking block production with one validator down..."
  if ! monitor_blocks "$rpc_url" 5 "  Monitoring for 5 seconds:"; then
    echo "Test FAILED: Network should continue producing blocks with one validator down"
    cleanup_tx_generator
    exit 1
  fi
  echo ""

  # Stop transaction generator and check for failures
  if ! stop_tx_generator "$tx_gen_pid"; then
    tx_gen_pid=""
    echo "Test FAILED: Transaction generator encountered failures"
    exit 1
  fi
  tx_gen_pid=""
  echo ""

  echo "Test PASSED: Validator recovery working correctly"
  echo ""

  # Stop the network
  stop_network "$SCRIPT_DIR"
}

# Run the test
main "$@"
