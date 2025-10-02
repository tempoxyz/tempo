#!/bin/bash

# Test validator recovery scenario
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Validator Recovery Test ==="

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

# Function to stop a validator
stop_validator() {
  local validator_id="$1"
  echo "Stopping tempo-validator-$validator_id..."
  docker stop "tempo-validator-$validator_id" >/dev/null
  echo "  Stopped tempo-validator-$validator_id"
}

# Function to start a validator
start_validator() {
  local validator_id="$1"
  echo "Starting tempo-validator-$validator_id..."
  docker start "tempo-validator-$validator_id" >/dev/null
  echo "  Started tempo-validator-$validator_id"
}

# Main test
main() {
  local rpc_url="http://localhost:8545"

  # Start the network
  echo "Starting consensus network..."
  "$SCRIPT_DIR/start-network.sh"
  echo ""

  # Wait for network to produce blocks
  echo "Waiting 3 seconds for network to produce blocks..."
  sleep 3
  echo ""

  # Check initial block production
  echo "Checking initial block production..."
  if ! monitor_blocks "$rpc_url" 5 "  Monitoring for 5 seconds:"; then
    echo "Test FAILED: Initial block production not working"
    exit 1
  fi
  echo ""

  # Stop one validator (validator-2)
  echo "Stopping one validator..."
  stop_validator 2
  echo ""

  # Check blocks still being produced
  echo "Checking block production with one validator down..."
  if ! monitor_blocks "$rpc_url" 5 "  Monitoring for 5 seconds:"; then
    echo "Test FAILED: Network should continue producing blocks with one validator down"
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
    exit 1
  fi
  echo ""

  echo "Test PASSED: Validator recovery working correctly"
  echo ""

  # Stop the network
  echo "Stopping network..."
  "$SCRIPT_DIR/stop-network.sh"
}

# Run the test
main "$@"
