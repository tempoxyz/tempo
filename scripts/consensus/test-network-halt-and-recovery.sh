#!/bin/bash

# Test network halt and recovery scenario
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Network Halt and Recovery Test ==="

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

# Function to start transaction generator
start_tx_generator() {
  local duration="${1:-10}"
  echo "Starting transaction generator (${duration}s)..."
  "$SCRIPT_DIR/tx-generator.sh" --duration "$duration" >/dev/null 2>&1 &
  local tx_gen_pid=$!
  echo "  Transaction generator started (PID: $tx_gen_pid)"
  echo "$tx_gen_pid"
}

# Function to stop transaction generator
stop_tx_generator() {
  local tx_gen_pid="$1"
  echo "Stopping transaction generator..."
  if kill -0 "$tx_gen_pid" 2>/dev/null; then
    kill "$tx_gen_pid" 2>/dev/null || true
    wait "$tx_gen_pid" 2>/dev/null
    local exit_code=$?
    echo "  Transaction generator stopped"
    if [ $exit_code -ne 0 ] && [ $exit_code -ne 143 ]; then  # 143 is SIGTERM
      echo "  ERROR: Transaction generator failed with exit code $exit_code"
      return 1
    fi
  else
    echo "  Transaction generator already stopped"
    echo "  ERROR: Transaction generator exited unexpectedly"
    return 1
  fi
  return 0
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
  echo "Waiting 20 seconds for network recovery..."
  sleep 20
  echo ""

  # Start transaction generator and assert block production
  tx_gen_pid=$(start_tx_generator 10)
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
  echo "Stopping network..."
  "$SCRIPT_DIR/stop-network.sh"
}

# Run the test
main "$@"