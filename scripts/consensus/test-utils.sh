#!/bin/bash

# Shared test utilities for consensus network tests

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

# Function to start background transaction generation
start_tx_generator() {
  local output_var="$1"
  local duration="${2:-999999}"
  local script_dir="${3:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

  echo "Starting transaction generator..."
  "$script_dir/tx-generator.sh" --duration "$duration" >/dev/null 2>&1 &
  printf -v "$output_var" '%s' "$!"
  echo "  Transaction generator started (PID: ${!output_var})"
}

# Function to stop transaction generator
stop_tx_generator() {
  local tx_gen_pid="$1"

  if [[ ! "$tx_gen_pid" =~ ^[0-9]+$ ]]; then
    echo "  ERROR: Invalid transaction generator PID: $tx_gen_pid"
    return 1
  fi

  local was_running=false
  if kill -0 "$tx_gen_pid" 2>/dev/null; then
    was_running=true
    echo "Stopping transaction generator..."
    kill "$tx_gen_pid" 2>/dev/null || true
  fi

  local exit_code=0
  wait "$tx_gen_pid" 2>/dev/null || exit_code=$?

  if $was_running; then
    echo "  Transaction generator stopped"
  fi

  if [ $exit_code -ne 0 ] && [ $exit_code -ne 143 ]; then # 143 is SIGTERM
    echo "  ERROR: Transaction generator failed with exit code $exit_code"
    return 1
  fi

  return 0
}

# Function to start the consensus network
start_network() {
  local script_dir="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
  echo "Starting consensus network..."
  "$script_dir/start-network.sh"
}

# Function to stop the consensus network
stop_network() {
  local script_dir="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
  echo "Stopping network..."
  "$script_dir/stop-network.sh"
}

# Function to wait for network to be ready and producing blocks
wait_for_network_ready() {
  local rpc_url="${1:-http://localhost:8545}"
  local timeout="${2:-30}"
  local check_interval="${3:-3}"
  
  echo "Waiting for network to be ready..."
  local elapsed=0
  
  while [ $elapsed -lt $timeout ]; do
    if monitor_blocks "$rpc_url" "$check_interval" "  Checking network readiness:"; then
      echo "Network is ready and producing blocks"
      return 0
    fi
    elapsed=$((elapsed + check_interval))
    if [ $elapsed -lt $timeout ]; then
      echo "  Network not ready yet, waiting..."
    fi
  done
  
  echo "  ERROR: Network failed to become ready within ${timeout}s"
  return 1
}