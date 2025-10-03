#!/bin/bash

# Transaction generator for consensus testing
set -euo pipefail

# Configuration
DEFAULT_RPC_URL="http://localhost:8545"
DEFAULT_DURATION=30

usage() {
  echo "Usage: $0 [OPTIONS]"
  echo "Generate transactions for consensus testing"
  echo ""
  echo "Options:"
  echo "  -d, --duration SEC   Duration in seconds (default: $DEFAULT_DURATION)"
  echo "  -h, --help           Show this help"
}

# Function to generate a simple transfer transaction
send_transfer() {
  local rpc_url="$1"
  local from_key="$2"
  local to_addr="$3"
  local value="$4"

  # Use cast to send transaction and get receipt
  local receipt=$(cast send \
    --rpc-url "$rpc_url" \
    --private-key "$from_key" \
    --value "0" \
    "$to_addr" \
    2>/dev/null)

  if [ -n "$receipt" ]; then
    local tx_hash=$(echo "$receipt" | grep "transactionHash" | awk '{print $2}')
    local status=$(echo "$receipt" | grep "status" | awk '{print $2}')
    echo "TX: $tx_hash"
    if [ "$status" = "1" ]; then
      return 0
    else
      echo "  ERROR: Transaction failed"
      return 1
    fi
  else
    echo "ERROR: Failed to send transaction"
    return 1
  fi
}

# Function to generate transactions
generate_transactions() {
  local rpc_urls="$1"
  local duration="$2"

  IFS=',' read -ra URL_ARRAY <<<"$rpc_urls"
  local num_nodes=${#URL_ARRAY[@]}

  echo "Starting transaction generation..."
  echo "  RPC URLs: $rpc_urls"
  echo "  Nodes: $num_nodes"
  echo "  Duration: ${duration}s"
  echo ""

  local from_key="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
  local to_addr=$(cast wallet new | grep "Address:" | awk '{print $2}')

  from_addr=$(cast wallet address --private-key "$from_key")

  echo "From: $from_addr"
  echo "To: $to_addr"
  echo ""

  local tx_count=0
  local start_time=$(date +%s)
  local end_time=$((start_time + duration))

  while [ $(date +%s) -lt $end_time ]; do
    # Rotate through nodes
    local node_index=$((tx_count % num_nodes))
    local current_rpc="${URL_ARRAY[$node_index]}"

    # Send transaction with no value
    if send_transfer "$current_rpc" "$from_key" "$to_addr" ""; then
      tx_count=$((tx_count + 1))
    fi
  done

  echo ""
  echo "Transaction generation completed"
  echo "Total transactions sent: $tx_count"
}

# Parse command line arguments
RPC_URL="$DEFAULT_RPC_URL"
DURATION="$DEFAULT_DURATION"

while [[ $# -gt 0 ]]; do
  case $1 in
  -u | --url)
    RPC_URL="$2"
    shift 2
    ;;
  -d | --duration)
    DURATION="$2"
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "Unknown option: $1"
    usage
    exit 1
    ;;
  esac
done

# Check dependencies
if ! command -v cast >/dev/null 2>&1; then
  echo "Error: 'cast' command not found. Please install foundry."
  exit 1
fi

# Main execution
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  ALL_URLS="http://localhost:8545,http://localhost:8546,http://localhost:8547,http://localhost:8548"
  generate_transactions "$ALL_URLS" "$DURATION"
fi
