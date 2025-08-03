#!/bin/bash

# e2e_test.sh - Run end-to-end test to verify chain advances to target block
# Usage: ./e2e_test.sh [num_nodes] [target_block] [timeout_seconds]

set -e

# Default values
NUM_NODES=${1:-3}
TARGET_BLOCK=${2:-100}
TIMEOUT=${3:-900} # 15 minutes default

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTNET_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
log() {
  echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Function to check block height of a node
check_block_height() {
  local port=$1
  local response=$(curl -s -X POST http://127.0.0.1:$port \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo "")

  if [ -n "$response" ] && echo "$response" | grep -q "result"; then
    local block_hex=$(echo "$response" | grep -o '"result":"0x[0-9a-fA-F]*"' | cut -d'"' -f4)
    if [ -n "$block_hex" ]; then
      echo $((16#${block_hex#0x}))
    else
      >&2 echo "DEBUG: Could not extract block hex from result"
      echo 0
    fi
  else
    echo 0
  fi
}

# Start the network
log "Starting $NUM_NODES node network..."
cd "$TESTNET_DIR"
./spawn.sh $NUM_NODES &
SPAWN_PID=$!

# Cleanup function
cleanup() {
  log "Cleaning up..."

  # First, preserve logs before cleanup
  if [ -d "$TESTNET_DIR/logs" ]; then
    log "Preserving logs..."
    cp -r "$TESTNET_DIR/logs" "$TESTNET_DIR/logs.preserved" 2>/dev/null || true
  fi

  if [ -n "$SPAWN_PID" ] && ps -p $SPAWN_PID >/dev/null 2>&1; then
    kill $SPAWN_PID 2>/dev/null || true
    wait $SPAWN_PID 2>/dev/null || true
  fi

  # Clean up but don't remove logs
  if pgrep -f "tempo" >/dev/null; then
    pkill -f "tempo" 2>/dev/null || true
    sleep 2
  fi

  # Restore logs if they were removed
  if [ -d "$TESTNET_DIR/logs.preserved" ] && [ ! -d "$TESTNET_DIR/logs" ]; then
    mv "$TESTNET_DIR/logs.preserved" "$TESTNET_DIR/logs"
  fi
}

trap cleanup EXIT

# Give nodes time to start
log "Waiting 10 seconds for nodes to initialize..."
sleep 10

# Check if nodes actually started
log "Checking if nodes are running..."
for i in $(seq 0 $((NUM_NODES - 1))); do
  if [ -f "$TESTNET_DIR/nodes/node$i/node.pid" ]; then
    PID=$(cat "$TESTNET_DIR/nodes/node$i/node.pid")
    if ps -p $PID >/dev/null 2>&1; then
      log "Node $i is running (PID: $PID)"
    else
      error "Node $i process died immediately"
      if [ -f "$TESTNET_DIR/logs/$i/console.log" ]; then
        echo "Last 50 lines from node $i console log:"
        tail -n 50 "$TESTNET_DIR/logs/$i/console.log"
      fi
    fi
  else
    error "Node $i PID file not found"
  fi
done

# Wait for RPC to be available
log "Waiting for RPC endpoints to become available..."
rpc_timeout=60 # 60 seconds to wait for RPC
rpc_start_time=$(date +%s)
all_rpc_ready=false

while [ "$all_rpc_ready" = false ]; do
  current_time=$(date +%s)
  elapsed=$((current_time - rpc_start_time))

  if [ $elapsed -gt $rpc_timeout ]; then
    error "RPC endpoints did not become available within $rpc_timeout seconds"
    exit 1
  fi

  ready_count=0
  for i in $(seq 0 $((NUM_NODES - 1))); do
    port=$((8545 + i))
    # Test with eth_blockNumber - the same method we'll use later
    response=$(curl -s -X POST http://127.0.0.1:$port \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' 2>/dev/null || echo "")

    if [ -n "$response" ] && echo "$response" | grep -q "result"; then
      ready_count=$((ready_count + 1))
      log "Node $i RPC responding on port $port"
    fi
  done

  if [ $ready_count -eq $NUM_NODES ]; then
    all_rpc_ready=true
    log "All $NUM_NODES RPC endpoints are ready"
  else
    log "RPC ready: $ready_count/$NUM_NODES nodes (waiting...)"
    sleep 2
  fi
done

# Monitor block progression
log "Monitoring block progression (target: block $TARGET_BLOCK, timeout: ${TIMEOUT}s)..."
start_time=$(date +%s)
last_progress_time=$start_time
last_max_height=0

while true; do
  current_time=$(date +%s)
  elapsed=$((current_time - start_time))

  # Check timeout
  if [ $elapsed -gt $TIMEOUT ]; then
    error "Timeout reached after $TIMEOUT seconds"
    exit 1
  fi

  # Check if spawn process is still running
  if ! ps -p $SPAWN_PID >/dev/null 2>&1; then
    error "Network process died unexpectedly"
    # Print last logs from each node
    for i in $(seq 0 $((NUM_NODES - 1))); do
      if [ -f "$TESTNET_DIR/logs/$i/console.log" ]; then
        echo -e "\n${YELLOW}Last logs from node $i:${NC}"
        tail -n 20 "$TESTNET_DIR/logs/$i/console.log"
      fi
    done
    exit 1
  fi

  # Check all nodes
  all_reached=true
  min_height=999999
  max_height=0
  responsive_nodes=0

  for i in $(seq 0 $((NUM_NODES - 1))); do
    port=$((8545 + i))
    height=$(check_block_height $port)

    # Check if we got a valid response (height will be -1 if no response)
    if [ $height -ge 0 ]; then
      responsive_nodes=$((responsive_nodes + 1))
      printf "Node %d: block %3d | " "$i" "$height"

      if [ $height -lt $min_height ]; then
        min_height=$height
      fi
      if [ $height -gt $max_height ]; then
        max_height=$height
      fi

      if [ $height -lt $TARGET_BLOCK ]; then
        all_reached=false
      fi
    else
      printf "Node %d: ${YELLOW}not responding${NC} | " "$i"
      all_reached=false
    fi
  done

  # Check if we're making progress
  if [ $max_height -gt $last_max_height ]; then
    last_progress_time=$current_time
    last_max_height=$max_height
  else
    time_since_progress=$((current_time - last_progress_time))
    if [ $time_since_progress -gt 60 ]; then
      echo ""
      error "No progress for 60 seconds (stuck at block $max_height)"
      exit 1
    fi
  fi

  printf "Min: %d, Max: %d, Responsive: %d/%d\n" "$min_height" "$max_height" "$responsive_nodes" "$NUM_NODES"

  # Check if all nodes reached target
  if [ "$all_reached" = true ] && [ $responsive_nodes -eq $NUM_NODES ]; then
    log "SUCCESS: All nodes reached block $TARGET_BLOCK"

    # Run transaction tests
    log "Running transaction tests..."
    if [ -x "$SCRIPT_DIR/test_transactions.sh" ]; then
      if "$SCRIPT_DIR/test_transactions.sh" $NUM_NODES; then
        log "Transaction tests passed!"
      else
        error "Transaction tests failed!"
        exit 1
      fi
    else
      log "Transaction test script not found or not executable, skipping transaction tests"
    fi

    # Ensure logs directory exists for artifact upload
    if [ ! -d "$TESTNET_DIR/logs" ]; then
      log "Creating empty logs directory for artifact upload"
      mkdir -p "$TESTNET_DIR/logs"
    fi
    exit 0
  fi

  # Require at least one responsive node
  if [ $responsive_nodes -eq 0 ]; then
    error "No nodes are responding to RPC calls"
    # Print diagnostic information
    for i in $(seq 0 $((NUM_NODES - 1))); do
      echo -e "\n${YELLOW}Diagnostic info for node $i:${NC}"
      if [ -f "$TESTNET_DIR/nodes/node$i/node.pid" ]; then
        PID=$(cat "$TESTNET_DIR/nodes/node$i/node.pid")
        if ps -p $PID >/dev/null 2>&1; then
          echo "Process still running (PID: $PID)"
        else
          echo "Process not running"
        fi
      fi
      if [ -f "$TESTNET_DIR/logs/$i/console.log" ]; then
        echo "Last 30 lines of console log:"
        tail -n 30 "$TESTNET_DIR/logs/$i/console.log"
        echo ""
        echo "Checking for RPC server startup:"
        grep -i "rpc.*server.*started" "$TESTNET_DIR/logs/$i/console.log" | tail -5 || echo "No RPC startup messages found"
      else
        echo "No console log found"
      fi
    done
    exit 1
  fi

  sleep 5
done
