#!/bin/bash

# spawn.sh - Launch a test network of tempo nodes
# Usage: ./spawn.sh [num_nodes] [options]

set -e

# Default values
NUM_NODES=${1:-3}
BLOCK_TIME=${BLOCK_TIME:-1s}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NODES_DIR="$SCRIPT_DIR/nodes"
BINARY="$PROJECT_ROOT/target/debug/tempo"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Port bases
CONSENSUS_PORT_BASE=26656
METRICS_PORT_BASE=9000
RETH_PORT_BASE=30303
RETH_RPC_PORT_BASE=8545
AUTH_RPC_PORT_BASE=8551

# Function to print colored output
log() {
  echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

# Kill any tempo processes
kill_reth_processes() {
  if pgrep -f "tempo" >/dev/null; then
    log "Stopping existing tempo processes..."
    pkill -f "tempo" 2>/dev/null || true
    sleep 2 # Give processes time to exit
  fi
}

# Clean up function
cleanup() {
  log "Cleaning up..."

  # Kill any existing tempo processes
  kill_reth_processes

  if [ "$1" == "clean" ]; then
    log "Removing nodes and logs directories..."
    rm -rf "$NODES_DIR"
    rm -rf "$SCRIPT_DIR/logs"
    log "Clean complete"
    exit 0
  fi

  # Kill all child processes
  jobs -p | xargs -r kill 2>/dev/null || true
  wait
  log "All nodes stopped"
}

# Set up trap for cleanup
trap cleanup EXIT INT TERM

# Handle clean command
if [ "$1" == "clean" ]; then
  cleanup clean
fi

# Validate input
if ! [[ "$NUM_NODES" =~ ^[0-9]+$ ]] || [ "$NUM_NODES" -lt 1 ] || [ "$NUM_NODES" -gt 10 ]; then
  error "Number of nodes must be between 1 and 10"
  exit 1
fi

log "Starting $NUM_NODES node test network"

# Check for and kill existing processes
kill_reth_processes

# Build the binary
log "Building tempo..."
cd "$PROJECT_ROOT"
cargo build
if [ ! -f "$BINARY" ]; then
  error "Failed to build tempo binary"
  exit 1
fi

# Clean and create nodes directory
rm -rf "$NODES_DIR"
mkdir -p "$NODES_DIR"

# Create centralized logs directory
LOGS_DIR="$SCRIPT_DIR/logs"
rm -rf "$LOGS_DIR"
mkdir -p "$LOGS_DIR"

# Generate keys for all nodes
log "Generating validator keys..."
"$SCRIPT_DIR/scripts/generate_keys.sh" "$NUM_NODES"

# Generate genesis file
log "Creating genesis configuration..."
"$SCRIPT_DIR/scripts/generate_genesis.sh" "$NUM_NODES"

# Generate node configurations
log "Setting up node configurations..."
for ((i = 0; i < $NUM_NODES; i++)); do
  NODE_DIR="$NODES_DIR/node$i"
  mkdir -p "$NODE_DIR/malachite/config" "$NODE_DIR/malachite/data" "$NODE_DIR/reth"

  # Calculate ports
  CONSENSUS_PORT=$((CONSENSUS_PORT_BASE + i))
  METRICS_PORT=$((METRICS_PORT_BASE + i))
  RETH_PORT=$((RETH_PORT_BASE + i))
  RETH_RPC_PORT=$((RETH_RPC_PORT_BASE + i))

  # Generate peer list (all nodes except self)
  PEERS=""
  for ((j = 0; j < $NUM_NODES; j++)); do
    if [ $j -ne $i ]; then
      PEER_PORT=$((CONSENSUS_PORT_BASE + j))
      if [ -n "$PEERS" ]; then
        PEERS="${PEERS},"
      fi
      PEERS="${PEERS}\"/ip4/127.0.0.1/tcp/${PEER_PORT}\""
    fi
  done

  # Generate node configuration from template
  sed -e "s/\${NODE_ID}/$i/g" \
    -e "s/\${CONSENSUS_PORT}/$CONSENSUS_PORT/g" \
    -e "s/\${METRICS_PORT}/$METRICS_PORT/g" \
    -e "s#\${PEERS}#$PEERS#g" \
    -e "s/\${BLOCK_TIME}/$BLOCK_TIME/g" \
    "$SCRIPT_DIR/config/template.toml" >"$NODE_DIR/malachite/config/malachite.toml"

  # Copy genesis (keys are already in place)
  cp "$NODES_DIR/genesis.json" "$NODE_DIR/malachite/config/"

  # Create a minimal reth.toml to prevent Reth from writing to our malachite.toml
  mkdir -p "$NODE_DIR/reth"
  cat >"$NODE_DIR/reth/reth.toml" <<EOF
# Minimal Reth configuration
[stages]
[prune]
EOF
done

# Launch nodes
log "Launching nodes..."
for ((i = 0; i < $NUM_NODES; i++)); do
  NODE_DIR="$NODES_DIR/node$i"
  NODE_LOG_DIR="$LOGS_DIR/$i"
  mkdir -p "$NODE_LOG_DIR"
  LOG_FILE="$NODE_LOG_DIR/console.log"

  log "Starting node$i..."

  # Debug: Check if malachite.toml was created correctly
  if [ -f "$NODE_DIR/malachite/config/malachite.toml" ]; then
    log "Created malachite.toml ($(wc -c <"$NODE_DIR/malachite/config/malachite.toml") bytes)"
  else
    error "Failed to create malachite.toml"
  fi

  # Launch node in background
  RUST_LOG="${RUST_LOG:-info}" $BINARY node \
    --datadir "$NODE_DIR/reth" \
    --port $((RETH_PORT_BASE + i)) \
    --discovery.port $((RETH_PORT_BASE + i)) \
    --http \
    --http.addr 127.0.0.1 \
    --http.port $((RETH_RPC_PORT_BASE + i)) \
    --http.api eth,net,web3 \
    --authrpc.port $((AUTH_RPC_PORT_BASE + i)) \
    --metrics $((METRICS_PORT_BASE + i)) \
    --log.file.directory "$NODE_LOG_DIR" \
    --ipcdisable \
    --malachite-home "$NODE_DIR/malachite" \
    --consensus-config "$NODE_DIR/malachite/config/malachite.toml" \
    --validator-key "$NODE_DIR/malachite/config/priv_validator_key.json" \
    --genesis "$NODE_DIR/malachite/config/genesis.json" \
    --chain "dev" \
    --node-id "node-$i" \
    --chain-id "tempo-testnet" \
    >"$LOG_FILE" 2>&1 &

  PID=$!
  echo $PID >"$NODE_DIR/node.pid"

  log "Node$i started with PID $PID, logs at $LOG_FILE"
done

# Monitor nodes
log "All nodes started. Press Ctrl+C to stop the network."
log "Logs can be found in $LOGS_DIR/*/"
log ""
log "Useful commands:"
log "  tail -f $LOGS_DIR/0/console.log     # Follow node0 console output"
log "  tail -f $LOGS_DIR/*/console.log     # Follow all console logs"
log "  tail -f $LOGS_DIR/0/reth.log        # Follow node0 debug logs"
log ""

# Wait for interrupt
wait

