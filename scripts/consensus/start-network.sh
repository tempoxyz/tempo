#!/bin/bash

# Start consensus validator network with 4 validators using Docker network
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source test utilities
source "$SCRIPT_DIR/test-utils.sh"

DOCKER_IMAGE="tempo:latest"
NETWORK_NAME="tempo"

echo "=== Starting Tempo Network ==="

# Create Docker network if it doesn't exist
if ! docker network ls | grep -q "$NETWORK_NAME"; then
  echo "Creating Docker network: $NETWORK_NAME"
  docker network create "$NETWORK_NAME"
fi

# Config files for 4 validators
CONFIGS=(
  "0c229e27a8c69e7afe86900dfbceab6ef6d207582c127a0d99fe9b3fb5a2068a.toml"
  "2a685998ee44953a3eb0a5d316937f810a80bdcc952c0aa07b4d82b3fed459c2.toml"
  "7f7fdd1ca8d7c3ed8206137178b47bcafe7a54d4a0b4ce5bd9e25978184b48ce.toml"
  "ee1aa49a4459dfe813a3cf6eb882041230c7b2558469de81f87c9bf23bf10a03.toml"
)

start_validator() {
  local validator_id="$1"
  local config_file="$2"
  local container_name="tempo-validator-$validator_id"
  local rpc_port=$((8545 + validator_id))

  echo "Starting $container_name with config $config_file..."

  # Remove existing container if it exists
  docker rm -f "$container_name" >/dev/null 2>&1 || true

  # Start the validator container
  # Build extra args for metrics OTLP if TELEMETRY_OTLP is set
  local metrics_args=""
  if [[ -n "${TELEMETRY_OTLP:-}" ]]; then
    metrics_args="--telemetry-otlp $TELEMETRY_OTLP"
  fi

  docker run -d \
    --name "$container_name" \
    --network "$NETWORK_NAME" \
    -p "$rpc_port:8545" \
    -v "$SCRIPT_DIR/configs/$config_file:/tmp/consensus-config.toml:ro" \
    -v "$PROJECT_ROOT/crates/node/tests/assets/test-genesis.json:/tmp/test-genesis.json:ro" \
    -e RUST_LOG=debug \
    "$DOCKER_IMAGE" \
    node \
    --chain /tmp/test-genesis.json \
    --consensus-config /tmp/consensus-config.toml \
    --datadir "/tmp/data" \
    --port 30303 \
    --http \
    --http.addr 0.0.0.0 \
    --http.port 8545 \
    --http.api all \
    $metrics_args

  echo "  ✓ Started $container_name on port $rpc_port"
}

# Start all validators simultaneously
echo "Starting all validators..."
for i in {0..3}; do
  start_validator "$i" "${CONFIGS[$i]}" &
done
wait

# Wait for network to be ready
if ! wait_for_network_ready "http://localhost:8545" 15 3; then
  echo "ERROR: Network failed to start properly"
  exit 1
fi

echo ""
echo "=== Network Started ==="
echo "Validators:"
echo "  tempo-validator-0: http://localhost:8545"
echo "  tempo-validator-1: http://localhost:8546"
echo "  tempo-validator-2: http://localhost:8547"
echo "  tempo-validator-3: http://localhost:8548"
echo ""
echo "To stop the network: $SCRIPT_DIR/stop-network.sh"
