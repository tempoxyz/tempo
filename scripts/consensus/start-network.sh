#!/bin/bash

# Start consensus validator network with 4 validators using Docker network
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DOCKER_IMAGE="tempo-commonware:latest"
NETWORK_NAME="tempo-commonware"

echo "=== Starting Tempo Network ==="

# Create Docker network if it doesn't exist
if ! docker network ls | grep -q "$NETWORK_NAME"; then
  echo "Creating Docker network: $NETWORK_NAME"
  docker network create "$NETWORK_NAME"
fi

# Config files for 4 validators
CONFIGS=(
  "196506320dcb5ea6bf4a5404dae21d6119341e7248e8f7f6dfb14d12301befe2.toml"
  "1bc6dd47289a73e859502db4233ebcc36976cedf33f4a45635f7cd6a983f9a7b.toml"
  "2635bdd26e096ae9dbd6d57a45558606d301e7962f10a43359dd7e7fbb0422ce.toml"
  "a964d167f9ed16a76e1e48efa74ef8d84545f8af883aae8373c63776871c2d89.toml"
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
    --http.api all

  echo "  ✓ Started $container_name on port $rpc_port"
}

# Start all validators
for i in {0..3}; do
  start_validator "$i" "${CONFIGS[$i]}"
done

# Hacky fix: restart validator-0 if it failed
echo "Restarting validator-0..."
docker restart tempo-validator-0 >/dev/null 2>&1 || true

echo ""
echo "=== Network Started ==="
echo "Validators:"
echo "  tempo-validator-0: http://localhost:8545"
echo "  tempo-validator-1: http://localhost:8546"
echo "  tempo-validator-2: http://localhost:8547"
echo "  tempo-validator-3: http://localhost:8548"
echo ""
echo "To stop the network: $SCRIPT_DIR/stop-network.sh"
