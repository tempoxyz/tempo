#!/bin/bash

# Start consensus validator network using Docker Compose
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/test-utils.sh"

echo "=== Starting Tempo Network ==="

docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d

if ! wait_for_network_ready "http://localhost:8545" 30 6; then
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
