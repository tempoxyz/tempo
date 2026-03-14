#!/bin/bash

# Stop consensus validator network
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Stopping Tempo Network ==="

docker compose -f "$SCRIPT_DIR/docker-compose.yml" down

echo "=== Network Stopped ==="
