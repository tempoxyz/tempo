#!/bin/bash
set -e

echo "=== Bridge E2E Test ==="

# Start Anvil in background
echo "Starting Anvil..."
anvil --port 8545 &
ANVIL_PID=$!
sleep 2

# Cleanup on exit
trap "kill $ANVIL_PID 2>/dev/null" EXIT

# Deploy origin contracts
echo "Deploying origin chain contracts..."
cd contracts/bridge
forge build
# forge script script/Deploy.s.sol --rpc-url http://localhost:8545 --broadcast

# Run e2e tests
echo "Running bridge tests..."
cd ../..
cargo nextest run -p tempo-e2e bridge --no-capture

echo "=== All tests passed ==="
