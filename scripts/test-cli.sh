#!/bin/bash
# CLI smoke tests
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -n "$1" ]]; then
    TEMPO="$1"
else
    TEMPO="$REPO_ROOT/target/release/tempo"
    if [[ ! -x "$TEMPO" ]]; then
        echo "Building tempo..."
        cargo build --release -p tempo --manifest-path "$REPO_ROOT/Cargo.toml"
    fi
fi

echo "Testing: $TEMPO"

echo "Test: --version"
$TEMPO --version | grep -E "[0-9]+\.[0-9]+" || { echo "FAIL"; exit 1; }
echo "PASS"

echo "Test: --help"
$TEMPO --help | grep -q "node" || { echo "FAIL"; exit 1; }
echo "PASS"

echo "Test: consensus generate-private-key"
TMPKEY=$(mktemp -u)
$TEMPO consensus generate-private-key -o "$TMPKEY" || { rm -f "$TMPKEY"; echo "FAIL"; exit 1; }
rm -f "$TMPKEY"
echo "PASS"

echo "Test: node --help"
$TEMPO node --help | grep -q "datadir\|chain" || { echo "FAIL"; exit 1; }
echo "PASS"

echo "Test: node --follow (RPC endpoints)"
DATADIR=$(mktemp -d)
$TEMPO node --chain moderato --follow --datadir "$DATADIR" --http --http.port 18545 &
NODE_PID=$!
cleanup() { kill $NODE_PID 2>/dev/null; rm -rf "$DATADIR"; }
trap cleanup EXIT

# Wait for node to start
STARTED=false
for i in {1..30}; do
    if cast rpc eth_chainId --rpc-url http://localhost:18545 &>/dev/null; then
        STARTED=true
        break
    fi
    sleep 1
done
if [[ "$STARTED" != "true" ]]; then
    echo "FAIL: node didn't start within 30s"
    exit 1
fi

# Test RPC endpoints
cast rpc eth_chainId --rpc-url http://localhost:18545 || { echo "FAIL: eth_chainId"; exit 1; }
cast rpc eth_blockNumber --rpc-url http://localhost:18545 || { echo "FAIL: eth_blockNumber"; exit 1; }
cast rpc net_version --rpc-url http://localhost:18545 || { echo "FAIL: net_version"; exit 1; }
echo "PASS"

echo "All CLI tests passed!"
