#!/bin/bash
# CLI smoke tests
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -n "$1" ]]; then
    TEMPO="$1"
else
    TEMPO="$REPO_ROOT/target/debug/tempo"
    if [[ ! -x "$TEMPO" ]]; then
        echo "Building tempo..."
        cargo build -p tempo --manifest-path "$REPO_ROOT/Cargo.toml"
    fi
fi

echo "Testing: $TEMPO"

echo "Test: tempo --version"
$TEMPO --version | grep -E "[0-9]+\.[0-9]+" || { echo "FAIL"; exit 1; }
echo "PASS"

echo "Test: tempo --help"
$TEMPO --help | grep -q "node" || { echo "FAIL"; exit 1; }
echo "PASS"

echo "Test: tempo node --help"
$TEMPO node --help | grep -q "datadir\|chain" || { echo "FAIL"; exit 1; }
echo "PASS"

echo "Test: tempo node --follow (no panic)"
DATADIR=$(mktemp -d)
NODE_LOG=$(mktemp)
$TEMPO node --chain moderato --follow --datadir "$DATADIR" --http --http.port 18545 2>"$NODE_LOG" &
NODE_PID=$!
cleanup() { kill $NODE_PID 2>/dev/null; rm -rf "$DATADIR" "$NODE_LOG"; }
trap cleanup EXIT

sleep 5

if grep -q "panicked" "$NODE_LOG"; then
    echo "FAIL: node panicked during startup"
    grep "panicked" "$NODE_LOG"
    exit 1
fi

if ! kill -0 $NODE_PID 2>/dev/null; then
    echo "FAIL: node process exited unexpectedly"
    cat "$NODE_LOG"
    exit 1
fi
echo "PASS"

echo "Test: tempoup --version"
"$REPO_ROOT/tempoup/tempoup" --version | grep -E "[0-9]+\.[0-9]+" || { echo "FAIL"; exit 1; }
echo "PASS"

echo "Test: tempoup -i (install latest release)"
LATEST_VERSION=$(curl -sSL https://api.github.com/repos/tempoxyz/tempo/releases/latest | grep '"tag_name":' | head -n1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
echo "Latest release: $LATEST_VERSION"
TEMPO_DIR=$(mktemp -d)
export TEMPO_DIR
"$REPO_ROOT/tempoup/tempoup" -i "$LATEST_VERSION" 2>&1 || { echo "FAIL: tempoup install failed"; exit 1; }
INSTALLED="$TEMPO_DIR/bin/tempo"
if [[ ! -x "$INSTALLED" ]]; then
    echo "FAIL: tempo binary not found at $INSTALLED"
    exit 1
fi
"$INSTALLED" --version | grep -E "[0-9]+\.[0-9]+" || { echo "FAIL: installed binary --version failed"; exit 1; }
rm -rf "$TEMPO_DIR"
echo "PASS"

echo "All CLI tests passed!"
