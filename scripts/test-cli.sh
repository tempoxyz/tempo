#!/bin/bash
# CLI smoke tests — exits non-zero on any failure.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FAILED=0
fail() { echo "FAIL: $1"; FAILED=1; }
dump_log() { echo "--- output ---"; cat "$1"; echo "---"; }

run_ok() {
    local label="$1"; shift
    echo "--- Test: $label"
    OUT=$("$@" 2>&1) || { fail "$label exited with non-zero status"; return; }
    echo "PASS"
}

TEMPO="${1:-$REPO_ROOT/target/debug/tempo}"
if [[ ! -x "$TEMPO" ]]; then
    echo "Building tempo..."
    cargo build -p tempo --manifest-path "$REPO_ROOT/Cargo.toml"
fi
echo "Testing: $TEMPO"

run_ok "tempo --version" "$TEMPO" --version
run_ok "tempo --help" "$TEMPO" --help
run_ok "tempo node --help" "$TEMPO" node --help

# --- node --follow: verify it stays alive for 15s with no crashes ---
echo "--- Test: tempo node --follow (no crash)"
DATADIR=$(mktemp -d)
NODE_LOG=$(mktemp)
$TEMPO node --chain moderato --follow --datadir "$DATADIR" --http --http.port 18545 >"$NODE_LOG" 2>&1 &
NODE_PID=$!
trap 'kill "$NODE_PID" 2>/dev/null || true; wait "$NODE_PID" 2>/dev/null || true; rm -rf "$DATADIR" "$NODE_LOG"' EXIT

NODE_EXITED=0
for i in $(seq 1 15); do
    if ! kill -0 "$NODE_PID" 2>/dev/null; then
        EC=0; wait "$NODE_PID" || EC=$?
        dump_log "$NODE_LOG"
        fail "node exited after ${i}s (exit code $EC)"
        NODE_EXITED=1
        break
    fi
    sleep 1
done

if [[ $NODE_EXITED -eq 0 ]]; then
    if grep -qiE "panicked|SIGSEGV|SIGABRT|thread.*panicked" "$NODE_LOG"; then
        dump_log "$NODE_LOG"; fail "node output contains panic/crash indicators"
    else
        echo "PASS"
    fi
fi

if [[ $FAILED -ne 0 ]]; then echo ""; echo "CLI smoke tests FAILED"; exit 1; fi
echo ""; echo "All CLI tests passed!"
