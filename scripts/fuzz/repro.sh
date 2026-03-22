#!/usr/bin/env bash
set -euo pipefail

# Usage: ./repro.sh <fuzz-crate-dir> <target> <crash-file>
# Example: ./repro.sh crates/transaction-pool/fuzz merge_best_ordering artifacts/merge_best_ordering/swarm_1/crash-abc123

FUZZ_DIR="${1:?Usage: $0 <fuzz-crate-dir> <target> <crash-file>}"
TARGET="${2:?Usage: $0 <fuzz-crate-dir> <target> <crash-file>}"
CRASH_FILE="${3:?Usage: $0 <fuzz-crate-dir> <target> <crash-file>}"

echo "🔍 Reproducing crash for $TARGET"
echo "   File: $CRASH_FILE"
echo ""

cargo fuzz run "$TARGET" --fuzz-dir "$FUZZ_DIR" "$CRASH_FILE"
