#!/bin/bash
# Generate coverage report for StablecoinDEX invariant tests.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CASES="${1:-50}"
COV_DIR="$REPO_DIR/target/coverage"

cd "$REPO_DIR"

rm -rf "$COV_DIR"
mkdir -p "$COV_DIR"

echo "Running invariant tests with coverage ($CASES cases)..."
RUSTFLAGS="-C instrument-coverage" \
  LLVM_PROFILE_FILE="$COV_DIR/invariants-%p.profraw" \
  PROPTEST_CASES="$CASES" \
  cargo test --test invariants --features test-utils 2>&1 | tee "$COV_DIR/test-output.txt"

echo "Merging profraw data..."
llvm-profdata merge -sparse "$COV_DIR"/invariants-*.profraw -o "$COV_DIR/invariants.profdata"

BINARY=$(grep -oE 'target/debug/deps/invariants-[a-f0-9]+' "$COV_DIR/test-output.txt" | head -1)
BINARY="$REPO_DIR/$BINARY"

echo ""
echo "Coverage summary (StablecoinDEX only):"
llvm-cov report "$BINARY" \
  --instr-profile="$COV_DIR/invariants.profdata" \
  --sources crates/precompiles/src/stablecoin_dex/

echo ""
echo "Generating HTML report..."
llvm-cov show "$BINARY" \
  --instr-profile="$COV_DIR/invariants.profdata" \
  --sources crates/precompiles/src/stablecoin_dex/ \
  --format=html --output-dir="$COV_DIR/html"

echo "Done. open target/coverage/html/index.html"
