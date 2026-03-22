#!/usr/bin/env bash
set -euo pipefail

# Usage: ./run-parallel.sh <fuzz-crate-dir> <target> [processes] [duration_secs]
# Example: ./run-parallel.sh crates/transaction-pool/fuzz merge_best_ordering 8 1800

FUZZ_DIR="${1:?Usage: $0 <fuzz-crate-dir> <target> [processes] [duration]}"
TARGET="${2:?Usage: $0 <fuzz-crate-dir> <target> [processes] [duration]}"
PROCS="${3:-8}"
DURATION="${4:-1800}"

CORPUS_BASE="$FUZZ_DIR/corpus/$TARGET"
ARTIFACT_BASE="$FUZZ_DIR/artifacts/$TARGET"
LOG_DIR="$FUZZ_DIR/logs/$TARGET"

mkdir -p "$LOG_DIR"

echo "🐝 Parallel fuzzing: $TARGET"
echo "   Processes: $PROCS"
echo "   Duration:  ${DURATION}s per process"
echo "   Corpus:    $CORPUS_BASE"
echo "   Artifacts: $ARTIFACT_BASE"
echo ""

PIDS=()

cleanup() {
    echo ""
    echo "Caught interrupt, killing processes..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    exit 1
}
trap cleanup INT TERM

for i in $(seq 1 "$PROCS"); do
    CORPUS_DIR="$CORPUS_BASE/process_$i"
    ARTIFACT_DIR="$ARTIFACT_BASE/process_$i/"

    mkdir -p "$CORPUS_DIR" "$ARTIFACT_DIR"

    echo "  Starting process $i..."

    cargo fuzz run "$TARGET" "$CORPUS_DIR" \
        --fuzz-dir "$FUZZ_DIR" \
        -- -max_total_time="$DURATION" \
           -artifact_prefix="$ARTIFACT_DIR" \
        > "$LOG_DIR/process_${i}.log" 2>&1 &

    PIDS+=($!)
done

echo ""
echo "⏳ Waiting for $PROCS processes..."
echo "   Logs in: $LOG_DIR/"

FAILED=0
for i in "${!PIDS[@]}"; do
    pid="${PIDS[$i]}"
    proc=$((i + 1))
    if wait "$pid"; then
        echo "  ✅ Process $proc finished"
    else
        echo "  ❌ Process $proc found crashes!"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "━━━ Summary ━━━"

# Count crashes
CRASH_COUNT=$(find "$ARTIFACT_BASE" -name "crash-*" -o -name "oom-*" -o -name "timeout-*" 2>/dev/null | wc -l)
if [ "$CRASH_COUNT" -gt 0 ]; then
    echo "🔴 Found $CRASH_COUNT crash(es)!"
    find "$ARTIFACT_BASE" -name "crash-*" -o -name "oom-*" -o -name "timeout-*" 2>/dev/null
else
    echo "🟢 No crashes found."
fi

# Merge corpora
echo ""
echo "Merging corpora..."
MERGED_DIR="$CORPUS_BASE/merged"
mkdir -p "$MERGED_DIR"
cargo fuzz cmin "$TARGET" --fuzz-dir "$FUZZ_DIR" "$MERGED_DIR" $CORPUS_BASE/process_* 2>/dev/null || true
echo "Done. Merged corpus: $MERGED_DIR"
