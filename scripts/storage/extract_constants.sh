#!/usr/bin/env bash
# Extract storage constants from the current branch
#
# Usage:
#   ./scripts/extract_constants.sh [output_filename]
#
# If no filename is provided, uses current branch name
#
# Example:
#   ./scripts/extract_constants.sh
#   ./scripts/extract_constants.sh my_constants.json

set -euo pipefail

# Get script directory and workspace root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Determine output filename
if [ $# -eq 0 ]; then
    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
    OUTPUT_FILE="${CURRENT_BRANCH//\//_}_constants.json"
else
    OUTPUT_FILE="$1"
fi

echo "🔍 Extracting storage constants from current branch..."
cd "$WORKSPACE_ROOT"

# Run the export test
cargo test --package tempo-precompiles export_all_storage_constants -- --ignored --nocapture

# Rename the output file
if [ -f "current_branch_constants.json" ]; then
    mv current_branch_constants.json "$OUTPUT_FILE"
    echo "✅ Constants exported to: $OUTPUT_FILE"

    # Show file size and preview
    echo ""
    echo "📊 File size: $(wc -c < "$OUTPUT_FILE") bytes"
    echo ""
    echo "📝 Preview (first few precompiles):"
    if command -v jq >/dev/null 2>&1; then
        jq 'keys' "$OUTPUT_FILE"
    else
        head -n 20 "$OUTPUT_FILE"
    fi
else
    echo "❌ Error: Failed to export constants"
    exit 1
fi
