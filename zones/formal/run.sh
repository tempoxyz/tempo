#!/usr/bin/env bash
set -euo pipefail

# Run from any directory in this checkout. Dependencies are documented in README.md.
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
logs=$(mktemp -d)
trap 'rm -rf "$logs"' EXIT
cd "$root"
cargo test --locked -p zone-precompiles --lib tla_native_lifecycle_traces -- \
    --nocapture --test-threads=1 | tee "$logs/native.log"
(
    cd crates/zones/contracts
    "${FORGE:-forge}" test --match-contract '^ZonesTlaTraceTest$' --match-test test_tla -vv
) | tee "$logs/portal.log"
uv run python zones/formal/check.py --trace "$logs/native.log" --trace "$logs/portal.log" \
    --negative-control "$@"
