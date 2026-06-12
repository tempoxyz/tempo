#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LEAN_DIR="$ROOT/formal/lean"
FIXTURE="$ROOT/crates/precompiles/testdata/nonce_replay_conformance.json"

if command -v lake >/dev/null 2>&1; then
  LAKE="lake"
else
  LAKE="$HOME/.elan/bin/lake"
fi

cd "$LEAN_DIR"
"$LAKE" --wfail build nonceFixtures

generated_fixture="$(mktemp)"
trap 'rm -f "$generated_fixture"' EXIT

"$LAKE" --quiet exe nonceFixtures > "$generated_fixture"
diff -u "$FIXTURE" "$generated_fixture"

cd "$ROOT"
cargo test -p tempo-precompiles nonce_replay_conforms_to_lean_fixture
