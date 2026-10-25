#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=bench-tempo-extract.sh
source "$(dirname "${BASH_SOURCE[0]}")/bench-tempo-extract.sh"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export EXTRACT_TEST_DIR="$scratch"
export REPLAY_RPC_URL=http://example.invalid
export TXGEN_TEMPO_BIN=fake_txgen

sleep() { :; }
fake_txgen() {
  local output="" attempt=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --buffer-size) [ "$2" = 1 ]; shift ;;
      --output) output="$2"; shift ;;
    esac
    shift
  done
  if [ -f "$EXTRACT_TEST_DIR/attempt" ]; then
    attempt=$(cat "$EXTRACT_TEST_DIR/attempt")
  fi
  attempt=$(( attempt + 1 ))
  echo "$attempt" > "$EXTRACT_TEST_DIR/attempt"
  if [ "${EXTRACT_TEST_FAIL:-false}" = true ] || [ "$attempt" -eq 1 ]; then
    echo incomplete > "$output"
    return 1
  fi
  echo complete > "$output"
}

extract_replay_blocks 10 20 "$scratch/blocks.jsonl"
[ "$(cat "$scratch/blocks.jsonl")" = complete ]
[ "$(cat "$scratch/attempt")" = 2 ]
[ ! -e "$scratch/blocks.jsonl.partial" ]

rm "$scratch/attempt" "$scratch/blocks.jsonl"
EXTRACT_TEST_FAIL=true
if extract_replay_blocks 10 20 "$scratch/blocks.jsonl"; then
  echo 'Expected extraction failure' >&2
  exit 1
fi
[ "$(cat "$scratch/attempt")" = 3 ]
[ ! -e "$scratch/blocks.jsonl" ]
[ ! -e "$scratch/blocks.jsonl.partial" ]
echo 'PASS: retry partial extractions and fail without publishing incomplete input'
