#!/usr/bin/env bash
# Stage replay inputs before measuring; publish only complete extractions.
set -euo pipefail

extract_replay_blocks() {
  local from="$1" to="$2" output="$3"
  local partial="${output}.partial"
  local attempt
  for attempt in 1 2 3; do
    rm -f "$partial"
    if "$TXGEN_TEMPO_BIN" extract --rpc "$REPLAY_RPC_URL" \
      --from "$from" --to "$to" --buffer-size 1 --output "$partial"; then
      mv "$partial" "$output"
      return 0
    fi
    echo "Replay extraction attempt $attempt failed for blocks $from..$to" >&2
    if [ "$attempt" -lt 3 ]; then
      sleep "$(( attempt * 5 ))"
    fi
  done
  rm -f "$partial"
  return 1
}
