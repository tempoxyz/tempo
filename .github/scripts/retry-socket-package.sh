#!/usr/bin/env bash

set -uo pipefail

log=$(mktemp)
trap 'rm -f "$log"' EXIT

for attempt in {1..10}; do
  : >"$log"
  "$@" 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  if (( status == 0 )); then
    exit 0
  fi

  if ! grep -Eq 'Socket (analysis incomplete|API returned HTTP 429)|Reason: recentlyPublished' "$log"; then
    exit "$status"
  fi
  if (( attempt == 10 )); then
    exit "$status"
  fi

  echo "Socket package policy is temporarily unavailable; retrying in 15 seconds (attempt $((attempt + 1))/10)"
  sleep 15
done
