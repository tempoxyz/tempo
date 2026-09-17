#!/usr/bin/env bash

set -uo pipefail

log=$(mktemp)
trap 'rm -f "$log"' EXIT

max_attempts=${SOCKET_RETRY_ATTEMPTS:-30}
delay_seconds=${SOCKET_RETRY_DELAY_SECONDS:-15}

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  : >"$log"
  "$@" 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  if (( status == 0 )); then
    exit 0
  fi

  if ! grep -Eq 'Socket (analysis incomplete|API returned HTTP 429)|Reason: recentlyPublished' "$log"; then
    exit "$status"
  fi
  if (( attempt == max_attempts )); then
    exit "$status"
  fi

  echo "Socket package policy is temporarily unavailable; retrying in ${delay_seconds} seconds (attempt $((attempt + 1))/${max_attempts})"
  sleep "$delay_seconds"
done
