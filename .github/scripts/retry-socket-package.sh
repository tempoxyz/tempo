#!/usr/bin/env bash

set -uo pipefail

log=$(mktemp)
trap 'rm -f "$log"' EXIT

max_attempts=${SOCKET_RETRY_ATTEMPTS:-10}
delay_seconds=${SOCKET_RETRY_DELAY_SECONDS:-15}

# Avoid bursting concurrent crate downloads through the Socket proxy while its
# policy service evaluates packages.
export CARGO_HTTP_MULTIPLEXING=${CARGO_HTTP_MULTIPLEXING:-false}

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  : >"$log"
  "$@" 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  if ((status == 0)); then
    exit 0
  fi

  # Retry only verdict-service infrastructure failures. Cooldown denials such
  # as recentlyPublished and actual command failures must fail immediately.
  if ! grep -Eq 'Aegis could not obtain a complete Socket verdict.*(context deadline exceeded|Socket API returned HTTP (429|5[0-9][0-9]))|Socket (analysis incomplete|API returned HTTP (429|5[0-9][0-9]))' "$log"; then
    exit "$status"
  fi
  if ((attempt == max_attempts)); then
    exit "$status"
  fi

  echo "Socket verdict service is temporarily unavailable; retrying in ${delay_seconds} seconds (attempt $((attempt + 1))/${max_attempts})"
  sleep "$delay_seconds"
done
