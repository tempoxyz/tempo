#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

run_parser() {
  bash .github/scripts/build-devnet-event.sh \
    "$1" \
    "dan/qmdb-sdk-integration" \
    "alice" \
    "devnet-pr-123"
}

mainnet_payload="$(run_parser "/build-devnet network=mainnet-qmdb")"
jq -e '
  .name == "devnet-pr-123" and
  .branch == "dan/qmdb-sdk-integration" and
  .requested_by == "alice" and
  .network == "mainnet-qmdb" and
  .state_root_backend == "qmdb"
' <<< "$mainnet_payload" > /dev/null

moderato_payload="$(run_parser "/build-devnet network=moderato-qmdb")"
jq -e '
  .network == "moderato-qmdb" and
  .state_root_backend == "qmdb"
' <<< "$moderato_payload" > /dev/null

backend_payload="$(run_parser "/build-devnet state-root.backend=qmdb")"
jq -e '
  .network == "mainnet" and
  .state_root_backend == "qmdb"
' <<< "$backend_payload" > /dev/null
