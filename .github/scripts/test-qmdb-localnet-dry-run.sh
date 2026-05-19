#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

output="$(nu tempo.nu localnet --network mainnet-qmdb --nodes 1 --dry-run)"

grep -F -- "--chain mainnet-qmdb" <<< "$output"
grep -F -- "--state-root.backend qmdb" <<< "$output"
grep -F -- "--tempo.bootnodes-endpoint none" <<< "$output"

if grep -Fq "https://peers.tempo.xyz" <<< "$output"; then
  echo "canonical bootnode endpoint leaked into QMDB localnet dry-run" >&2
  exit 1
fi

if grep -Fq -- "--follow" <<< "$output"; then
  echo "follow URL leaked into QMDB localnet dry-run" >&2
  exit 1
fi
