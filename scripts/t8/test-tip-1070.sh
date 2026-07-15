#!/usr/bin/env bash

set -euo pipefail
source "$(dirname "$0")/common.sh"
require_tools
require_env RPC_URL
require_t8

read_committee() {
  call "$CURRENT_COMMITTEE" "getCommitteeMembers()(uint64,bytes32[])" --json
}

committee=$(read_committee)
epoch=$(jq -er '.[0]' <<<"$committee")
members=$(jq -er '.[1] | length' <<<"$committee")
if (( members == 0 )); then
  echo "FAIL: onchain committee is empty at epoch $epoch" >&2
  exit 1
fi
print_pass "TIP-1070 exposes $members committee members for epoch $epoch"

if [[ "${WAIT_FOR_EPOCH:-0}" != "1" ]]; then
  exit 0
fi

deadline=$((SECONDS + ${EPOCH_TIMEOUT_SECONDS:-7200}))
interval=${EPOCH_POLL_SECONDS:-15}
while (( SECONDS < deadline )); do
  sleep "$interval"
  next=$(read_committee)
  next_epoch=$(jq -er '.[0]' <<<"$next")
  if (( next_epoch > epoch )); then
    next_members=$(jq -er '.[1] | length' <<<"$next")
    (( next_members > 0 )) || { echo "FAIL: committee became empty at epoch $next_epoch" >&2; exit 1; }
    print_pass "TIP-1070 committee advanced from epoch $epoch to $next_epoch ($next_members members)"
    exit 0
  fi
done

echo "FAIL: committee epoch did not advance from $epoch within ${EPOCH_TIMEOUT_SECONDS:-7200}s" >&2
exit 1
