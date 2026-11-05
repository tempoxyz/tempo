#!/bin/sh
# Antithesis test command: once faults stop, checks that the portal's escrow backs everything the
# zone owes (tempo-zone-xtask verify-portal-backing: zone supply plus pending deposits,
# withdrawals and refunds). A failed audit must repeat on consecutive audits to count, so a
# deposit or withdrawal landing between the L1 and zone snapshots cannot fail it.
set -eu

. /opt/zones/sdk.sh
. /opt/zones/journey-env.sh

ZONE_RPC_URL=http://10.20.0.20:8545
height() { cast block-number --rpc-url "$1" 2>/dev/null || echo 0; }

# Waits up to 30s for the RPC follower to reach the sequencers' height. A lagging follower can be
# missing zone events (a withdrawal request L1 has already paid) that the audit then reports as
# incomplete history.
catch_up() {
    target=0
    for node in 10.20.0.11 10.20.0.12 10.20.0.13; do
        h=$(height "http://$node:8545")
        [ "$h" -gt "$target" ] && target=$h
    done
    for _ in $(seq 1 30); do
        [ "$(height "$ZONE_RPC_URL")" -ge "$target" ] && return 0
        sleep 1
    done
    return 1
}

# Only RPC reads that fail are not a verdict; a deficit or any other audit error (such as the zone
# processing more deposits than the portal recorded) must repeat on consecutive audits to count.
failures=0
for attempt in $(seq 1 60); do
    if ! catch_up; then
        # The follower is still recovering: not a verdict.
        failures=0
        continue
    fi
    if out=$(tempo-zone-xtask verify-portal-backing --l1-rpc-url "$L1_RPC_URL" \
        --zone-rpc-url "$ZONE_RPC_URL" --portal "$ZONE_PORTAL_ADDRESS" \
        --token 0x20c0000000000000000000000000000000000000 2>&1); then
        echo "$out"
        sdk_assert always true true "$PORTAL_BACKED"
        exit 0
    fi
    echo "$out"
    if echo "$out" | grep -qE "failed connecting|failed reading|failed scanning|is after snapshot block"; then
        # The chains are still recovering: not a verdict.
        failures=0
    else
        failures=$((failures + 1))
        if [ "$failures" -ge 3 ]; then
            sdk_assert always true false "$PORTAL_BACKED" \
                "$(echo "$out" | jq -Rsc '{audit: .}')"
            exit 1
        fi
    fi
    sleep 5
done
echo "portal backing: no verdict after $attempt attempts"
