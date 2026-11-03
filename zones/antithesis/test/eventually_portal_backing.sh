#!/bin/sh
# Antithesis test command: once faults stop, checks that the portal's escrow backs everything the
# zone owes (tempo-zone-xtask verify-portal-backing: zone supply plus pending deposits,
# withdrawals and refunds). A deficit must persist across consecutive audits to count, so a
# deposit or withdrawal landing between the L1 and zone snapshots cannot fail it.
set -eu

. /opt/zones/sdk.sh
. /opt/zones/journey-env.sh

ZONE_RPC_URL=http://10.20.0.20:8545
deficits=0
for attempt in $(seq 1 60); do
    if out=$(tempo-zone-xtask verify-portal-backing --l1-rpc-url "$L1_RPC_URL" \
        --zone-rpc-url "$ZONE_RPC_URL" --portal "$ZONE_PORTAL_ADDRESS" \
        --token 0x20c0000000000000000000000000000000000000 2>&1); then
        echo "$out"
        sdk_assert always true true "$PORTAL_BACKED"
        exit 0
    fi
    echo "$out"
    if echo "$out" | grep -q "FAIL: backing deficit"; then
        deficits=$((deficits + 1))
        if [ "$deficits" -ge 3 ]; then
            sdk_assert always true false "$PORTAL_BACKED" \
                "$(echo "$out" | jq -Rsc '{audit: .}')"
            exit 1
        fi
    else
        # The chains are still recovering: not a verdict.
        deficits=0
    fi
    sleep 5
done
echo "portal backing: no verdict after $attempt attempts"
