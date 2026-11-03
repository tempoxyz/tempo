#!/bin/sh
# Waits until the RPC follower has imported zone blocks from the leader, declares the test
# commands' assertions, then tells the test platform that setup is complete and stays up for
# test commands (/opt/antithesis/test/v1/zones).
set -eu

. /opt/zones/sdk.sh
. /opt/zones/journey-env.sh

ZONE_RPC=http://10.20.0.20:8545
READY_HEIGHT=5

until [ "$(cast block-number --rpc-url "$ZONE_RPC" 2>/dev/null || echo 0)" -ge "$READY_HEIGHT" ]; do
    sleep 1
done
echo "workload: zone replicated to height $READY_HEIGHT"

sdk_declare sometimes "$JOURNEY_COMPLETED"
sdk_declare always "$JOURNEY_FAILURES_FROM_FAULTS"
sdk_declare always "$PORTAL_BACKED"

if [ -n "${ANTITHESIS_OUTPUT_DIR:-}" ]; then
    mkdir -p "$ANTITHESIS_OUTPUT_DIR"
    echo '{"antithesis_setup":{"status":"complete","details":{}}}' >> "$ANTITHESIS_OUTPUT_DIR/sdk.jsonl"
fi

exec sleep infinity
