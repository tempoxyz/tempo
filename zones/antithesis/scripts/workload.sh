#!/bin/sh
# Installs the test template, waits until the RPC follower has imported zone blocks from the
# leader, then tells the test platform that setup is complete and stays up for test commands.
# The template ships in the shared image outside /opt/antithesis so no other container offers it.
set -eu

ZONE_RPC=http://10.20.0.20:8545
READY_HEIGHT=5

rm -rf /opt/antithesis/test
mkdir -p /opt/antithesis
cp -R /opt/zones/antithesis-test /opt/antithesis/test

until [ "$(cast block-number --rpc-url "$ZONE_RPC" 2>/dev/null || echo 0)" -ge "$READY_HEIGHT" ]; do
    sleep 1
done
echo "workload: zone replicated to height $READY_HEIGHT"

if [ -n "${ANTITHESIS_OUTPUT_DIR:-}" ]; then
    mkdir -p "$ANTITHESIS_OUTPUT_DIR"
    echo '{"antithesis_setup":{"status":"complete","details":{}}}' >> "$ANTITHESIS_OUTPUT_DIR/sdk.jsonl"
fi

exec sleep infinity
