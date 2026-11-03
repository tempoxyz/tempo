#!/bin/sh
# Antithesis test command: runs txgen zone journeys (/opt/zones/txgen/journey.yml), each for an
# account the zone has never seen, against a random zone node, and reports the outcome as SDK
# assertions.
set -eu

. /opt/zones/sdk.sh
. /opt/zones/journey-env.sh

rand() { od -An -N4 -tu4 /dev/urandom | tr -d ' '; }

COUNT=${ZONE_JOURNEY_COUNT:-32}
POOL=${ZONE_JOURNEY_POOL:-256}
# A fresh window of the mnemonic on every run (index 1000 and up stays clear of the dev
# accounts), so each journey's account is new to the zone.
ZONE_JOURNEY_FRESH_START=$((1000 + $(rand) % 2000000000))
ZONE_JOURNEY_FRESH_END=$((ZONE_JOURNEY_FRESH_START + POOL))
export ZONE_JOURNEY_FRESH_START ZONE_JOURNEY_FRESH_END

# Any zone node accepts transactions: sequencers include them, and the RPC follower forwards them.
case $(($(rand) % 4)) in
    0) ZONE_RPC_URL=http://10.20.0.11:8545 ;;
    1) ZONE_RPC_URL=http://10.20.0.12:8545 ;;
    2) ZONE_RPC_URL=http://10.20.0.13:8545 ;;
    *) ZONE_RPC_URL=http://10.20.0.20:8545 ;;
esac
export ZONE_RPC_URL

report=$(mktemp)
echo "journeys: $COUNT via $ZONE_RPC_URL, accounts $ZONE_JOURNEY_FRESH_START..$ZONE_JOURNEY_FRESH_END"
# Failed journeys exit nonzero; the report says why.
txgen-tempo scenario run \
    --scenario /opt/zones/txgen/journey.yml \
    --count "$COUNT" \
    --starts-per-second 1 \
    --max-in-flight 8 \
    --seed "$(rand)" \
    --failure-policy continue \
    --report "json:$report" || true

if ! jq -e '.completed | numbers' "$report" >/dev/null 2>&1; then
    # Initialization (chain IDs, nonces) needs both chains; under faults it may not get there.
    echo "journeys: no report"
    exit 0
fi

jq -c '{started, completed, failed, timed_out, failures: [.failures[] | {step_name, classification, count, sample_detail}]}' "$report"

completed=$(jq .completed "$report")
sdk_assert sometimes true "$([ "$completed" -gt 0 ] && echo true || echo false)" "$JOURNEY_COMPLETED" \
    "$(jq -c '{started, completed, failed, timed_out}' "$report")"

# Faults delay, drop or refuse requests; they never make a transaction revert or a node return
# the wrong transaction hash.
unexplained=$(jq -c '[.failures[] | select(.classification | IN(
    "timeout", "rpc_error", "invoke_error", "submission_ambiguous", "submission_rejected",
    "nonce_state_ambiguous", "nonce_recovery_error") | not)]' "$report")
sdk_assert always true "$([ "$unexplained" = "[]" ] && echo true || echo false)" \
    "$JOURNEY_FAILURES_FROM_FAULTS" "{\"failures\": $unexplained}"
