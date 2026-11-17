#!/bin/bash
# Uses prebuilt images. Starts a fresh isolated local cluster; never launches Antithesis.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root/contrib/antithesis/tempo-cluster"
export EVENTUALLY_AFTER_SECONDS="${EVENTUALLY_AFTER_SECONDS:-60}"
export DISABLE_EVENTUALLY=1
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-tempo-cluster-smoke}"
artifacts="${SMOKE_ARTIFACT_DIR:-$root/.bench-tmp/tempo-cluster-smoke}"
mkdir -p "$artifacts"
# The fixture image must not require passphrase decryption on validator restarts.
# shellcheck disable=SC2016 # These variables expand inside the container.
timeout 30s docker run --rm --network none --entrypoint /bin/bash "${TEMPO_IMAGE:?TEMPO_IMAGE required}" -c '
    set -euo pipefail
    test ! -e /opt/tempo-cluster/secret
    if grep -Fq -- --consensus.secret /opt/tempo-cluster/node.sh; then
        echo "Fixture launcher still requests passphrase decryption" >&2
        exit 1
    fi
    keys=(/opt/tempo-cluster/genesis/*:8000/signing.key)
    [[ "${#keys[@]}" == 4 ]]
    for key in "${keys[@]}"; do
        [[ "$(cat "$key")" =~ ^0x[0-9a-fA-F]{64}$ ]]
    done
'
# shellcheck disable=SC2329 # Invoked by the EXIT trap.
cleanup() {
    docker compose logs --no-color > "$artifacts/compose.log" 2>&1 || true
    docker compose cp driver:/state/sdk.jsonl "$artifacts/sdk.jsonl" || true
    docker compose cp driver:/state/recovery-result.json "$artifacts/recovery-result.json" || true
    docker compose down -v --remove-orphans
}
trap cleanup EXIT
docker compose down -v --remove-orphans
docker compose up -d
# Local Compose does not run test templates. Readiness still gates all workload actions.
docker compose exec -T driver /opt/antithesis/test/v1/main/first_start_workload
# Exercise restart durability locally too, after fixture setup is confirmed.
setup_deadline=$((SECONDS + 360))
until docker compose exec -T driver test -f /state/setup-confirmed; do
    ((SECONDS < setup_deadline)) || { echo 'Setup timed out' >&2; exit 1; }
    sleep 2
done
sleep 5
docker compose kill -s SIGKILL validator-3
docker compose start validator-3
# The non-signing follower must reconnect and catch up from its persisted datadir.
docker compose kill -s SIGKILL follower
sleep 5
docker compose start follower
deadline=$((SECONDS + 240))
while ((SECONDS < deadline)); do
    id=$(docker compose ps -aq driver)
    state=$(docker inspect --format '{{.State.Status}}' "$id")
    if [[ "$state" == exited ]]; then
        [[ "$(docker inspect --format '{{.State.ExitCode}}' "$id")" == 0 ]]
        docker compose cp driver:/state/recovery-result.json "$artifacts/recovery-result.json"
        jq -e '.recovered == true and (.heights | length == 5)' "$artifacts/recovery-result.json"
        docker compose cp driver:/state/sdk.jsonl "$artifacts/sdk.jsonl"
        cp "$artifacts/sdk.jsonl" "$artifacts/all-sdk.jsonl"
        for node in validator-{0..3} follower; do
            docker compose cp "$node:/data/sdk.jsonl" "$artifacts/$node-sdk.jsonl"
            cat "$artifacts/$node-sdk.jsonl" >> "$artifacts/all-sdk.jsonl"
        done
        jq -es '
            [.[] | .antithesis_assert? | select(.hit and .condition) | .message]
            | index("Follow mode execution never rejects a finalized block as invalid") != null
              and index("Follow mode forkchoice never rejects a finalized tip as invalid") != null
        ' "$artifacts/follower-sdk.jsonl"
        python3 "$root/contrib/antithesis/tempo-cluster/tests/check_sdk.py" "$artifacts/all-sdk.jsonl"
        exit 0
    fi
    sleep 2
done
echo 'Smoke timed out; see compose.log' >&2
exit 1
