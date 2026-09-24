#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
exec 9>/tmp/tempo-general-state-access-20260922.lock
flock -n 9
tool=${HISTORY_FIXTURE_TOOL:-$PWD/target/profiling/examples/prepare_history_state_paths}
archive="bench-results/history-router-update-$(date -u +%Y%m%d-%H%M%S)"
mkdir "$archive"
cp contrib/bench/txgen/history-state-paths.json "$archive/new-artifact.json"
sha256sum "$tool" > "$archive/helper-sha256.txt"
for side in a b; do
    # Only fixtures created by prepare-history-state-paths.sh are eligible.
    base=/reth-bench-$side/tempo_e2e_100000mb_state_access_isolated_roles_history_paths
    test -f "$base.virgin/.bench-meta/history-state-paths.json"
    test ! -e "$base.router_update"
    cp "$base.virgin/.bench-meta/history-state-paths.json" "$archive/$side-before.json"
    count=$(node -p "require('$base.virgin/.bench-meta/history-state-paths.json').code_count")
    mv "$base.virgin" "$base.router_update"
    # Failure deliberately leaves the fixture unavailable, not falsely promoted.
    "$tool" --datadir "$base.router_update" --chain "$base.router_update/.bench-meta/genesis.json" \
        --code-count "$count" --router-artifact "$PWD/contrib/bench/txgen/history-state-paths.json" --replace-router \
        > "$archive/$side-update.log" 2>&1
    cp "$base.router_update/.bench-meta/history-state-paths.json" "$archive/$side-after.json"
    mv "$base.router_update" "$base.virgin"
done
printf 'ROUTER_UPDATE_COMPLETE %s %s\n' "$archive" "$(date -u --iso-8601=seconds)"
