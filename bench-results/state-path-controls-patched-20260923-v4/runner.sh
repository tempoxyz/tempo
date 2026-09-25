#!/usr/bin/env bash
set -euo pipefail
cd /home/ubuntu/repos/tempo-payments-bloat-pr
export PATH=/tmp/bench-e2e-cp-fallback-bin:/usr/local/bin:/usr/bin:/bin
export TXGEN_TEMPO_BIN=/home/ubuntu/repos/txgen/target/release/txgen-tempo
export TXGEN_BENCH_BIN=/home/ubuntu/.cargo/bin/bench
export CARGO_BUILD_JOBS=8
revision=f62969a95e8a787d2956f3509d25c533bdaac746
suite=bench-results/state-path-controls-patched-20260923-v4
binary=${STATE_PATH_FEATURE_BINARY:?Set STATE_PATH_FEATURE_BINARY to the verified patched binary}
build_manifest=$(dirname "$binary")/build-manifest.json
test -x "$binary"
test -f "$build_manifest"
node - "$binary" "$build_manifest" "$revision" <<'JS'
const assert = require('node:assert/strict'), fs = require('node:fs');
const {execFileSync} = require('node:child_process');
const [binary, file, revision] = process.argv.slice(2);
const build = JSON.parse(fs.readFileSync(file));
assert.equal(build.tempo_base, revision, 'wrong source base');
assert.equal(execFileSync('sha256sum', [binary], {encoding: 'utf8'}).split(' ')[0], build.binary_sha256, 'binary hash mismatch');
assert.equal(/^Commit SHA: (.+)$/m.exec(execFileSync(binary, ['--version'], {encoding: 'utf8'}))?.[1], revision, 'stale embedded commit metadata');
const path = require('node:path');
const observer = JSON.parse(fs.readFileSync(path.join(path.dirname(binary), 'observer-manifest.json')));
assert.equal(execFileSync('sha256sum', [path.join(path.dirname(binary), 'read_finish_checkpoint')], {encoding: 'utf8'}).split(' ')[0], observer.helper_sha256, 'checkpoint helper hash mismatch');
JS
exec 9>/tmp/tempo-general-state-access-20260922.lock
flock -n 9
test "$(git rev-parse HEAD)" = "$revision"
test -d /reth-bench-a/tempo_e2e_100000mb_state_access_isolated_roles.virgin
test -d /reth-bench-b/tempo_e2e_100000mb_state_access_isolated_roles.virgin
mkdir -p "$suite"
cp "$build_manifest" "$suite/build-manifest.json"
cp "$(dirname "$binary")/observer-manifest.json" "$suite/observer-manifest.json"
finish() {
    local rc=$?
    if (( rc != 0 )); then
        sudo -n systemctl stop tempo-e2e-a-feature-1.scope tempo-e2e-b-feature-1.scope || true
    fi
    printf '%s\n' "$rc" > "$suite/exit-code"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
git diff -- bench-e2e.nu contrib/bench/txgen/helpers.nu > "$suite/harness.patch"
cp bench-e2e.nu "$suite/bench-e2e.nu"
cp "$0" "$suite/runner.sh"
sha256sum bench-e2e.nu contrib/bench/run-state-path-controls.sh contrib/bench/state-path-observer.cjs > "$suite/harness-sha256.txt"
/usr/local/bin/nu --no-config-file -c 'source contrib/bench/txgen/helpers.nu; let status = (txgen-run-streaming-command "echo sender-preflight-ok"); exit $status'
printf 'Ordinary state-path suite started %s\n' "$(date --iso-8601=seconds)"
for scenario in state_paths_read state_paths_write; do
    export BENCHMARK_ID="local-ordinary-patched-v4-${scenario}-20260923"
    printf '\nCASE_START %s %s\n' "$scenario" "$(date --iso-8601=seconds)"
    set +e
    /usr/local/bin/nu --no-config-file bench-e2e.nu e2e \
        --baseline "$revision" --feature "$revision" \
        --feature-binary "$binary" --feature-name f62969a-payload-cancel-cache-fix \
        --preset "$scenario" --preset-path "$PWD/contrib/bench/txgen/presets/${scenario}.yml" \
        --tps 50000 --duration 1200 --accounts 1000 \
        --summary-warmup-blocks 0 --summary-warmup-seconds 600 \
        --bloat 100 --state-access-bloat --isolated-roles --observe-state-paths \
        --token-count 1 --gas-limit 1000000000000 --general-gas-limit 1000000000000 \
        --run-pairs 1 --run-side feature --profile profiling \
        '--feature-args=--rpc-cache.max-blocks 128 --rpc-cache.max-receipts 128 --builder.max-transactions 900' \
        --bench-env RUST_LOG=error
    rc=$?
    set -e
    node - "$suite" "$scenario" "$BENCHMARK_ID" "$rc" <<'JS'
const fs = require('node:fs'), path = require('node:path');
const [suite, scenario, id, code] = process.argv.slice(2);
const results = fs.readdirSync('bench-results').filter(name => /^20\d{6}-/.test(name)).sort().reverse()
  .map(name => path.join('bench-results', name)).find(dir => {
    try { return JSON.parse(fs.readFileSync(path.join(dir, 'summary-config.json'))).benchmark_id === id; }
    catch { return false; }
  });
const file = path.join(suite, 'manifest.json');
const manifest = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : {reference_results: 'bench-results/20260922-152637-070', cases: []};
manifest.build = JSON.parse(fs.readFileSync(path.join(suite, 'build-manifest.json')));
manifest.reference_comparison = 'Historical unpatched SLOAD reference; not a same-binary comparison.';
const entry = {scenario, benchmark_id: id, results_dir: results, exit_code: Number(code), finished_at: new Date().toISOString()};
if (results) fs.copyFileSync(path.join(suite, 'observer-manifest.json'), path.join(results, 'observer-manifest.json'));
manifest.attempts ||= [...manifest.cases];
manifest.attempts.push(entry);
manifest.cases = manifest.cases.filter(item => item.scenario !== scenario);
manifest.cases.push(entry);
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
JS
    printf 'CASE_FINISH %s status=%s %s\n' "$scenario" "$rc" "$(date --iso-8601=seconds)"
    if (( rc != 0 )); then exit "$rc"; fi
done
node contrib/bench/analyze-state-access.cjs "$suite"
node contrib/bench/analyze-state-path-controls.cjs "$suite"
printf 'Ordinary state-path suite finished %s\n' "$(date --iso-8601=seconds)"
