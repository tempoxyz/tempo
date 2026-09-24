#!/usr/bin/env bash
# Fresh-genesis controls on the standard two-node Linux e2e benchmark host.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
if [[ ${1:-} == --help ]]; then
    printf '%s\n' 'Usage: bash contrib/bench/run-clean-state-path-controls.sh [--dry-run]' \
        'Required binaries: TEMPO_BIN, XTASK_BIN, STATE_PATH_CHECKPOINT_TOOL, TXGEN_TEMPO_BIN, TXGEN_BENCH_BIN.' \
        'Defaults: STATE_PATH_DURATION=1200 STATE_PATH_WARMUP=600 STATE_PATH_TPS=50000 STATE_PATH_MAX_TRANSACTIONS=900.' \
        'Set STATE_PATH_MAX_TRANSACTIONS=none to omit the builder transaction-count cap.' \
        'STATE_PATH_SUITE_DIR overrides the new result directory. No bloat database or archived results are used.'
    exit 0
fi
[[ $# == 0 || ( $# == 1 && $1 == --dry-run ) ]] || { printf 'Unknown argument\n' >&2; exit 2; }
duration=${STATE_PATH_DURATION:-1200}
warmup=${STATE_PATH_WARMUP:-600}
tps=${STATE_PATH_TPS:-50000}
cap=${STATE_PATH_MAX_TRANSACTIONS:-900}
for value in "$duration" "$warmup" "$tps"; do
    [[ $value =~ ^(0|[1-9][0-9]{0,5})$ ]] || { printf 'Invalid numeric configuration\n' >&2; exit 2; }
done
(( duration <= 3000 && duration - warmup >= 270 && tps > 0 && tps <= 50000 )) || {
    printf 'Require duration <= 3000, at least 270 measured seconds, and TPS in 1..50000\n' >&2; exit 2;
}
[[ $cap == none || $cap =~ ^[1-9][0-9]{0,5}$ ]] || { printf 'Cap must be a positive integer or none\n' >&2; exit 2; }
export TEMPO_BIN=${TEMPO_BIN:-$PWD/target/profiling/tempo}
export XTASK_BIN=${XTASK_BIN:-$PWD/target/profiling/tempo-xtask}
export STATE_PATH_CHECKPOINT_TOOL=${STATE_PATH_CHECKPOINT_TOOL:-$(dirname "$TEMPO_BIN")/examples/read_finish_checkpoint}
export TXGEN_TEMPO_BIN=${TXGEN_TEMPO_BIN:-txgen-tempo}
export TXGEN_BENCH_BIN=${TXGEN_BENCH_BIN:-bench}
for name in TEMPO_BIN XTASK_BIN STATE_PATH_CHECKPOINT_TOOL TXGEN_TEMPO_BIN TXGEN_BENCH_BIN; do
    resolved=$(command -v "${!name}") || { printf 'Missing executable: %s=%s\n' "$name" "${!name}" >&2; exit 2; }
    [[ -x $resolved ]] || { printf 'Not executable: %s\n' "$resolved" >&2; exit 2; }
    printf -v "$name" '%s' "$(realpath "$resolved")"
    export "$name"
done
nu_bin=$(command -v nu)
revision=$(git rev-parse HEAD)
suite=${STATE_PATH_SUITE_DIR:-$PWD/bench-results/resident-state-paths-$(date -u +%Y%m%d-%H%M%S)-$$}
suite=$(realpath -m "$suite")
feature_args='--rpc-cache.max-blocks 128 --rpc-cache.max-receipts 128'
if [[ $cap != none ]]; then feature_args+=" --builder.max-transactions $cap"; fi
common=(--no-config-file bench-e2e.nu e2e --baseline "$revision" --feature "$revision"
    --feature-binary "$TEMPO_BIN" --xtask-binary "$XTASK_BIN" --feature-name resident-control
    --tps "$tps" --duration "$duration" --accounts 1000
    --summary-warmup-blocks 0 --summary-warmup-seconds "$warmup"
    --bloat 0 --force-bloat --snapshot-suffix resident_controls --isolated-roles --observe-state-paths --token-count 1
    --gas-limit 1000000000000 --general-gas-limit 1000000000000
    --run-pairs 1 --run-side feature --profile profiling --skip-summary
    "--feature-args=$feature_args" --bench-env RUST_LOG=error)
# Never promote an entire Schelk volume or touch the unrelated large snapshots.
export BENCH_DISABLE_SCHELK=1
if [[ ${1:-} == --dry-run ]]; then
    printf 'BENCH_DISABLE_SCHELK=1\n'
    for scenario in state_paths_read state_paths_write; do
        printf '%q ' "$nu_bin" "${common[@]}" --preset "$scenario" --preset-path "$PWD/contrib/bench/txgen/presets/$scenario.yml"
        printf '\n'
    done
    exit 0
fi
# Share the lock used by the existing state-path benchmark on this host.
exec 9>/tmp/tempo-general-state-access-20260922.lock
flock -n 9 || { printf 'Another state-path benchmark owns the host lock\n' >&2; exit 1; }
test ! -e "$suite" || { printf 'Result directory already exists: %s\n' "$suite" >&2; exit 1; }
mkdir -p "$suite/source"
started=0
finish() {
    local rc=$?
    if (( rc != 0 && started )); then
        sudo -n systemctl stop tempo-e2e-a-feature-1.scope tempo-e2e-b-feature-1.scope || true
    fi
    printf '%s\n' "$rc" > "$suite/exit-code"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
node - "$suite" "$revision" "$duration" "$warmup" "$tps" "$cap" <<'JS'
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const [suite, revision, duration, warmup, tps, cap] = process.argv.slice(2);
const binaries = {};
for (const name of ['TEMPO_BIN', 'XTASK_BIN', 'STATE_PATH_CHECKPOINT_TOOL', 'TXGEN_TEMPO_BIN', 'TXGEN_BENCH_BIN']) {
  const file = process.env[name];
  binaries[name] = {path: file, sha256: execFileSync('sha256sum', [file], {encoding:'utf8'}).split(' ')[0]};
}
binaries.TEMPO_BIN.version = execFileSync(process.env.TEMPO_BIN, ['--version'], {encoding:'utf8'});
assert.equal(/^Commit SHA: (.+)$/m.exec(binaries.TEMPO_BIN.version)?.[1], revision, 'node binary must identify the checked-out base commit');
const manifest = {created_at:new Date().toISOString(), configuration:{bloat_mib:0, accounts:1000,
  duration_seconds:Number(duration), warmup_seconds:Number(warmup), target_tps:Number(tps),
  max_transactions:cap === 'none' ? null : Number(cap), snapshot_mode:'copy', fresh_genesis:true},
  build:{tempo_base:revision, binary_sha256:binaries.TEMPO_BIN.sha256}, binaries, cases:[]};
fs.writeFileSync(path.join(suite, 'manifest.json'), JSON.stringify(manifest,null,2)+'\n');
JS
git diff --binary > "$suite/worktree.patch"
git status --short > "$suite/worktree-status.txt"
files=(bench-e2e.nu tempo.nu contrib/bench/run-clean-state-path-controls.sh
    contrib/bench/state-path-timing.cjs contrib/bench/state-path-observer.cjs
    contrib/bench/analyze-state-access.cjs contrib/bench/analyze-state-path-controls.cjs
    contrib/bench/txgen/helpers.nu contrib/bench/txgen/presets/state_paths_read.yml
    contrib/bench/txgen/presets/state_paths_write.yml contrib/bench/txgen/state-path-vault.abi.json
    contrib/bench/txgen/vault/bytecodes/StrategyVault.bin bin/tempo/examples/read_finish_checkpoint.rs)
cp --parents "${files[@]}" "$suite/source"
sha256sum "${files[@]}" > "$suite/source-sha256.txt"
lscpu > "$suite/lscpu.txt"
free -b > "$suite/memory.txt"
df -B1 /reth-bench-a /reth-bench-b > "$suite/filesystems.txt"
printf 'SUITE_DIR=%s\n' "$suite"
for scenario in state_paths_read state_paths_write; do
    export BENCHMARK_ID="$(basename "$suite")-$scenario"
    printf 'CASE_START %s %s\n' "$scenario" "$(date -u --iso-8601=seconds)"
    started=1
    set +e
    "$nu_bin" "${common[@]}" --preset "$scenario" --preset-path "$PWD/contrib/bench/txgen/presets/$scenario.yml" > "$suite/$scenario.log" 2>&1
    rc=$?
    set -e
    node - "$suite" "$scenario" "$BENCHMARK_ID" "$rc" <<'JS'
const fs=require('node:fs'), path=require('node:path'), assert=require('node:assert/strict'), crypto=require('node:crypto');
const [suite,scenario,id,rc]=process.argv.slice(2);
const result=fs.readdirSync('bench-results').filter(n=>/^20\d{6}-/.test(n)).sort().reverse()
  .map(n=>path.resolve('bench-results',n)).find(d=>{try{return JSON.parse(fs.readFileSync(path.join(d,'summary-config.json'))).benchmark_id===id;}catch{return false;}});
const file=path.join(suite,'manifest.json'), m=JSON.parse(fs.readFileSync(file));
const entry={scenario,benchmark_id:id,results_dir:result,exit_code:Number(rc),finished_at:new Date().toISOString()};
if(Number(rc)===0&&result){
  const meta='/reth-bench-a/tempo_e2e_0mb_isolated_roles_resident_controls/.bench-meta';
  for(const name of ['genesis.json','marker.json']) fs.copyFileSync(path.join(meta,name),path.join(result,name));
  entry.genesis_sha256=crypto.createHash('sha256').update(fs.readFileSync(path.join(result,'genesis.json'))).digest('hex');
}
m.cases.push(entry);
fs.writeFileSync(file,JSON.stringify(m,null,2)+'\n');
if(Number(rc)===0){assert.ok(result,'missing results');const report=JSON.parse(fs.readFileSync(path.join(result,'report-feature-1.json')));assert.equal(Number(report.metadata.bloat_mib),0);}
JS
    printf 'CASE_FINISH %s status=%s %s\n' "$scenario" "$rc" "$(date -u --iso-8601=seconds)"
    if (( rc != 0 )); then tail -n 60 "$suite/$scenario.log"; exit "$rc"; fi
done
node contrib/bench/analyze-state-access.cjs "$suite" > "$suite/analysis.log"
node contrib/bench/analyze-state-path-controls.cjs "$suite" > "$suite/throughput.log"
printf 'Reports: %s/throughput.md and validation.md\n' "$suite"
