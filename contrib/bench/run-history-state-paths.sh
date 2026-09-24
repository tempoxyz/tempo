#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
root=$PWD
for arg in "$@"; do
    case "$arg" in --list|--show|--help) exec node contrib/bench/state-access-config.cjs "$@";; esac
done
configuration=$(node contrib/bench/state-access-config.cjs --resolve "$@") || exit 2
fields=$(node -e 'const c=JSON.parse(process.argv[1]); console.log([c.duration,c.warmup,c.tps,c.accounts,c.gas_limit,c.node_args,c.dry_run,...c.cases.map(x=>x.scenario)].join("\n"));' "$configuration")
mapfile -t settings <<< "$fields"
duration=${settings[0]}
warmup=${settings[1]}
tps=${settings[2]}
accounts=${settings[3]}
gas_limit=${settings[4]}
node_args=${settings[5]}
dry_run=${settings[6]}
scenarios=("${settings[@]:7}")
binary=${TEMPO_BIN:-$root/target/profiling/tempo}
export STATE_PATH_CHECKPOINT_TOOL=${STATE_PATH_CHECKPOINT_TOOL:-$root/target/profiling/examples/read_finish_checkpoint}
export TXGEN_TEMPO_BIN=${TXGEN_TEMPO_BIN:-$root/../txgen/target/release/txgen-tempo}
export TXGEN_BENCH_BIN=${TXGEN_BENCH_BIN:-$HOME/.cargo/bin/bench}
export BENCH_DISABLE_SCHELK=1
revision=$(git rev-parse HEAD)
base=tempo_e2e_100000mb_state_access_isolated_roles_history_paths
a=/reth-bench-a/$base
b=/reth-bench-b/$base
suite=${HISTORY_SUITE_DIR:-$root/bench-results/history-state-paths-$(date -u +%Y%m%d-%H%M%S)}
args=(--baseline "$revision" --feature "$revision" --feature-binary "$binary"
    --feature-name matched-state-access --tps "$tps" --duration "$duration" --accounts "$accounts"
    --summary-warmup-blocks 0 --summary-warmup-seconds "$warmup"
    --bloat 100 --state-access-bloat --snapshot-suffix history_paths --single-restore --isolated-roles --observe-state-paths
    --token-count 1 --gas-limit "$gas_limit" --general-gas-limit "$gas_limit"
    --run-pairs 1 --run-side feature --profile profiling
    "--feature-args=$node_args"
    --bench-env RUST_LOG=error)
if [[ $dry_run == true ]]; then
    printf 'BENCH_DISABLE_SCHELK=1; dedicated prebuilt snapshots, no builder transaction cap\n'
    for scenario in "${scenarios[@]}"; do
        printf '%q ' nu --no-config-file bench-e2e.nu e2e "${args[@]}" --preset "$scenario" --preset-path "$root/contrib/bench/txgen/presets/$scenario.yml"
        printf '\n'
    done
    exit
fi
for tool in "$binary" "$STATE_PATH_CHECKPOINT_TOOL" "$TXGEN_TEMPO_BIN" "$TXGEN_BENCH_BIN"; do test -x "$tool"; done
exec 9>/tmp/tempo-general-state-access-20260922.lock
flock -n 9
test ! -e "$suite"
TXGEN_HISTORY_CODE_COUNT=$(node - "$configuration" "$a.virgin" "$b.virgin" <<'JS'
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const config=JSON.parse(process.argv[2]);
const fixtures=process.argv.slice(3).map(dir=>{
  assert.ok(!fs.existsSync(path.join(dir,'.bench-meta/history-state-paths.incomplete')));
  return JSON.parse(fs.readFileSync(path.join(dir,'.bench-meta/history-state-paths.json')));
});
assert.deepEqual(fixtures[0],fixtures[1]);
assert.ok(fixtures[0].total_code_bytes>=100000*1024*1024,'100000 MiB active code corpus required');
assert.equal(fixtures[0].code_bytes,24576);
assert.equal(fixtures[0].code_count,config.fixture_requirements.code_count);
const artifact=JSON.parse(fs.readFileSync('contrib/bench/txgen/history-state-paths.json'));
const hash=execFileSync(process.env.CAST_BIN || path.join(process.env.HOME,'.foundry/bin/cast'),['keccak',artifact.deployedBytecode.object],{encoding:'utf8'}).trim();
assert.equal(fixtures[0].router_code_hash,hash,'fixture router differs: run update-history-router.sh before benchmarking');
console.log(fixtures[0].code_count);
JS
)
export TXGEN_HISTORY_CODE_COUNT
# Parse both complete presets and derive signers before the expensive restores.
for scenario in "${scenarios[@]}"; do
    TXGEN_ACCOUNTS="$accounts" TXGEN_STATE_ACCESS_PAGE_COUNT=399999 \
        "$TXGEN_TEMPO_BIN" addresses -s "$root/contrib/bench/txgen/presets/$scenario.yml" -f shell >/dev/null
done
mkdir -p "$suite/source"
git diff > "$suite/worktree.patch"
cp --parents bench-e2e.nu tempo.nu bin/tempo/examples/prepare_history_state_paths.rs \
    contrib/bench/run-history-state-paths.sh contrib/bench/prepare-history-state-paths.sh \
    contrib/bench/update-history-router.sh \
    contrib/bench/state-access-config.cjs contrib/bench/configs/state-access-bloated.json \
    contrib/bench/configs/README.md contrib/bench/history-state-paths.md \
    contrib/bench/state-access-config.test.cjs contrib/bench/history-state-paths.test.cjs \
    contrib/bench/state-path-observer.cjs contrib/bench/state-path-timing.cjs contrib/bench/state-path-memory.cjs contrib/bench/state-path-durability.cjs \
    contrib/bench/state-access-validation.cjs \
    contrib/bench/history-state-path-validation.cjs contrib/bench/analyze-history-state-paths.cjs \
    contrib/bench/analyze-state-access.cjs contrib/bench/analyze-state-path-controls.cjs \
    contrib/bench/txgen/HistoryStatePaths.sol contrib/bench/txgen/HistoryStatePaths.t.sol \
    contrib/bench/txgen/StateAccessBenchmark.sol contrib/bench/txgen/state-access-benchmark.json \
    contrib/bench/txgen/presets/state_access_dependent.yml \
    contrib/bench/txgen/history-state-paths.json contrib/bench/txgen/presets/history_code.yml \
    contrib/bench/txgen/presets/history_write.yml "$suite/source/"
node - "$suite" "$binary" "$revision" "$configuration" "$a.virgin" <<'JS'
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const [suite,binary,revision,configuration,fixtureDir]=process.argv.slice(2);
const config=JSON.parse(configuration);
const version=execFileSync(binary,['--version'],{encoding:'utf8'});
assert.equal(/^Commit SHA: (.+)$/m.exec(version)?.[1],revision,'binary source revision differs');
const sha=file=>execFileSync('sha256sum',[file],{encoding:'utf8'}).split(' ')[0];
const fixture=JSON.parse(fs.readFileSync(path.join(fixtureDir,'.bench-meta/history-state-paths.json')));
fs.writeFileSync(path.join(suite,'configuration.json'),JSON.stringify(config,null,2)+'\n');
fs.writeFileSync(path.join(suite,'manifest.json'),JSON.stringify({started_at:new Date().toISOString(),
  build:{binary,version,binary_sha256:sha(binary),revision,checkpoint_sha256:sha(process.env.STATE_PATH_CHECKPOINT_TOOL),txgen_sha256:sha(process.env.TXGEN_TEMPO_BIN),sender_sha256:sha(process.env.TXGEN_BENCH_BIN)},
  configuration:config,
  host:{cpus:os.cpus(),total_memory_bytes:os.totalmem(),platform:os.platform()},fixture,cases:[]},null,2)+'\n');
JS
finish() {
    local rc=$?
    if (( rc != 0 )); then
        node - "$(basename "$suite")" <<'JS'
const fs=require('node:fs'),path=require('node:path');
for(const name of fs.readdirSync('bench-results').filter(name=>/^20\d{6}-/.test(name))) {
  const dir=path.join('bench-results',name);
  try {
    const config=JSON.parse(fs.readFileSync(path.join(dir,'summary-config.json')));
    if(config.benchmark_id?.startsWith(process.argv[2]+'-')) fs.writeFileSync(path.join(dir,'state-path-observer-feature-1.stop'),'stop\n');
  } catch {}
}
JS
        sudo -n systemctl stop tempo-e2e-a-feature-1.scope tempo-e2e-b-feature-1.scope || true
    fi
    printf '%s\n' "$rc" > "$suite/exit-code"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
printf 'SUITE=%s START=%s\n' "$suite" "$(date -u --iso-8601=seconds)"
for scenario in "${scenarios[@]}"; do
    # Refuse mid-suite changes instead of silently comparing different executables or fixtures.
    node - "$suite" "$a.virgin" "$b.virgin" <<'JS'
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{execFileSync}=require('node:child_process');
const m=JSON.parse(fs.readFileSync(path.join(process.argv[2],'manifest.json')));
for(const [file,expected] of [[m.build.binary,m.build.binary_sha256],[process.env.STATE_PATH_CHECKPOINT_TOOL,m.build.checkpoint_sha256],[process.env.TXGEN_TEMPO_BIN,m.build.txgen_sha256],[process.env.TXGEN_BENCH_BIN,m.build.sender_sha256]])
  assert.equal(execFileSync('sha256sum',[file],{encoding:'utf8'}).split(' ')[0],expected,'executable changed during suite');
for(const dir of process.argv.slice(3)) assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir,'.bench-meta/history-state-paths.json'))),m.fixture,'fixture changed during suite');
JS
    export BENCHMARK_ID="$(basename "$suite")-$scenario"
    printf 'CASE_START %s %s\n' "$scenario" "$(date -u --iso-8601=seconds)"
    set +e
    nu --no-config-file bench-e2e.nu e2e "${args[@]}" --preset "$scenario" \
        --preset-path "$root/contrib/bench/txgen/presets/$scenario.yml" 2>&1 | tee "$suite/$scenario.log"
    rc=${PIPESTATUS[0]}
    set -e
    node - "$suite" "$scenario" "$BENCHMARK_ID" "$rc" <<'JS'
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const [suite,scenario,id,rc]=process.argv.slice(2);
const results=fs.readdirSync('bench-results').filter(name=>/^20\d{6}-/.test(name)).sort().reverse().map(name=>path.join('bench-results',name)).find(dir=>{
  try{return JSON.parse(fs.readFileSync(path.join(dir,'summary-config.json'))).benchmark_id===id;}catch{return false;}
});
const file=path.join(suite,'manifest.json'),manifest=JSON.parse(fs.readFileSync(file));
manifest.cases.push({scenario,results_dir:results,exit_code:Number(rc),finished_at:new Date().toISOString()});
fs.writeFileSync(file,JSON.stringify(manifest,null,2)+'\n');
assert.ok(results,'no report directory recorded');
JS
    printf 'CASE_FINISH %s status=%s %s\n' "$scenario" "$rc" "$(date -u --iso-8601=seconds)"
    (( rc == 0 )) || exit "$rc"
done
node contrib/bench/analyze-history-state-paths.cjs "$suite"
node - "$suite" <<'JS'
const fs=require('node:fs'),path=require('node:path');
const suite=path.resolve(process.argv[2]),m=JSON.parse(fs.readFileSync(path.join(suite,'manifest.json')));
const result={completed_at:new Date().toISOString(),suite,configuration_id:m.configuration.id,
  cases:m.cases.map(c=>c.scenario),complete_three_way:m.cases.length===3,
  report:path.join(suite,'throughput.md'),data:path.join(suite,'throughput.json')};
fs.writeFileSync(path.join(suite,'completion.json'),JSON.stringify(result,null,2)+'\n');
fs.writeFileSync('bench-results/state-access-bloated-latest.json',JSON.stringify(result,null,2)+'\n');
JS
printf 'SUITE_FINISH %s\n' "$(date -u --iso-8601=seconds)"
