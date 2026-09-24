'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync, spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const base = ['--no-config-file', 'bench-e2e.nu', 'state-access-bloat-worst-case'];
const run = (args, env = process.env) => execFileSync('nu', [...base, ...args], {cwd: root, encoding: 'utf8', env});

test('native suite lists all workloads and uses the saved matched defaults', () => {
  const listing = run(['--list']);
  for (const id of ['sload', 'bytecode', 'writes']) assert.match(listing, new RegExp(id));
  const plan = JSON.parse(run(['--baseline', 'HEAD', '--feature', 'HEAD', '--dry-run']));
  assert.deepEqual(plan.configuration.cases.map(c => c.id), ['sload', 'bytecode', 'writes']);
  assert.deepEqual([plan.configuration.tps, plan.configuration.duration, plan.configuration.warmup], [1000, 1200, 600]);
  assert.equal(plan.options.feature_binary, '');
  assert.equal(plan.options.run_side, 'feature');
  assert.equal(plan.configuration.transaction_cap, null);
});

test('native flags select a case and preserve explicit git refs and comparison options', () => {
  const plan = JSON.parse(run(['--case', 'writes', '--baseline', 'baseline-ref', '--feature', 'feature-ref',
    '--run-side', 'comparison', '--run-pairs', '2', '--tps', '2000', '--duration', '900',
    '--summary-warmup-seconds', '300', '--feature-args=--example.feature 2', '--baseline-args=--example.baseline 1',
    '--baseline-env', 'BASELINE=1', '--feature-env', 'FEATURE=2', '--bench-env', 'RUST_LOG=warn', '--no-cache', '--dry-run']));
  assert.deepEqual(plan.configuration.cases.map(c => c.id), ['writes']);
  assert.deepEqual([plan.configuration.tps, plan.configuration.duration, plan.configuration.warmup], [2000, 900, 300]);
  assert.equal(plan.options.baseline, 'baseline-ref');
  assert.equal(plan.options.feature, 'feature-ref');
  assert.equal(plan.options.run_side, 'comparison');
  assert.equal(plan.options.run_pairs, 2);
  assert.equal(plan.options.no_cache, true);
  assert.equal(plan.options.feature_env, 'FEATURE=2');
  assert.equal(plan.options.baseline_env, 'BASELINE=1');
  assert.equal(plan.options.bench_env, 'RUST_LOG=warn');
});

test('native configuration ignores legacy shell overrides, including TEMPO_BIN', () => {
  const plan = JSON.parse(run(['--dry-run'], {...process.env, HISTORY_TPS: '50000', HISTORY_DURATION: '60', TEMPO_BIN: '/not/a/binary'}));
  assert.equal(plan.configuration.tps, 1000);
  assert.equal(plan.configuration.duration, 1200);
  assert.equal(plan.options.feature_binary, '');
});

test('invalid native options fail in dry-run before any database or build access', () => {
  for (const args of [['--case', 'unknown'], ['--run-side', 'invalid'], ['--run-pairs', '0'],
    ['--duration', '60'], ['--tps', '0'], ['--feature-binary', '/tmp/local-tempo', '--run-side', 'comparison']]) {
    const result = spawnSync('nu', [...base, ...args, '--dry-run'], {cwd: root, encoding: 'utf8'});
    assert.notEqual(result.status, 0, args.join(' '));
    assert.doesNotMatch(result.stdout, /Restoring snapshot|Removing stale|Building tempo/);
  }
});

test('real native dispatcher forwards both sides and fixture flags into main e2e', () => {
  const source = fs.readFileSync(path.join(root, 'bench-e2e.nu'), 'utf8');
  const signature = /def "main e2e" \[[\s\S]*?\n\] \{/.exec(source)[0];
  const dispatch = source.slice(source.indexOf('def run-state-access-case '), source.indexOf('# Runs under the same flock'));
  const plan = JSON.parse(run(['--case', 'bytecode', '--baseline', 'base-ref', '--feature', 'feature-ref',
    '--run-side', 'comparison', '--run-pairs', '2', '--feature-args=--example.feature 2', '--baseline-args=--example.baseline 1', '--dry-run']));
  // Rebind only the dispatcher to a no-I/O e2e stub with the production signature.
  const definitions = source.slice(0, source.indexOf('def merge-e2e-features'));
  const program = `${definitions}\n${signature}
    {baseline: $baseline, feature: $feature, preset: $preset, preset_path: $preset_path,
     tps: $tps, duration: $duration, accounts: $accounts, warmup: $summary_warmup_seconds,
     bloat: $bloat, state_access_bloat: $state_access_bloat, snapshot_suffix: $snapshot_suffix,
     isolated_roles: $isolated_roles, observe_state_paths: $observe_state_paths,
     gas_limit: $gas_limit, general_gas_limit: $general_gas_limit,
     run_side: $run_side, run_pairs: $run_pairs, baseline_args: $baseline_args, feature_args: $feature_args,
     feature_binary: $feature_binary, single_restore: $single_restore, clickhouse_run: $clickhouse_run}
  }\n${dispatch}\nlet p = ($env.NATIVE_TEST_PLAN | from json)\nrun-state-access-case $p.options $p.configuration ($p.configuration.cases | first) | to json`;
  const forwarded = JSON.parse(execFileSync('nu', ['--no-config-file', '-c', program], {
    cwd: root, encoding: 'utf8', env: {...process.env, NATIVE_TEST_PLAN: JSON.stringify(plan)}}));
  assert.equal(forwarded.baseline, 'base-ref');
  assert.equal(forwarded.feature, 'feature-ref');
  assert.equal(forwarded.run_side, 'comparison');
  assert.equal(forwarded.run_pairs, 2);
  assert.equal(forwarded.preset, 'history_code');
  assert.equal(forwarded.preset_path, 'contrib/bench/txgen/presets/history_code.yml');
  assert.deepEqual([forwarded.tps, forwarded.duration, forwarded.accounts, forwarded.warmup], [1000, 1200, 1000, 600]);
  assert.equal(forwarded.bloat, 100);
  assert.equal(forwarded.snapshot_suffix, 'history_paths');
  for (const key of ['state_access_bloat', 'isolated_roles', 'observe_state_paths']) assert.equal(forwarded[key], true);
  assert.equal(forwarded.feature_binary, '');
  assert.equal(forwarded.single_restore, false);
  assert.equal(forwarded.clickhouse_run, '');
  assert.match(forwarded.baseline_args, /--example.baseline 1$/);
  assert.match(forwarded.feature_args, /--example.feature 2$/);
  assert.doesNotMatch(forwarded.feature_args, /max-transactions|disable.*prewarm/);
});

test('child failure is recorded without claiming success or cleaning up an unstarted suite', () => {
  const os = require('node:os');
  const {finish} = require('./state-access-suite-process.cjs');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'native-state-access-test-'));
  const plan = path.join(dir, 'configuration.json'), manifest = path.join(dir, 'manifest.json');
  let cleaned = 0;
  try {
    fs.writeFileSync(plan, JSON.stringify({benchmark_id: 'test'}));
    assert.equal(finish(plan, 23, () => cleaned++), 23);
    assert.equal(cleaned, 0);
    assert.equal(JSON.parse(fs.readFileSync(manifest)).status, 'failed');
    fs.writeFileSync(manifest, JSON.stringify({status: 'running', cases: []}));
    assert.equal(finish(plan, 1, () => cleaned++), 1);
    assert.equal(cleaned, 1);
    fs.writeFileSync(manifest, JSON.stringify({status: 'running', cases: []}));
    assert.equal(finish(plan, 0, () => cleaned++), 1, 'incomplete manifest must not pass');
    fs.writeFileSync(manifest, JSON.stringify({status: 'complete', cases: []}));
    assert.equal(finish(plan, 0, () => cleaned++), 0);
    assert.equal(fs.readFileSync(path.join(dir, 'exit-code'), 'utf8'), '0\n');
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
