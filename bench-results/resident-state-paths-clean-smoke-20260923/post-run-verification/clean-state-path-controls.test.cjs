'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {execFileSync, spawnSync} = require('node:child_process');
const {measurementTiming, readTiming} = require('./state-path-timing.cjs');
const {markdown} = require('./analyze-state-path-controls.cjs');
const root = path.resolve(__dirname, '../..');
const script = path.join(__dirname, 'run-clean-state-path-controls.sh');
const env = {...process.env, TEMPO_BIN:'/usr/bin/true', XTASK_BIN:'/usr/bin/true',
  STATE_PATH_CHECKPOINT_TOOL:'/usr/bin/true', TXGEN_TEMPO_BIN:'/usr/bin/true', TXGEN_BENCH_BIN:'/usr/bin/true',
  STATE_PATH_DURATION:'360', STATE_PATH_WARMUP:'60', STATE_PATH_TPS:'5000', STATE_PATH_MAX_TRANSACTIONS:'900'};

test('clean runner uses fresh zero-bloat initialization and the two ordinary presets', () => {
  const output = execFileSync('bash', [script, '--dry-run'], {cwd:root, env, encoding:'utf8'});
  assert.match(output, /BENCH_DISABLE_SCHELK=1/);
  assert.equal((output.match(/--bloat 0/g) || []).length, 2);
  assert.equal((output.match(/--force-bloat/g) || []).length, 2);
  assert.match(output, /--xtask-binary/);
  assert.match(output, /--snapshot-suffix resident_controls/);
  assert.match(output, /--preset state_paths_read/);
  assert.match(output, /--preset state_paths_write/);
  assert.match(output, /--duration 360/);
  assert.match(output, /--summary-warmup-seconds 60/);
  assert.match(output, /--builder\.max-transactions/);
  assert.doesNotMatch(output, /--state-access-bloat|100000mb|state_access_dependent/);
});

test('uncapped mode omits the transaction limit instead of setting it to zero', () => {
  const output = execFileSync('bash', [script, '--dry-run'], {cwd:root,
    env:{...env, STATE_PATH_MAX_TRANSACTIONS:'none'}, encoding:'utf8'});
  assert.doesNotMatch(output, /--builder\.max-transactions/);
});

test('harness rejects an unsafe clean snapshot suffix before touching storage', () => {
  const result = spawnSync('nu', ['--no-config-file','bench-e2e.nu','e2e','--baseline','HEAD',
    '--feature','HEAD','--bloat','0','--snapshot-suffix','../outside'], {cwd:root,encoding:'utf8'});
  assert.notEqual(result.status,0);
  assert.match(result.stderr,/simple filename suffix/);
});

test('runner rejects invalid timing and transaction caps before starting nodes', () => {
  for (const config of [{STATE_PATH_DURATION:'60'}, {STATE_PATH_WARMUP:'360'},
    {STATE_PATH_MAX_TRANSACTIONS:'0'}, {STATE_PATH_TPS:'-1'}, {STATE_PATH_DURATION:'1;false'}]) {
    const result = spawnSync('bash', [script, '--dry-run'], {cwd:root, env:{...env,...config}, encoding:'utf8'});
    assert.equal(result.status, 2, result.stderr);
  }
});

test('measurement windows use the declared warmup and retain five equal trend slices', () => {
  assert.deepEqual(measurementTiming(360,60), {duration_seconds:360,warmup_seconds:60,from_ms:60000,to_ms:360000,slice_ms:60000});
  assert.equal(measurementTiming(1200).slice_ms,120000);
  for (const [duration,warmup] of [[60,60],[0,0],[360,-1],[360,0.5]]) assert.throws(()=>measurementTiming(duration,warmup));
});

test('analysis reads local timing metadata without depending on an archived suite', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(),'state-path-timing-'));
  try {
    const report = {metadata:{run_duration_secs:'1200'}};
    assert.equal(readTiming(directory,report).warmup_seconds,600);
    fs.writeFileSync(path.join(directory,'summary-config.json'),JSON.stringify({summary_warmup_seconds:60}));
    assert.equal(readTiming(directory,{metadata:{run_duration_secs:'360'}}).warmup_seconds,60);
  } finally {fs.rmSync(directory,{recursive:true,force:true});}
});

test('clean reports do not claim a bloated snapshot or round tiny nonzero faults to zero', () => {
  const metrics = {wall_clock_mgas_per_second:80,aggregate_execution_mgas_per_second:2500,
    major_faults_per_mgas:0.000058,stop_reasons:{transaction_limit:600},pending_pool:{median:1000},
    builder_reverted_transactions:0,invalid_execution_attempts:0,
    other_caches:{code:{misses_per_mgas:0.03}},execution_coverage:{}};
  const output = markdown([{label:'state_paths_read',metadata:{bloat_mib:'0'},timing:measurementTiming(360,60),
    canonical:{mgas_per_second:80},builder:metrics,follower:metrics}]);
  assert.match(output,/Fresh genesis, no imported state bloat/);
  assert.match(output,/360-second loads; first 60 seconds excluded/);
  assert.match(output,/5\.80e-5/);
  assert.doesNotMatch(output,/100 GB|Twenty-minute|historical and unpatched/);
});
