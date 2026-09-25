#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createHash} = require('node:crypto');
const {spawn, execFileSync} = require('node:child_process');

const MEMORY = 20 * 2 ** 30;
const ORDER = [
  {reads: 4096, prewarming: true}, {reads: 128, prewarming: true},
  {reads: 128, prewarming: false}, {reads: 4096, prewarming: false},
];

function makePlan(base, item, id) {
  const plan = structuredClone(base);
  plan.benchmark_id = id;
  plan.configuration.id = item.scenario ? 'state-access-max-tx' : 'sload-size-isolation';
  plan.configuration.prewarming = item.prewarming ? 'builder and engine enabled' : 'builder and engine disabled';
  plan.configuration.cases = item.scenario ? [structuredClone(base.configuration.cases.find(c => c.scenario === item.scenario))] : [{id: 'sload', scenario: item.reads === 128 ? 'history_read' : 'state_access_dependent',
    description: `${item.reads} cold history-selected SLOADs`, operations_per_transaction: item.reads,
    minimum_history_advanced_fraction: item.reads === 128 ? 0.9 : 0}];
  plan.options.node_memory = '20G';
  plan.options.node_swap_limit = '0';
  plan.options.allow_first_sload_samples = item.reads === 4096;
  plan.options.feature_label = id;
  plan.options.feature_env = 'RETH_BYTECODE_PREFETCH=1';
  plan.options.feature_args = item.prewarming ? '' : '--builder.disable-prewarming --engine.disable-prewarming';
  return plan;
}

function checkMemory(sample) {
  const limits = sample.memory_limits;
  assert.ok(limits, 'missing live memory-limit evidence');
  assert.equal(Number(limits['memory.max']), MEMORY, 'unexpected node memory cap');
  assert.equal(Number(limits['memory.swap.max']), 0, 'node swap must be disabled');
  assert.equal(Number(limits['memory.swap.current']), 0, 'node swapped during run');
  assert.ok(Number(limits['memory.current']) <= MEMORY * 1.01, 'node exceeded cap');
  assert.equal(sample.memory_events?.oom, 0, 'node hit OOM');
  assert.equal(sample.memory_events?.oom_kill, 0, 'node was OOM-killed');
}

function liveEvidence(item, binary) {
  const nodes = {};
  for (const node of ['a', 'b']) {
    const dir = `/sys/fs/cgroup/system.slice/tempo-e2e-${node}-feature-1.scope`;
    if (!fs.existsSync(`${dir}/cgroup.procs`)) return null;
    const pids = fs.readFileSync(`${dir}/cgroup.procs`, 'utf8').trim().split(/\s+/);
    const processInfo = pids.map(pid => {
      try { return {pid, args: fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean)}; }
      catch { return null; }
    }).find(p => p?.args[0] === binary && p.args.includes('node'));
    if (!processInfo) return null;
    const args = processInfo.args;
    assert.equal(args.includes('--builder.disable-prewarming'), node === 'b' || !item.prewarming);
    assert.equal(args.includes('--engine.disable-prewarming'), !item.prewarming);
    const limits = Object.fromEntries(['memory.max','memory.current','memory.swap.max','memory.swap.current']
      .map(file => [file, fs.readFileSync(`${dir}/${file}`, 'utf8').trim()]));
    const events = Object.fromEntries(fs.readFileSync(`${dir}/memory.events`, 'utf8').trim().split('\n')
      .map(line => { const [key, value] = line.split(/\s+/); return [key, Number(value)]; }));
    nodes[node] = {...processInfo, memory_limits: limits, memory_events: events,
      cpus: /Cpus_allowed_list:\s*(.+)/.exec(fs.readFileSync(`/proc/${processInfo.pid}/status`, 'utf8'))?.[1]};
    checkMemory(nodes[node]);
    assert.equal(nodes[node].cpus, node === 'a' ? '0-7,16-23' : '8-15,24-31');
  }
  return {unix_ms: Date.now(), nodes};
}

async function main() {
  const [binaryArg, outputArg, mode, selectedCase] = process.argv.slice(2);
  assert.ok(binaryArg && outputArg && (!mode || mode === '--max-transaction-size'), 'usage: run-sload-size-isolation.cjs BINARY NEW_OUTPUT_DIR [--max-transaction-size [sload|bytecode]]');
  const maxTx = mode === '--max-transaction-size';
  assert.ok(!selectedCase || (maxTx && ['sload','bytecode'].includes(selectedCase)), 'invalid max-size case selection');
  const binary = path.resolve(binaryArg), output = path.resolve(outputArg);
  assert.ok(!fs.existsSync(path.join(output, 'experiment.json')), 'refusing to overwrite an experiment');
  for (const file of [binary, process.env.STATE_PATH_CHECKPOINT_TOOL, process.env.TXGEN_TEMPO_BIN, process.env.TXGEN_BENCH_BIN, process.env.STATE_PATH_CACHE_EVICT_TOOL]) {
    assert.ok(file, 'set STATE_PATH_CHECKPOINT_TOOL, TXGEN_TEMPO_BIN, TXGEN_BENCH_BIN and STATE_PATH_CACHE_EVICT_TOOL');
    fs.accessSync(file, fs.constants.X_OK);
  }
  const nu = process.env.NU_BIN || '/usr/local/bin/nu';
  const base = JSON.parse(execFileSync(nu, ['--no-config-file', 'bench-e2e.nu', 'state-access-bloat-worst-case',
    '--baseline', 'HEAD', '--feature', 'HEAD', '--case', maxTx ? selectedCase || 'all' : 'sload', '--feature-binary', binary,
    '--duration', '1200', '--summary-warmup-seconds', '600', '--tps', '1000', '--dry-run',
    ...(maxTx ? ['--max-transaction-size'] : [])], {encoding: 'utf8'}));
  const order = maxTx ? base.configuration.cases.map(c => ({id:c.id,scenario:c.scenario,reads:c.operations_per_transaction,prewarming:true})) : ORDER;
  const analyzer = maxTx ? 'contrib/bench/analyze-max-state-access.cjs' : 'contrib/bench/analyze-sload-size-isolation.cjs';
  const hash = file => execFileSync('sha256sum', [file], {encoding: 'utf8'}).split(' ')[0];
  const tools = Object.fromEntries([binary, process.env.STATE_PATH_CHECKPOINT_TOOL, process.env.TXGEN_TEMPO_BIN, process.env.TXGEN_BENCH_BIN, process.env.STATE_PATH_CACHE_EVICT_TOOL]
    .map(file => [file, hash(file)]));
  const fixture = () => JSON.parse(execFileSync(process.execPath,
    ['contrib/bench/state-access-config.cjs', '--ignore-env', '--check-fixtures'], {encoding: 'utf8'}));
  const manifest = {kind: maxTx ? 'near-cap-state-access-pair' : 'sload-size-prewarming-factorial', status: 'running', started_at: new Date().toISOString(),
    binary, sha256: tools[binary], tools, fixture: fixture(), order, memory_bytes_per_node: MEMORY,
    swap_bytes_per_node: 0, duration: 1200, warmup: 600, runs: [], sources: {},
    limits: 'Fresh restore each run, same router and binary, 20 GiB total memory per node, no swap. Scratch MDBX files are individually fsynced/evicted and mincore-verified before startup, so restore cache cannot bypass node caps. Caps do not pin file-cache bytes. No global cache flush. One pass is not a confidence interval.'};
  fs.mkdirSync(output, {recursive: true});
  const files = ['bench-e2e.nu', 'tempo.nu', ...fs.readdirSync('contrib/bench').filter(f => /\.(cjs|sh)$/.test(f)).map(f => `contrib/bench/${f}`),
    'contrib/bench/configs/state-access-bloated.json', 'contrib/bench/evict-benchmark-file-cache.c', 'contrib/bench/txgen/history-state-paths.json',
    'contrib/bench/txgen/HistoryStatePaths.sol', 'contrib/bench/txgen/StateAccessBenchmark.sol',
    'contrib/bench/txgen/presets/history_read.yml', 'contrib/bench/txgen/presets/state_access_dependent.yml',
    ...(maxTx ? ['contrib/bench/configs/state-access-max-tx.json', 'contrib/bench/txgen/presets/history_read_max.yml', 'contrib/bench/txgen/presets/history_code_max.yml'] : [])];
  for (const file of files) {
    manifest.sources[file] = createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    const dest = path.join(output, 'source', file);
    fs.mkdirSync(path.dirname(dest), {recursive: true});
    fs.copyFileSync(file, dest);
  }
  fs.writeFileSync(path.join(output, 'worktree.patch'), execFileSync('git', ['diff'], {maxBuffer: 64 * 2 ** 20}));
  const save = () => fs.writeFileSync(path.join(output, 'experiment.json'), JSON.stringify(manifest, null, 2) + '\n');
  save();
  try {
    for (const [index, item] of order.entries()) {
      for (const [file, digest] of Object.entries(tools)) assert.equal(hash(file), digest, `tool changed: ${file}`);
      assert.deepEqual(fixture(), manifest.fixture, 'fixture changed');
      for (const [file, digest] of Object.entries(manifest.sources))
        assert.equal(createHash('sha256').update(fs.readFileSync(file)).digest('hex'), digest, `source changed: ${file}`);
      const label = `${index + 1}-${item.id ? item.id+'-' : ''}${item.reads}-${item.prewarming ? 'on' : 'off'}`;
      const directory = path.join(output, label);
      fs.mkdirSync(directory);
      const plan = makePlan(base, item, `${path.basename(output)}-${label}`);
      plan.options.cache_evict_tool = path.resolve(process.env.STATE_PATH_CACHE_EVICT_TOOL);
      const planFile = path.join(directory, 'configuration.json');
      fs.writeFileSync(planFile, JSON.stringify(plan, null, 2) + '\n');
      const entry = {...item, label, directory, status: 'running', started_at: new Date().toISOString()};
      manifest.runs.push(entry); save();
      console.log(`${entry.started_at} START ${label}; log=${directory}/run.log`);
      const log = fs.openSync(path.join(directory, 'run.log'), 'wx');
      let timer, evidenceError;
      const code = await new Promise((resolve, reject) => {
        const child = spawn('flock', ['--nonblock', '/tmp/tempo-general-state-access-20260922.lock',
          process.execPath, 'contrib/bench/state-access-suite-process.cjs', nu, planFile],
        {stdio: ['ignore', log, log], env: {...process.env, BENCH_DISABLE_SCHELK: '1'}});
        timer = setInterval(() => {
          if (entry.live_evidence || evidenceError) return;
          try {
            const evidence = liveEvidence(item, binary);
            if (evidence) {entry.live_evidence = evidence; save(); console.log(`${new Date().toISOString()} VERIFIED live limits/flags ${label}`);}
          } catch (error) { evidenceError = error; console.error(`Live evidence failed: ${error}`); }
        }, 5000);
        child.once('error', reject);
        child.once('close', resolve);
      }).finally(() => {clearInterval(timer); fs.closeSync(log);});
      entry.exit_code = code;
      entry.finished_at = new Date().toISOString();
      entry.status = code === 0 ? 'complete' : 'failed';
      save();
      assert.equal(code, 0, `${label} failed: see run.log`);
      assert.ifError(evidenceError);
      assert.ok(entry.live_evidence, 'missing live process/limit evidence');
      const suite = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json')));
      assert.equal(suite.status, 'complete');
      assert.equal(suite.builds.feature.sha256, manifest.sha256);
      assert.deepEqual(suite.fixture, manifest.fixture);
      entry.results_dir = suite.cases[0].results_dir;
      const rows = fs.readFileSync(path.join(entry.results_dir, 'state-path-observer-feature-1.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
      for (const node of ['a', 'b']) {
        const samples = rows.map(row => row.nodes[node]).filter(sample => sample.memory);
        assert.ok(samples.length >= 100, 'insufficient live limit samples');
        samples.forEach(checkMemory);
      }
      save();
      console.log(`${entry.finished_at} FINISH ${label}; results=${entry.results_dir}`);
      execFileSync(process.execPath, [analyzer, output], {stdio: 'inherit'});
    }
    manifest.status = 'complete';
  } catch (error) {
    manifest.status = 'failed'; manifest.error = String(error); throw error;
  } finally {
    manifest.finished_at = new Date().toISOString(); save();
  }
  execFileSync(process.execPath, [analyzer, output], {stdio: 'inherit'});
}

module.exports = {makePlan, checkMemory, liveEvidence, MEMORY, ORDER};
if (require.main === module) main().catch(error => {console.error(error); process.exitCode = 1;});
