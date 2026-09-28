'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawn, execFileSync} = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const harness = path.join(__dirname, 'harness');
const manifestPath = path.join(__dirname, 'experiment.json');
const lock = '/tmp/tempo-general-state-access-20260922.lock';
const nu = '/usr/local/bin/nu';
const prior = path.join(root, 'bench-results/declared-storage-20260925');
const write = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
const read = file => JSON.parse(fs.readFileSync(file));
const hash = file => execFileSync('sha256sum', [file], {encoding: 'utf8'}).split(' ')[0];
const environment = tools => ({...process.env,
  PATH: '/home/ubuntu/.cargo/bin:/home/ubuntu/.foundry/bin:/usr/local/bin:/usr/bin:/bin',
  STATE_PATH_CHECKPOINT_TOOL: tools.read_finish_checkpoint.path,
  STATE_PATH_CACHE_EVICT_TOOL: tools['evict-benchmark-file-cache'].path,
  TXGEN_TEMPO_BIN: tools['txgen-tempo'].path, TXGEN_BENCH_BIN: tools.bench.path});

function prepare() {
  assert.ok(!fs.existsSync(manifestPath), 'refusing to overwrite an existing queue');
  const reference = read(path.join(prior, 'experiment.json'));
  const sources = ['bench-e2e.nu', 'tempo.nu', 'bench-schelk.nu', 'contrib/bench',
    '.github/scripts', 'crates/node/tests/assets/test-genesis.json'];
  for (const name of sources) {
    const dest = path.join(harness, name);
    fs.mkdirSync(path.dirname(dest), {recursive: true});
    fs.cpSync(path.join(root, name), dest, {recursive: true});
  }
  const tools = Object.fromEntries(Object.entries(reference.tools).map(([name, sha256]) =>
    [name, {path: path.join(prior, 'tools', name), sha256}]));
  const env = environment(tools);
  const base = JSON.parse(execFileSync(nu, ['--no-config-file', 'bench-e2e.nu',
    'state-access-bloat-worst-case', '--sized-transactions', '--baseline', reference.node_base,
    '--feature', reference.node_base, '--feature-binary', tools.tempo.path,
    '--feature-env', 'TEMPO_BENCH_TX_TIMING=1', '--dry-run'], {cwd: harness, env, encoding: 'utf8'}));
  const runs = [];
  for (const id of ['sload', 'bytecode']) for (const prewarming of [true, false]) {
    const label = `${id}-${prewarming ? 'on' : 'off'}`;
    const directory = path.join(__dirname, label);
    fs.mkdirSync(directory);
    const plan = structuredClone(base);
    plan.benchmark_id = `builder-prewarm-control-20260925-${label}`;
    plan.configuration.cases = base.configuration.cases.filter(item => item.id === id);
    plan.configuration.prewarming = `builder ${prewarming ? 'enabled' : 'disabled'}; engine unchanged`;
    plan.options.feature_args = prewarming ? '' : '--builder.disable-prewarming';
    plan.options.feature_label = label;
    write(path.join(directory, 'configuration.json'), plan);
    runs.push({label, prewarming, plan: path.join(directory, 'configuration.json'), status: 'queued'});
  }
  const sourcesSha256 = {};
  function index(dir) {
    for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) index(file);
      else sourcesSha256[path.relative(harness, file)] = hash(file);
    }
  }
  index(harness);
  write(manifestPath, {status: 'queued', queued_at: new Date().toISOString(), lock,
    predecessor: reference.suite_dir, fixture: reference.fixture, tools, sourcesSha256, runs,
    reason_for_fresh_on_reference: 'Shared router and txgen were updated by the declared-storage experiment; compare fresh on/off runs on identical inputs.',
    controls: {sload_accesses: 7200, bytecode_accesses: 2250, duration: 1200, warmup: 600,
      tps: 1000, memory_per_node: '20G', swap: 0, bytecode_prefetch: true,
      engine_prewarming: 'unchanged', builder_execution_cache_sharing: 'unchanged'},
    historical_reference: path.join(root, 'bench-results/state-access-latency-20260925/results.json')});
  console.log(`Prepared ${manifestPath}`);
}

function liveEvidence(binary, prewarming) {
  const nodes = {};
  for (const node of ['a', 'b']) {
    const group = `/sys/fs/cgroup/system.slice/tempo-e2e-${node}-feature-1.scope`;
    if (!fs.existsSync(`${group}/cgroup.procs`)) return null;
    const info = fs.readFileSync(`${group}/cgroup.procs`, 'utf8').trim().split(/\s+/).map(pid => {
      try {return {pid, args: fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean)};}
      catch {return null;}
    }).find(x => x?.args[0] === binary && x.args.includes('node'));
    if (!info) return null;
    assert.equal(info.args.includes('--builder.disable-prewarming'), node === 'b' || !prewarming);
    assert.ok(!info.args.includes('--engine.disable-prewarming'), 'engine prewarming changed');
    assert.equal(info.args.includes('--engine.disable-execution-cache-sharing-with-builder'), node === 'b');
    const limits = Object.fromEntries(['memory.max','memory.swap.max','memory.swap.current']
      .map(name => [name, fs.readFileSync(`${group}/${name}`, 'utf8').trim()]));
    assert.equal(Number(limits['memory.max']), 20 * 2 ** 30);
    assert.equal(Number(limits['memory.swap.max']), 0);
    assert.equal(Number(limits['memory.swap.current']), 0);
    const cpus = /Cpus_allowed_list:\s*(.+)/.exec(fs.readFileSync(`/proc/${info.pid}/status`, 'utf8'))[1];
    assert.equal(cpus, node === 'a' ? '0-7,16-23' : '8-15,24-31');
    const benchEnv = execFileSync('sudo', ['-n', 'cat', `/proc/${info.pid}/environ`], {encoding: 'utf8'}).split('\0')
      .filter(value => /^(RETH_BYTECODE_PREFETCH|TEMPO_BENCH_TX_TIMING)=/.test(value));
    assert.ok(benchEnv.includes('RETH_BYTECODE_PREFETCH=1'));
    assert.ok(benchEnv.includes('TEMPO_BENCH_TX_TIMING=1'));
    nodes[node] = {...info, limits, cpus, bench_env: benchEnv};
  }
  return {unix_ms: Date.now(), nodes};
}

async function runLocked() {
  assert.equal(process.env.BENCH_QUEUE_LOCKED, '1', 'must run through the blocking lock');
  const manifest = read(manifestPath), save = () => write(manifestPath, manifest);
  assert.ok(['queued', 'waiting'].includes(manifest.status), 'queue already started');
  manifest.status = 'starting'; manifest.acquired_lock_at = new Date().toISOString(); save();
  const active = execFileSync('systemctl', ['list-units', '--no-legend', '--state=active', 'tempo-e2e-*.scope'], {encoding: 'utf8'}).trim();
  assert.equal(active, '', 'foreign benchmark scopes remain active; refusing cleanup or launch');
  assert.ok(fs.existsSync(path.join(manifest.predecessor, 'exit-code')), 'predecessor has not recorded termination');
  const env = environment(manifest.tools);
  for (const tool of Object.values(manifest.tools)) assert.equal(hash(tool.path), tool.sha256, `tool changed: ${tool.path}`);
  for (const [file, sha256] of Object.entries(manifest.sourcesSha256)) assert.equal(hash(path.join(harness, file)), sha256, `harness changed: ${file}`);
  const checkFixture = () => assert.deepEqual(JSON.parse(execFileSync(process.execPath,
    ['contrib/bench/state-access-config.cjs', '--ignore-env', '--check-fixtures'], {cwd: harness, env, encoding: 'utf8'})), manifest.fixture, 'fixture changed while queued');
  checkFixture();
  for (const run of manifest.runs) {
    if (run.status === 'complete') continue;
    assert.equal(run.status, 'queued', `cannot resume ${run.label} from ${run.status}`);
    checkFixture();
    manifest.status = 'running'; run.status = 'running'; run.started_at = new Date().toISOString(); save();
    console.log(`${run.started_at} starting ${run.label}`);
    const directory = path.dirname(run.plan), log = fs.openSync(path.join(directory, 'run.log'), 'a');
    let evidence = null, validationError = null;
    const child = spawn(process.execPath, ['contrib/bench/state-access-suite-process.cjs', nu, run.plan],
      {cwd: harness, env, stdio: ['ignore', log, log]});
    const timer = setInterval(() => {
      if (evidence || validationError) return;
      try {
        evidence = liveEvidence(manifest.tools.tempo.path, run.prewarming);
        if (evidence) write(path.join(directory, 'live-controls.json'), evidence);
      } catch (error) {validationError = error; console.error(error);}
    }, 5000);
    let code;
    try {code = await new Promise((resolve, reject) => {child.on('error', reject); child.on('close', resolve);});}
    finally {clearInterval(timer); fs.closeSync(log);}
    run.exit_code = code; run.finished_at = new Date().toISOString();
    run.status = code === 0 && evidence && !validationError ? 'analyzing' : 'failed'; save();
    assert.equal(code, 0, `${run.label} failed; inspect run.log`);
    assert.ok(evidence, 'missing live controls');
    if (validationError) throw validationError;
    const suite = read(path.join(directory, 'manifest.json'));
    assert.equal(suite.status, 'complete');
    assert.deepEqual(suite.fixture, manifest.fixture);
    assert.equal(suite.builds.feature.sha256, manifest.tools.tempo.sha256);
    run.results = suite.cases.map(item => path.resolve(harness, item.results_dir));
    for (const results of run.results) {
      execFileSync(process.execPath, ['contrib/bench/analyze-state-access-latency.cjs', results],
        {cwd: harness, env, stdio: 'ignore'});
    }
    run.analyses = run.results.map(results => read(path.join(results, 'latency-analysis.json')));
    run.status = 'complete'; save();
    console.log(`${new Date().toISOString()} completed ${run.label}`);
  }
  manifest.status = 'complete'; manifest.finished_at = new Date().toISOString(); save();
}

async function wait() {
  const manifest = read(manifestPath);
  assert.ok(['queued', 'failed'].includes(manifest.status), 'queue already dispatched or complete');
  manifest.status = 'waiting'; manifest.waiting_at = new Date().toISOString(); write(manifestPath, manifest);
  console.log(`Waiting for ${lock}; active benchmark is not interrupted.`);
  const child = spawn('flock', [lock, 'env', 'BENCH_QUEUE_LOCKED=1', process.execPath, __filename, '--run'], {stdio: 'inherit'});
  const code = await new Promise((resolve, reject) => {child.on('error', reject); child.on('close', resolve);});
  assert.equal(code, 0, 'queued experiment failed');
}

if (require.main === module) {
  const mode = process.argv[2];
  Promise.resolve().then(() => {
    if (mode === '--prepare') return prepare();
    if (mode === '--wait') return wait();
    if (mode === '--run') return runLocked();
    throw new Error('usage: queue.cjs --prepare|--wait|--run');
  }).catch(error => {
    console.error(error);
    if (mode !== '--prepare' && fs.existsSync(manifestPath)) {
      const manifest = read(manifestPath);
      manifest.status = 'failed'; manifest.error = error.message; manifest.failed_at = new Date().toISOString();
      write(manifestPath, manifest);
    }
    process.exitCode = 1;
  });
}
module.exports = {liveEvidence};
