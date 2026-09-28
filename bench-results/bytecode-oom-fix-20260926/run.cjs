'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawn, execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const prior = path.join(root, 'bench-results/builder-prewarm-control-20260925');
const harness = path.join(__dirname, 'harness');
const lock = '/tmp/tempo-general-state-access-20260922.lock';
const read = file => JSON.parse(fs.readFileSync(file));
const write = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
const hash = file => execFileSync('sha256sum', [file], {encoding: 'utf8'}).split(' ')[0];
const manifestFile = path.join(__dirname, 'experiment.json');
const planFile = path.join(__dirname, 'configuration.json');

function prepare() {
  assert.ok(!fs.existsSync(manifestFile), 'refusing to overwrite experiment');
  for (const name of ['bench-e2e.nu', 'tempo.nu', 'bench-schelk.nu', 'contrib/bench',
    '.github/scripts', 'crates/node/tests/assets/test-genesis.json']) {
    const dest = path.join(harness, name);
    fs.mkdirSync(path.dirname(dest), {recursive: true});
    fs.cpSync(path.join(prior, 'harness', name), dest, {recursive: true});
  }
  const ref = read(path.join(prior, 'experiment.json'));
  const binary = path.join(__dirname, 'tempo');
  fs.copyFileSync(path.join(root, 'target/profiling/tempo'), binary);
  const plan = read(path.join(prior, 'bytecode-off/configuration.json'));
  plan.benchmark_id = 'bytecode-oom-fix-20260926';
  plan.options.feature_label = 'bytecode-off-bounded-cache';
  plan.options.feature_binary = binary;
  write(planFile, plan);
  const tools = {...ref.tools, tempo: {path: binary, sha256: hash(binary)}};
  const sources = {};
  function index(dir) {
    for (const entry of fs.readdirSync(dir, {withFileTypes: true})) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) index(file);
      else sources[path.relative(harness, file)] = hash(file);
    }
  }
  index(harness);
  write(manifestFile, {status: 'queued', created_at: new Date().toISOString(), lock,
    fixture: ref.fixture, tools, sources, reference: prior,
    change: 'Execution batches commit at 512 MiB of cached bytecode buffers plus jump tables, including read-only code. All workload and node resource controls unchanged.'});
}

function sample(manifest) {
  const nodes = {};
  for (const node of ['a', 'b']) {
    const dir = `/sys/fs/cgroup/system.slice/tempo-e2e-${node}-feature-1.scope`;
    if (!fs.existsSync(`${dir}/cgroup.procs`)) return null;
    const stat = fs.readFileSync(`${dir}/memory.stat`, 'utf8');
    const fields = Object.fromEntries(stat.trim().split('\n').map(line => line.split(' ')));
    const values = Object.fromEntries(['memory.current', 'memory.peak', 'memory.max', 'memory.swap.max', 'memory.swap.current']
      .map(name => [name, Number(fs.readFileSync(`${dir}/${name}`, 'utf8').trim())]));
    assert.equal(values['memory.max'], 20 * 2 ** 30);
    assert.equal(values['memory.swap.max'], 0);
    assert.equal(values['memory.swap.current'], 0);
    const processInfo = fs.readFileSync(`${dir}/cgroup.procs`, 'utf8').trim().split(/\s+/).map(pid => {
      try {return {pid, args: fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean)};}
      catch {return null;}
    }).find(info => info?.args[0] === manifest.tools.tempo.path && info.args.includes('node'));
    if (!processInfo) return null;
    assert.ok(processInfo.args.includes('--builder.disable-prewarming'));
    assert.ok(!processInfo.args.includes('--engine.disable-prewarming'));
    assert.equal(processInfo.args.includes('--engine.disable-execution-cache-sharing-with-builder'), node === 'b');
    const cpus = /Cpus_allowed_list:\s*(.+)/.exec(fs.readFileSync(`/proc/${processInfo.pid}/status`, 'utf8'))[1];
    assert.equal(cpus, node === 'a' ? '0-7,16-23' : '8-15,24-31');
    const env = execFileSync('sudo', ['-n', 'cat', `/proc/${processInfo.pid}/environ`], {encoding: 'utf8'}).split('\0');
    assert.ok(env.includes('RETH_BYTECODE_PREFETCH=1'));
    assert.ok(env.includes('TEMPO_BENCH_TX_TIMING=1'));
    nodes[node] = {...processInfo, cpus, ...values, anon: Number(fields.anon), file: Number(fields.file),
      memory_events: fs.readFileSync(`${dir}/memory.events`, 'utf8')};
  }
  return {unix_ms: Date.now(), nodes};
}

async function run() {
  assert.equal(process.env.OOM_FIX_LOCKED, '1');
  const manifest = read(manifestFile);
  assert.equal(manifest.status, 'queued');
  const active = execFileSync('systemctl', ['list-units', '--no-legend', '--state=active', 'tempo-e2e-*.scope'], {encoding: 'utf8'}).trim();
  assert.equal(active, '', 'another benchmark is active');
  for (const tool of Object.values(manifest.tools)) assert.equal(hash(tool.path), tool.sha256);
  for (const [file, sha] of Object.entries(manifest.sources)) assert.equal(hash(path.join(harness, file)), sha);
  const env = {...process.env, PATH: '/home/ubuntu/.cargo/bin:/home/ubuntu/.foundry/bin:/usr/local/bin:/usr/bin:/bin',
    STATE_PATH_CHECKPOINT_TOOL: manifest.tools.read_finish_checkpoint.path,
    STATE_PATH_CACHE_EVICT_TOOL: manifest.tools['evict-benchmark-file-cache'].path,
    TXGEN_TEMPO_BIN: manifest.tools['txgen-tempo'].path, TXGEN_BENCH_BIN: manifest.tools.bench.path};
  assert.deepEqual(JSON.parse(execFileSync(process.execPath, ['contrib/bench/state-access-config.cjs', '--ignore-env', '--check-fixtures'],
    {cwd: harness, env, encoding: 'utf8'})), manifest.fixture);
  manifest.status = 'running'; manifest.started_at = new Date().toISOString(); write(manifestFile, manifest);
  const child = spawn(process.execPath, ['contrib/bench/state-access-suite-process.cjs', '/usr/local/bin/nu', planFile],
    {cwd: harness, env, stdio: 'inherit'});
  let evidence = false, validationError;
  const timer = setInterval(() => {
    try {
      const row = sample(manifest);
      if (row) {fs.appendFileSync(path.join(__dirname, 'memory-controls.jsonl'), JSON.stringify(row) + '\n'); evidence = true;}
    } catch (error) {validationError = String(error); console.error(error);}
  }, 5000);
  const code = await new Promise((resolve, reject) => {child.on('error', reject); child.on('close', resolve);});
  clearInterval(timer);
  for (const node of ['a', 'b']) {
    const dir = path.join(harness, `localnet/logs-e2e-local-feature-1-${node}`);
    if (fs.existsSync(dir)) fs.cpSync(dir, path.join(__dirname, `logs-${node}`), {recursive: true});
  }
  manifest.status = code === 0 && evidence && !validationError ? 'complete' : 'failed';
  manifest.exit_code = code; manifest.finished_at = new Date().toISOString(); manifest.validation_error = validationError;
  write(manifestFile, manifest);
  assert.equal(manifest.status, 'complete');
}

async function main() {
  if (process.argv[2] === '--prepare') return prepare();
  if (process.argv[2] === '--locked') return run();
  assert.equal(process.argv[2], '--wait');
  const child = spawn('flock', [lock, 'env', 'OOM_FIX_LOCKED=1', process.execPath, __filename, '--locked'], {stdio: 'inherit'});
  process.exitCode = await new Promise(resolve => child.on('close', resolve));
}
main().catch(error => {console.error(error); process.exitCode = 1;});
