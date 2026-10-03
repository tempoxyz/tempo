'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {execFileSync, spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const lock = '/tmp/tempo-general-state-access-20260922.lock';
function plans(args) {
  const allowed = new Set(['--baseline', '--feature', '--feature-binary', '--duration',
    '--summary-warmup-seconds', '--tps', '--profile']);
  const forwarded = [];
  for (let i = 0; i < args.length; i++) {
    if (['--dry-run', '--wait', '--locked', '--transaction-timing'].includes(args[i])) continue;
    assert(allowed.has(args[i]) && args[i + 1] && !args[i + 1].startsWith('--'), `invalid option: ${args[i]}`);
    forwarded.push(args[i], args[++i]);
  }
  const nu = process.env.NU_BIN || 'nu';
  const plan = JSON.parse(execFileSync(nu, ['--no-config-file', 'bench-e2e.nu',
    'state-access-bloat-worst-case', '--sized-transactions', '--feature-env',
    `TEMPO_BENCH_TX_TIMING=${args.includes('--transaction-timing') ? '1' : '0'}`,
    ...forwarded, '--dry-run'], {cwd: root, encoding: 'utf8'}));
  return ['sload', 'bytecode'].flatMap(id => [true, false].map(enabled => {
    const cell = structuredClone(plan);
    cell.label = `${id}-${enabled ? 'on' : 'off'}`;
    cell.configuration.diagnostic_transaction_logging = args.includes('--transaction-timing');
    cell.configuration.cases = plan.configuration.cases.filter(c => c.id === id);
    cell.options.feature_args = enabled ? '' : '--builder.disable-prewarming';
    cell.configuration.prewarming = `builder ${enabled ? 'enabled' : 'disabled'}; engine unchanged`;
    return cell;
  }));
}
function main(args) {
  const cells = plans(args);
  if (args.includes('--dry-run')) { console.log(JSON.stringify(cells, null, 2)); return; }
  if (!args.includes('--locked')) {
    const result = spawnSync('flock', [...(args.includes('--wait') ? [] : ['--nonblock']), lock,
      process.execPath, __filename, ...args, '--locked'], {stdio: 'inherit', cwd: root});
    process.exitCode = result.status ?? 1; return;
  }
  for (const variable of ['STATE_PATH_CHECKPOINT_TOOL', 'STATE_PATH_CACHE_EVICT_TOOL', 'TXGEN_TEMPO_BIN', 'TXGEN_BENCH_BIN'])
    assert(process.env[variable] && fs.existsSync(process.env[variable]), `set ${variable}; see state-access-reproduction.md`);
  const scopes = execFileSync('systemctl', ['list-units', '--no-legend', '--state=active', 'tempo-e2e-*.scope'], {encoding: 'utf8'}).trim();
  assert.equal(scopes, '', 'existing benchmark scopes found; refusing to disturb them');
  for (const cell of cells) for (const side of ['baseline', 'feature'])
    cell.options[side] = execFileSync('git', ['rev-parse', cell.options[side]], {cwd: root, encoding: 'utf8'}).trim();
  const out = path.join(root, 'bench-results', `builder-prewarm-control-${new Date().toISOString().replace(/[:.]/g, '-')}`);
  fs.mkdirSync(out);
  process.env.TEMPO_BENCH_SUITE_BUILD_CACHE = path.join(out, 'builds');
  const experiment = {status: 'running', started_at: new Date().toISOString(), runs: []};
  const save = () => fs.writeFileSync(path.join(out, 'experiment.json'), JSON.stringify(experiment, null, 2) + '\n');
  save(); console.log(`PREWARM_CONTROL_DIR=${out}`);
  try {
  let binaryHash;
  for (const cell of cells) {
    const directory = path.join(out, cell.label); fs.mkdirSync(directory);
    const plan = path.join(directory, 'configuration.json');
    cell.benchmark_id = `${path.basename(out)}-${cell.label}`;
    fs.writeFileSync(plan, JSON.stringify(cell, null, 2) + '\n');
    const record = {label: cell.label, status: 'running', plan}; experiment.runs.push(record); save();
    const child = spawnSync(process.execPath, [path.join(__dirname, 'state-access-suite-process.cjs'),
      process.env.NU_BIN || 'nu', plan], {cwd: root, stdio: 'inherit'});
    record.exit_code = child.status ?? 1;
    if (record.exit_code !== 0) {
      record.status = 'failed'; experiment.status = 'failed'; save();
      throw new Error(`${cell.label} failed; inspect ${directory}`);
    }
    const result = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json')));
    assert.equal(result.status, 'complete');
    assert(!binaryHash || binaryHash === result.builds.feature.sha256, 'binary changed between control cells');
    binaryHash = result.builds.feature.sha256;
    record.results = result.cases.map(c => c.results_dir);
    for (const raw of record.results) execFileSync(process.execPath,
      [path.join(__dirname, 'analyze-state-access-latency.cjs'), path.resolve(root, raw)], {cwd: root, stdio: 'inherit'});
    record.status = 'complete'; save();
  }
  experiment.status = 'complete'; experiment.finished_at = new Date().toISOString(); save();
  } catch (error) {
    experiment.status = 'failed'; experiment.error = error.message;
    experiment.finished_at = new Date().toISOString();
    const running = experiment.runs.find(r => r.status === 'running');
    if (running) running.status = 'failed';
    save(); throw error;
  }
}
if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (error) { console.error(error.stack); process.exitCode = 1; }
}
module.exports = {plans};
