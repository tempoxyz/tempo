'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {parseArgs} = require('node:util');
const {execFileSync} = require('node:child_process');
const defaultFile = path.join(__dirname, 'configs/state-access-bloated.json');
const scenarios = {sload: 'state_access_dependent', bytecode: 'history_code', writes: 'history_write'};

function resolveConfig(file = defaultFile, selected = [], env = process.env) {
  const source = JSON.parse(fs.readFileSync(file));
  assert.equal(source.schema_version, 1, 'unsupported configuration schema');
  assert.match(source.id, /^[a-z0-9-]+$/);
  const common = {...source.common};
  for (const [key, variable] of Object.entries({duration: 'HISTORY_DURATION', warmup: 'HISTORY_WARMUP', tps: 'HISTORY_TPS'})) {
    if (env[variable] !== undefined) {
      assert.match(env[variable], /^\d+$/, `invalid ${variable}`);
      common[key] = Number(env[variable]);
    }
  }
  for (const key of ['duration', 'warmup', 'tps', 'accounts']) assert.ok(Number.isSafeInteger(common[key]) && common[key] >= 0, `invalid ${key}`);
  assert.ok(common.duration <= 3000 && common.duration - common.warmup >= 270, 'at least 270 measured seconds required');
  assert.ok(common.tps >= 1 && common.tps <= 50000 && common.accounts === 1000, 'invalid load or fixture signer count');
  assert.equal(common.gas_limit, '1000000000000', 'comparison uses nonbinding gas limits');
  assert.equal(common.node_args, '--rpc-cache.max-blocks 128 --rpc-cache.max-receipts 128', 'comparison node settings must match');
  assert.deepEqual(source.fixture, {snapshot_suffix: 'history_paths', bloat_mib: 100000, code_count: 4266667, code_bytes: 24576});
  assert.deepEqual(source.cases.map(c => c.id).sort(), Object.keys(scenarios).sort(), 'registry must contain each workload exactly once');
  for (const item of source.cases) assert.equal(item.scenario, scenarios[item.id], 'unexpected workload preset');
  assert.equal(new Set(selected).size, selected.length, 'duplicate case selection');
  for (const id of selected) assert.ok(Object.hasOwn(scenarios, id), `unknown case ${id}; choose sload, bytecode, writes`);
  return {id: source.id, schema_version: source.schema_version, ...common,
    fixture_requirements: source.fixture,
    transaction_cap: null, prewarming: 'unchanged/default enabled',
    whole_node_memory_required: true, persistence_priming_required: true,
    cache_policy: 'fresh snapshot restore and new node processes per case; no global page-cache drop; exclude warmup',
    cases: selected.length ? selected.map(id => source.cases.find(c => c.id === id)) : source.cases};
}

function verifyCaseConfiguration(manifest, entry, summary, metadata, fixture) {
  const c = manifest.configuration;
  assert.ok(c.cases.some(item => item.scenario === entry.scenario), 'unregistered case');
  for (const [key, expected] of Object.entries({preset: entry.scenario, tps: c.tps, duration: c.duration,
    summary_warmup_seconds: c.warmup, summary_warmup_blocks: 0, bloat_mib: c.fixture_requirements.bloat_mib,
    run_side: 'feature'})) assert.equal(summary[key], expected, `run configuration drift: ${key}`);
  for (const [key, expected] of Object.entries({scenario: entry.scenario, target_tps: String(c.tps),
    run_duration_secs: String(c.duration), accounts: String(c.accounts), bloat_mib: String(c.fixture_requirements.bloat_mib),
    node_commit_sha: manifest.build.revision})) assert.equal(metadata[key], expected, `sender configuration drift: ${key}`);
  assert.equal(metadata.benchmark_id, summary.benchmark_id, 'benchmark ID mismatch');
  for (const key of ['state_root', 'router_code_hash', 'code_count', 'code_bytes', 'hashed_storage_entries']) {
    assert.ok(manifest.fixture[key] !== undefined, `missing suite fixture ${key}`);
    assert.equal(fixture[key], manifest.fixture[key], `fixture drift: ${key}`);
  }
  return true;
}

function verifyFixtures(config) {
  const suffix = config.fixture_requirements.snapshot_suffix;
  const fixtures = ['a', 'b'].map(side => {
    const dir = `/reth-bench-${side}/tempo_e2e_${config.fixture_requirements.bloat_mib}mb_state_access_isolated_roles_${suffix}.virgin`;
    assert.ok(!fs.existsSync(path.join(dir, '.bench-meta/history-state-paths.incomplete')), 'incomplete history fixture');
    for (const file of ['db/mdbx.dat', '.bench-meta/genesis.json', '.bench-meta/marker.json'])
      assert.ok(fs.existsSync(path.join(dir, file)), `missing prepared fixture ${dir}/${file}; see contrib/bench/configs/README.md`);
    return JSON.parse(fs.readFileSync(path.join(dir, '.bench-meta/history-state-paths.json')));
  });
  assert.deepEqual(fixtures[0], fixtures[1], 'node fixtures differ');
  const fixture = fixtures[0];
  for (const key of ['code_count', 'code_bytes']) assert.equal(fixture[key], config.fixture_requirements[key], `fixture ${key} differs`);
  assert.ok(fixture.total_code_bytes >= 100000 * 1024 * 1024, '100000 MiB code corpus required');
  const artifact = JSON.parse(fs.readFileSync(path.join(__dirname, 'txgen/history-state-paths.json')));
  const hash = execFileSync(process.env.CAST_BIN || path.join(process.env.HOME, '.foundry/bin/cast'),
    ['keccak', artifact.deployedBytecode.object], {encoding: 'utf8'}).trim();
  assert.equal(fixture.router_code_hash, hash, 'fixture router differs: run contrib/bench/update-history-router.sh');
  return fixture;
}

function main() {
  const {values} = parseArgs({options: {config: {type: 'string', default: defaultFile}, case: {type: 'string', multiple: true},
    list: {type: 'boolean'}, show: {type: 'boolean'}, help: {type: 'boolean'}, resolve: {type: 'boolean'}, 'dry-run': {type: 'boolean'},
    'check-fixtures': {type: 'boolean'}, 'ignore-env': {type: 'boolean'},
    tps: {type: 'string'}, duration: {type: 'string'}, warmup: {type: 'string'}}});
  if (values.help) {
    console.log('Usage: bash contrib/bench/run-history-state-paths.sh [--list | --show | --dry-run] [--case sload|bytecode|writes] [--config FILE]\nNo selection runs all three cases sequentially. Repeat --case to choose an order.');
    return;
  }
  const env = values['ignore-env'] ? {} : {...process.env};
  for (const key of ['tps', 'duration', 'warmup']) if (values[key] !== undefined) env[`HISTORY_${key.toUpperCase()}`] = values[key];
  const config = resolveConfig(values.config, values.case, env);
  if (values['check-fixtures']) console.log(JSON.stringify(verifyFixtures(config)));
  else if (values.list) for (const item of config.cases) console.log(`${item.id}\t${item.scenario}\t${item.description}`);
  else console.log(JSON.stringify({...config, dry_run: !!values['dry-run']}, null, values.resolve ? 0 : 2));
}
if (require.main === module) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 2; }
}
module.exports = {resolveConfig, verifyCaseConfiguration, verifyFixtures};
