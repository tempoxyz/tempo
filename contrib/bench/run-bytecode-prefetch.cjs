#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createHash} = require('node:crypto');
const {spawn, execFileSync} = require('node:child_process');

async function main() {
  const [binaryArg, outputArg] = process.argv.slice(2);
  assert.ok(binaryArg && outputArg, 'usage: run-bytecode-prefetch.cjs BINARY OUTPUT_DIR');
  const binary = path.resolve(binaryArg), output = path.resolve(outputArg);
  assert.ok(fs.statSync(binary).isFile());
  const checkpoint = process.env.STATE_PATH_CHECKPOINT_TOOL;
  assert.ok(checkpoint && fs.existsSync(checkpoint), 'set STATE_PATH_CHECKPOINT_TOOL');
  fs.mkdirSync(output, {recursive: true});
  const file = path.join(output, 'experiment.json');
  assert.ok(!fs.existsSync(file), 'refusing to overwrite an existing experiment');
  const digest = () => execFileSync('sha256sum', [binary], {encoding: 'utf8'}).split(' ')[0];
  const sha256 = digest();
  const nu = process.env.NU_BIN || '/usr/local/bin/nu';
  const manifest = {kind: 'targeted-bytecode-prefetch-ab', started_at: new Date().toISOString(),
    binary, sha256, version: execFileSync(binary, ['--version'], {encoding: 'utf8'}),
    status: 'running', runs: [], order: [0, 1],
    scope: 'Same binary and restored fixture; only RETH_BYTECODE_PREFETCH differs. No global cache drop.',
    sources: {}};
  for (const source of ['bench-e2e.nu', 'contrib/bench/run-bytecode-prefetch.cjs',
    'contrib/bench/state-path-observer.cjs', 'contrib/bench/configs/state-access-bloated.json']) {
    manifest.sources[source] = createHash('sha256').update(fs.readFileSync(source)).digest('hex');
    const destination = path.join(output, 'source', source);
    fs.mkdirSync(path.dirname(destination), {recursive: true});
    fs.copyFileSync(source, destination);
  }
  const save = () => fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
  save();
  try {
    for (const enabled of manifest.order) {
      assert.equal(digest(), sha256, 'binary changed between runs');
      const label = enabled ? 'prefetch' : 'baseline';
      const directory = path.join(output, label);
      fs.mkdirSync(directory);
      const args = ['--no-config-file', 'bench-e2e.nu', 'state-access-bloat-worst-case',
        '--baseline', 'HEAD', '--feature', 'HEAD', '--case', 'bytecode',
        '--feature-binary', binary, '--profile', 'profiling',
        '--feature-env', `RETH_BYTECODE_PREFETCH=${enabled}`, '--dry-run'];
      const plan = JSON.parse(execFileSync(nu, args, {encoding: 'utf8'}));
      plan.benchmark_id = `bytecode-prefetch-${Date.now()}-${label}`;
      plan.options.feature_label = `bytecode-prefetch-${label}`;
      const planFile = path.join(directory, 'configuration.json');
      fs.writeFileSync(planFile, JSON.stringify(plan, null, 2) + '\n');
      const entry = {label, enabled, directory, started_at: new Date().toISOString(), status: 'running'};
      manifest.runs.push(entry);
      save();
      console.log(`${entry.started_at} START ${label}; log=${directory}/run.log`);
      const log = fs.openSync(path.join(directory, 'run.log'), 'wx');
      const code = await new Promise((resolve, reject) => {
        const child = spawn('flock', ['--nonblock', '/tmp/tempo-general-state-access-20260922.lock',
          process.execPath, 'contrib/bench/state-access-suite-process.cjs', nu, planFile],
        {stdio: ['ignore', log, log], env: process.env});
        child.once('error', reject);
        child.once('close', resolve);
      }).finally(() => fs.closeSync(log));
      entry.exit_code = code;
      entry.finished_at = new Date().toISOString();
      entry.status = code === 0 ? 'complete' : 'failed';
      save();
      assert.equal(code, 0, `${label} suite failed; see ${directory}/run.log`);
      const suite = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json')));
      assert.equal(suite.status, 'complete');
      assert.equal(suite.builds.feature.sha256, sha256);
      entry.results_dir = suite.cases[0].results_dir;
      if (manifest.fixture) assert.deepEqual(suite.fixture, manifest.fixture, 'fixture changed');
      manifest.fixture = suite.fixture;
      save();
      console.log(`${entry.finished_at} FINISH ${label}; results=${entry.results_dir}`);
    }
    manifest.status = 'complete';
  } catch (error) {
    manifest.status = 'failed';
    manifest.error = String(error);
    throw error;
  } finally {
    manifest.finished_at = new Date().toISOString();
    save();
  }
}

if (require.main === module) main().catch(error => {console.error(error); process.exitCode = 1;});
