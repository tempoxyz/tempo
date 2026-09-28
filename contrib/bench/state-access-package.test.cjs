'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {options, verifyPatches} = require('./setup-state-access.cjs');
const {plans} = require('./run-builder-prewarm-control.cjs');
const {options: ssdOptions} = require('./run-ssd-read-bandwidth.cjs');
const {unique} = require('./build-bytecode-diagnostics.cjs');
const root = path.resolve(__dirname, '../..');
test('pinned dependency checksums include the OOM fix and txgen access lists', () => {
  const manifest = verifyPatches();
  assert.match(manifest.reth.base, /^[a-f0-9]{40}$/);
  assert.match(fs.readFileSync(path.join(__dirname, 'patches/reth.patch'), 'utf8'), /max_cached_bytecode_bytes/);
  assert.match(fs.readFileSync(path.join(__dirname, 'patches/txgen.patch'), 'utf8'), /access_list/);
});
test('setup rejects unknown or incomplete options without creating checkouts', () => {
  assert.throws(() => options(['--directory']));
  assert.throws(() => options(['--wrong']));
  assert.equal(options(['--build-tools']).buildTools, true);
});
test('prewarming control resolves all four fresh cells with matching limits', () => {
  const cells = plans(['--dry-run']);
  assert.deepEqual(cells.map(c => c.label), ['sload-on', 'sload-off', 'bytecode-on', 'bytecode-off']);
  for (const c of cells) {
    assert.equal(c.configuration.cases.length, 1);
    assert.equal(c.options.node_memory, '20G');
    assert.equal(c.options.node_swap_limit, '0');
    assert.match(c.options.feature_env, /RETH_BYTECODE_PREFETCH=1/);
    assert.equal(c.options.feature_args, c.label.endsWith('-off') ? '--builder.disable-prewarming' : '');
  }
});
test('native control entry point is a no-side-effect dry-run', () => {
  const result = JSON.parse(execFileSync('nu', ['--no-config-file', 'bench-e2e.nu', 'state-access-prewarm-control',
    '--baseline', 'HEAD', '--feature', 'HEAD', '--dry-run'], {cwd: root, encoding: 'utf8'}));
  assert.equal(result.length, 4);
});
test('patched worktree builds bypass the ordinary binary cache', () => {
  const source = fs.readFileSync(path.join(root, 'tempo.nu'), 'utf8');
  const body = source.slice(source.indexOf('def build-in-worktree '), source.indexOf('# Get the path to a built binary'));
  assert.match(body, /TEMPO_BENCH_CARGO_CONFIG/);
  assert.match(body, /if not \$no_cache and \$cargo_config == "" and/);
  assert.match(body, /if \$cargo_config == "" \{ cache-upload/);
  assert.match(body, /\["--config" \$cargo_config\]/);
});
test('SSD controls require explicit inputs and a fresh output location', () => {
  assert.throws(() => ssdOptions([]));
  assert.throws(() => ssdOptions(['--output', 'x']));
  assert.throws(() => ssdOptions(['--builder-file', 'a', '--follower-file', 'b', '--output', 'x', '--builder-cpu', '-1']));
  assert.equal(ssdOptions(['--builder-file', 'a', '--follower-file', 'b', '--output', 'x']).output, 'x');
});
test('diagnostic artifact selection refuses missing or ambiguous libraries', () => {
  assert.throws(() => unique([], 'test'));
  assert.throws(() => unique([__filename, path.join(__dirname, 'setup-state-access.cjs')], 'test'));
  assert.equal(unique([__filename, __filename], 'test'), __filename);
});
