'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {execFileSync, spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const patchRoot = path.join(__dirname, 'patches');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const run = (exe, args, cwd = root, options = {}) => {
  const output = execFileSync(exe, args,
    {cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...options});
  return output === null ? '' : output.trim();
};
function options(args) {
  const result = {directory: path.join(root, 'target/state-access-deps'), buildTools: false};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help') result.help = true;
    else if (arg === '--build-tools') result.buildTools = true;
    else {
      const key = {'--directory': 'directory', '--reth-source': 'rethSource', '--txgen-source': 'txgenSource'}[arg];
      assert(key && args[i + 1] && !args[i + 1].startsWith('--'), `unknown or incomplete option: ${arg}`);
      result[key] = path.resolve(args[++i]);
    }
  }
  return result;
}
function verifyPatches() {
  const manifest = JSON.parse(fs.readFileSync(path.join(patchRoot, 'manifest.json')));
  for (const name of ['reth', 'txgen']) {
    assert.match(manifest[name].base, /^[a-f0-9]{40}$/);
    assert.equal(sha(fs.readFileSync(path.join(patchRoot, `${name}.patch`))), manifest[name].patch_sha256,
      `${name} patch checksum mismatch`);
  }
  return manifest;
}
function checkout(name, pin, directory, local) {
  const dest = path.join(directory, `${name}-${pin.base.slice(0, 12)}-${pin.patch_sha256.slice(0, 16)}`);
  const marker = `${dest}.json`;
  if (fs.existsSync(dest)) {
    assert(fs.existsSync(marker), `incomplete checkout; inspect before removing: ${dest}`);
    const saved = JSON.parse(fs.readFileSync(marker));
    assert.equal(run('git', ['rev-parse', 'HEAD'], dest), pin.base);
    assert.equal(run('git', ['write-tree'], dest), saved.tree, 'patched dependency index changed');
    run('git', ['diff', '--exit-code'], dest);
    assert.equal(run('git', ['ls-files', '--others', '--exclude-standard'], dest), '', 'untracked dependency source');
    return dest;
  }
  if (local) run('git', ['clone', '--shared', '--no-checkout', local, dest]);
  else {
    fs.mkdirSync(dest);
    run('git', ['init', '-q'], dest);
    run('git', ['remote', 'add', 'origin', `https://github.com/${name === 'reth' ? 'paradigmxyz/reth' : 'tempoxyz/txgen'}.git`], dest);
    run('git', ['fetch', '--depth', '1', 'origin', pin.base], dest);
  }
  run('git', ['checkout', '--detach', pin.base], dest);
  run('git', ['apply', '--check', path.join(patchRoot, `${name}.patch`)], dest);
  run('git', ['apply', path.join(patchRoot, `${name}.patch`)], dest);
  run('git', ['add', '.'], dest);
  fs.writeFileSync(marker, JSON.stringify({...pin, tree: run('git', ['write-tree'], dest)}, null, 2) + '\n');
  return dest;
}
function main(args) {
  const opts = options(args);
  if (opts.help) {
    console.log('node contrib/bench/setup-state-access.cjs [--build-tools] [--directory DIR] [--reth-source LOCAL_REPO] [--txgen-source LOCAL_REPO]');
    return;
  }
  const manifest = verifyPatches();
  fs.mkdirSync(opts.directory, {recursive: true});
  const reth = checkout('reth', manifest.reth, opts.directory, opts.rethSource);
  const txgen = checkout('txgen', manifest.txgen, opts.directory, opts.txgenSource);
  const config = path.join(opts.directory, 'cargo-config.toml');
  fs.writeFileSync(config, run('python3', [path.join(patchRoot, 'reth-config.py'), reth]) + '\n');
  const toolTarget = path.join(opts.directory, 'tools');
  const variables = {
    TEMPO_BENCH_CARGO_CONFIG: config,
    STATE_PATH_CHECKPOINT_TOOL: path.join(root, 'target/profiling/examples/read_finish_checkpoint'),
    HISTORY_FIXTURE_TOOL: path.join(root, 'target/profiling/examples/prepare_history_state_paths'),
    STATE_PATH_CACHE_EVICT_TOOL: path.join(toolTarget, 'evict-benchmark-file-cache'),
    TXGEN_TEMPO_BIN: path.join(toolTarget, 'release/txgen-tempo'),
    TXGEN_BENCH_BIN: path.join(toolTarget, 'release/bench'),
  };
  fs.mkdirSync(toolTarget, {recursive: true});
  if (opts.buildTools) {
    run('cargo', ['build', '--manifest-path', path.join(txgen, 'Cargo.toml'), '--locked', '--release',
      '--target-dir', toolTarget, '-p', 'txgen-tempo', '-p', 'bench-cli', '--bins'], root, {stdio: 'inherit'});
    const cargo = spawnSync('cargo', ['build', '--config', config, '--profile', 'profiling', '-p', 'tempo',
      '--bin', 'tempo', '--example', 'read_finish_checkpoint', '--example', 'prepare_history_state_paths',
      '--features', 'jemalloc,asm-keccak', '--target-dir', path.join(root, 'target'), '--message-format=json-render-diagnostics'],
    {cwd: root, env: {...process.env, RUSTFLAGS: process.env.RUSTFLAGS || '-C target-cpu=native'},
      encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'inherit']});
    assert.equal(cargo.status, 0, cargo.error?.message || 'Cargo node/helper build failed');
    const artifacts = cargo.stdout.split('\n').filter(Boolean).map(line => JSON.parse(line));
    fs.writeFileSync(path.join(opts.directory, 'build-artifacts.json'), JSON.stringify({root, reth, config, artifacts}, null, 2) + '\n');
    run('cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      path.join(__dirname, 'evict-benchmark-file-cache.c'), '-o', variables.STATE_PATH_CACHE_EVICT_TOOL], root, {stdio: 'inherit'});
  }
  const shellQuote = value => "'" + value.replaceAll("'", "'\\''") + "'";
  fs.writeFileSync(path.join(opts.directory, 'env.sh'), Object.entries(variables)
    .map(([key, value]) => `export ${key}=${shellQuote(value)}`).join('\n') + '\n');
  fs.writeFileSync(path.join(opts.directory, 'env.nu'), Object.entries(variables)
    .map(([key, value]) => `$env.${key} = ${JSON.stringify(value)}`).join('\n') + '\n');
  fs.writeFileSync(path.join(opts.directory, 'setup.json'), JSON.stringify({root, reth, txgen, manifest, variables,
    tools_built: opts.buildTools}, null, 2) + '\n');
  console.log(`Prepared verified dependencies. ${opts.buildTools ? 'Tools built.' : 'Run again with --build-tools before benchmarking.'}`);
  console.log(`Nushell: source ${path.join(opts.directory, 'env.nu')}`);
  console.log(`Bash: source ${path.join(opts.directory, 'env.sh')}`);
}
if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = {options, verifyPatches};
