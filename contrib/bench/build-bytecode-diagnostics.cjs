'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
function unique(values, label) {
  const candidates = [...new Set(values)];
  assert.equal(candidates.length, 1, `expected one ${label}, found: ${candidates.join(', ')}`);
  assert(fs.existsSync(candidates[0]), `missing ${label}: rerun setup-state-access.cjs --build-tools`);
  return candidates[0];
}
function build(directory) {
  const {reth, artifacts} = JSON.parse(fs.readFileSync(path.join(directory, 'build-artifacts.json')));
  // Build-script dependencies can emit an unoptimized copy with another feature
  // set. Select the optimized runtime libraries from the fixed profiling build.
  const library = name => unique(artifacts.filter(a => a.reason === 'compiler-artifact' && a.target.name === name &&
    a.profile.opt_level === '3' && !a.profile.test)
    .flatMap(a => a.filenames.filter(f => f.endsWith('.rlib'))), name);
  const mdbx = unique(artifacts.filter(a => a.reason === 'build-script-executed' && /reth-mdbx-sys/.test(a.package_id))
    .map(a => path.join(a.out_dir, 'libmdbx.a')), 'MDBX static library');
  const out = path.join(directory, 'tools');
  fs.mkdirSync(out, {recursive: true});
  const run = (exe, args) => execFileSync(exe, args, {cwd: root, stdio: 'inherit'});
  run('cc', ['-O2', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
    '-I', path.join(reth, 'crates/storage/libmdbx-rs/mdbx-sys/libmdbx'),
    path.join(__dirname, 'bytecode-latency-diagnostic.c'), mdbx, '-pthread', '-lm', '-ldl',
    '-o', path.join(out, 'bytecode-latency-diagnostic')]);
  const libraries = ['reth_primitives_traits', 'reth_codecs', 'libc'].map(name => [name, library(name)]);
  for (const allocator of ['system', 'jemalloc']) {
    const deps = allocator === 'jemalloc' ? [...libraries, ['tikv_jemallocator', library('tikv_jemallocator')]] : libraries;
    run('rustc', ['--edition=2024', '-O', '-C', 'target-cpu=native',
      ...(allocator === 'jemalloc' ? ['--cfg', 'jemalloc'] : []),
      ...[...new Set(deps.map(([, file]) => path.dirname(file)))].flatMap(dir => ['-L', `dependency=${dir}`]),
      ...deps.flatMap(([name, file]) => ['--extern', `${name}=${file}`]),
      path.join(__dirname, 'bytecode-codec-diagnostic.rs'), '-o', path.join(out, `bytecode-codec-${allocator}`)]);
  }
  console.log(`Built diagnostics in ${out}`);
}
if (require.main === module) {
  try {
    assert(process.argv.length <= 3, 'usage: node contrib/bench/build-bytecode-diagnostics.cjs [SETUP_DIRECTORY]');
    build(path.resolve(process.argv[2] || path.join(root, 'target/state-access-deps')));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = {unique};
