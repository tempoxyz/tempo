'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const source = fs.readFileSync(path.resolve(__dirname, '../../tempo.nu'), 'utf8');
function definition(name) {
  const start = source.indexOf(`def ${name} `);
  assert(start >= 0);
  return source.slice(start, source.indexOf('\n}\n', start) + 3);
}
test('suite build reuse is checksum-verified and keyed by build settings', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tempo-build-cache-'));
  try {
    fs.mkdirSync(path.join(dir, 'bin'));
    const log = path.join(dir, 'build.log'), config = path.join(dir, 'config.toml');
    fs.writeFileSync(config, '# dependency config\n');
    fs.writeFileSync(path.join(dir, 'bin/cargo'), '#!/bin/sh\nset -eu\n[ "${FAKE_FAIL:-0}" = 0 ] || exit 7\nprintf "build\\n" >> "$FAKE_LOG"\nmkdir -p target/profiling\nprintf "executable\\n" > target/profiling/tempo\nchmod +x target/profiling/tempo\n', {mode: 0o755});
    const definitions = `const RUSTFLAGS = "-C target-cpu=native"
def bench-cache-key [sha, features, no_default] { "unused" }
def try-cache-download [wt, profile, sha, key] { error make {msg: "patched build read shared cache"} }
def cache-upload [wt, profile, sha, key] { error make {msg: "patched build wrote shared cache"} }
def cargo-feature-args [features, no_default] { [] }
${definition('worktree-bin')}
${definition('build-in-worktree')}`;
    const run = (wt, features, extra = {}) => {
      fs.mkdirSync(path.join(dir, wt, 'feature'), {recursive: true});
      return spawnSync('nu', ['--no-config-file', '-c', `${definitions}\nbuild-in-worktree $env.WT HEAD profiling ${features} abc`],
        {encoding: 'utf8', env: {...process.env, PATH: path.join(dir, 'bin') + ':' + process.env.PATH,
          TEMPO_BENCH_CARGO_CONFIG: config, TEMPO_BENCH_SUITE_BUILD_CACHE: path.join(dir, 'cache'),
          WT: path.join(dir, wt, 'feature'), FAKE_LOG: log, ...extra}});
    };
    for (const [wt, features] of [['first', 'a'], ['second', 'a'], ['third', 'b']]) {
      const result = run(wt, features); assert.equal(result.status, 0, result.stderr);
    }
    assert.equal(fs.readFileSync(log, 'utf8'), 'build\nbuild\n');
    assert.equal(fs.readFileSync(path.join(dir, 'second/feature/target/profiling/tempo'), 'utf8'), 'executable\n');
    assert.notEqual(run('failed', 'c', {FAKE_FAIL: '1'}).status, 0);
    for (const name of fs.readdirSync(path.join(dir, 'cache')).filter(n => !n.endsWith('.sha256')))
      fs.appendFileSync(path.join(dir, 'cache', name), 'tampered');
    const corrupt = run('fourth', 'a');
    assert.notEqual(corrupt.status, 0); assert.match(corrupt.stderr, /checksum changed/);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
