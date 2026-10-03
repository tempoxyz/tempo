'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'bench-e2e.nu'), 'utf8');
function definition(name) {
  const start = source.indexOf(`def ${name} `);
  assert(start >= 0);
  return source.slice(start, source.indexOf('\n}\n', start) + 3);
}

test('local nodes inherit regular log files, preserve both streams, and require explicit timing opt-in', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tempo-node-logging-'));
  try {
    const results = path.join(dir, 'results with spaces');
    fs.mkdirSync(results);
    const node = path.join(dir, 'fake-node.cjs');
    fs.writeFileSync(node, `#!/usr/bin/env node
const fs = require('node:fs');
fs.writeFileSync(process.argv[2], JSON.stringify({
  stdoutIsFile: fs.fstatSync(1).isFile(), stderrIsFile: fs.fstatSync(2).isFile(),
  timing: process.env.TEMPO_BENCH_TX_TIMING,
}));
fs.writeFileSync(1, 'stdout\\n'.repeat(30000));
fs.writeFileSync(2, 'stderr\\n'.repeat(30000));
`, {mode: 0o755});
    // Exercise the production launcher. Only privilege/resource wrapping and
    // the profiler are stubbed; the real background job and redirection run.
    const program = `
def systemd-scope-command [unit, cpus, memory, swap, script] { ["bash" "-c" $script] }
def wrap-samply [cmd, enabled, args] { $cmd }
${definition('taskset-command')}
${definition('start-e2e-local-node')}
let cases = ($env.LOG_TEST_CASES | from json)
for c in $cases {
  start-e2e-local-node $c.role $c.phase $env.LOG_TEST_NODE [$c.metadata] $c.env "" "" false [] $env.LOG_TEST_RESULTS "" "" "" | ignore
}
for i in 0..500 {
  if (job list | is-empty) { break }
  sleep 10ms
}
if not (job list | is-empty) { error make {msg: "node logging jobs did not finish"} }
`;
    const cases = ['baseline-1', 'feature-1'].flatMap(phase => ['a', 'b'].map(role => ({
      phase, role, metadata: path.join(dir, `${phase}-${role}.json`),
      env: phase === 'feature-1' ? 'TEMPO_BENCH_TX_TIMING=1 ' : '',
    })));
    const result = spawnSync('nu', ['--no-config-file', '-c', program], {
      cwd: root, encoding: 'utf8', timeout: 10000,
      env: {...process.env, TEMPO_BENCH_TX_TIMING: '1', LOG_TEST_CASES: JSON.stringify(cases),
        LOG_TEST_NODE: node, LOG_TEST_RESULTS: results},
    });
    assert.equal(result.status, 0, result.stderr || String(result.error));
    assert.doesNotMatch(result.stdout, /stdout\n|stderr\n/);
    for (const c of cases) {
      assert.deepEqual(JSON.parse(fs.readFileSync(c.metadata)), {
        stdoutIsFile: true, stderrIsFile: true, timing: c.phase === 'feature-1' ? '1' : '0',
      });
      assert.equal(fs.readFileSync(path.join(results, `node-${c.phase}-${c.role}.log`), 'utf8'),
        'stdout\n'.repeat(30000) + 'stderr\n'.repeat(30000));
    }
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
