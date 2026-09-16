const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const helper = path.join(__dirname, 'reth-ci-status.sh');
const workflow = fs.readFileSync(path.join(__dirname, '../workflows/update-reth.yml'), 'utf8');
const step = workflow.split('      - name: Wait for CI and fix failures\n')[1]
  .split('        run: |\n')[1].split('\n      # ── Slack notification')[0]
  .replace(/^          /gm, '').replaceAll('${{ github.repository }}', 'tempoxyz/tempo')
  .replaceAll('/tmp/amp-prompt.txt', '"$TMPDIR/amp-prompt.txt"');

// Execute the actual workflow shell with fake GitHub, git, and Amp commands.
// No network, real repository mutations, comments, or repair agents are involved.
const mock = String.raw`#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const statePath = process.env.TEST_STATE;
const state = JSON.parse(fs.readFileSync(statePath));
const args = process.argv.slice(2);
const tool = path.basename(process.argv[1]);
state.calls.push([tool, ...args]);
let output = '';
let code = 0;
if (tool === 'gh') {
  const endpoint = args.find(a => a.startsWith('repos/')) || '';
  if (endpoint.includes('/check-runs?')) {
    const poll = state.polls[Math.min(state.poll++, state.polls.length - 1)];
    if (poll === 'error') code = 1;
    else output = JSON.stringify(poll);
  } else if (endpoint.includes('/statuses?')) {
    output = JSON.stringify(state.statuses || [[]]);
  } else if (endpoint.includes('/comments')) output = '123';
  else if (args[0] === 'pr' && args[1] === 'view' && args.includes('number')) output = '7625';
  else if (args[0] === 'pr' && args[1] === 'comment') output = 'mock comment';
  else if (args[0] === 'run' && args[1] === 'list') output = '';
  else throw new Error('Unexpected GitHub call: ' + args.join(' '));
} else if (tool === 'git') {
  if (args[0] === 'rev-parse') output = state.sha;
  else if (args[0] !== 'status') throw new Error('Unexpected git mutation');
} else if (tool === 'amp-run') {
  state.repairs++;
  if (state.fix) state.sha = 'new-sha';
} else throw new Error('Unexpected tool');
fs.writeFileSync(statePath, JSON.stringify(state));
process.stdout.write(output + '\n');
process.exitCode = code;
`;

function run({ polls, statuses, fix = false, script = step, clockStep = 1800 }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reth-ci-test-'));
  try {
    fs.mkdirSync(path.join(dir, '.github/scripts'), { recursive: true });
    fs.copyFileSync(helper, path.join(dir, '.github/scripts/reth-ci-status.sh'));
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    for (const name of ['gh', 'git', 'amp-run']) {
      fs.writeFileSync(path.join(bin, name), mock, { mode: 0o755 });
    }
    const statePath = path.join(dir, 'state.json');
    fs.writeFileSync(statePath, JSON.stringify({
      polls, statuses, fix, sha: 'old-sha', poll: 0, repairs: 0, calls: [],
    }));
    const bashEnv = path.join(dir, 'bash-env');
    fs.writeFileSync(bashEnv, `sleep() { SECONDS=$((SECONDS + ${clockStep})); }\n`);
    const result = spawnSync('bash', ['-e', '-c', script], {
      cwd: dir, encoding: 'utf8', timeout: 10000,
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, BASH_ENV: bashEnv,
        TEST_STATE: statePath, GITHUB_REPOSITORY: 'tempoxyz/tempo', TMPDIR: dir },
    });
    assert.ifError(result.error);
    return { ...result, state: JSON.parse(fs.readFileSync(statePath)) };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const checks = (conclusion, status = 'completed') => [{ check_runs: [{
  name: 'test success', status, conclusion,
}, { name: 'lint success', status: 'completed', conclusion: 'success' }] }];
const checkCalls = result => result.state.calls.filter(c => c.some(a => a.includes('/check-runs?')));

test('polls the pushed SHA even when branch metadata would still be stale', () => {
  const result = run({ polls: [checks('failure'), checks('success')], fix: true });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.state.repairs, 1);
  assert.match(checkCalls(result)[0].join(' '), /commits\/old-sha\//);
  assert.match(checkCalls(result)[1].join(' '), /commits\/new-sha\//);
  const logs = result.state.calls.find(c => c[0] === 'gh' && c[1] === 'run');
  assert.equal(logs[logs.indexOf('--commit') + 1], 'old-sha');
});

test('refreshes after a no-op repair and accepts newly green CI', () => {
  const result = run({ polls: [checks('failure'), checks('success')] });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.state.repairs, 1);
  assert.equal(checkCalls(result).length, 2);
});

test('still fails if fresh results confirm an unfixable failure', () => {
  const result = run({ polls: [checks('failure')] });
  assert.equal(result.status, 1);
  assert.equal(result.state.repairs, 1);
  assert.equal(checkCalls(result).length, 2);
  assert.match(result.stdout, /fresh CI results still report the same failures/);
});

test('waits for empty checks to appear instead of declaring success', () => {
  const result = run({ polls: [[{ check_runs: [] }], checks('success')] });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(checkCalls(result).length, 2);
  assert.match(result.stdout, /Waiting for CI checks to appear/);
});

test('empty check sets and API failures both obey the overall deadline', () => {
  for (const poll of [[{ check_runs: [] }], 'error']) {
    const result = run({ polls: [poll] });
    assert.equal(result.status, 1);
    assert.equal(result.state.repairs, 0);
    assert.match(result.stdout, /timed out/);
  }
});

test('does not accept early external successes before test and lint register', () => {
  const result = run({ polls: [[{ check_runs: [{
    name: 'Socket Security', status: 'completed', conclusion: 'success',
  }] }], checks('success')] });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(checkCalls(result).length, 2);
  assert.equal(result.state.repairs, 0);
});

test('allows pending checks to complete after a no-op repair', () => {
  const result = run({ polls: [checks('failure'), checks(null, 'queued'), checks('success')] });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.state.repairs, 1);
  assert.equal(checkCalls(result).length, 3);
});

test('refreshes after a no-op stuck-job investigation', () => {
  const result = run({ polls: [checks(null, 'in_progress'), checks('success')],
    script: step.replace('CI_TIMEOUT_MINUTES=30', 'CI_TIMEOUT_MINUTES=0') });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.state.repairs, 1);
});

test('normalizes check conclusions and selects the newest paginated legacy status', () => {
  const conclusions = ['success', 'neutral', 'skipped', 'failure', 'cancelled', 'timed_out', 'action_required', null];
  const pages = conclusions.map(conclusion => ({ check_runs: [{
    name: String(conclusion), status: conclusion === null ? 'queued' : 'completed', conclusion,
  }] }));
  const result = run({ polls: [pages], statuses: [
    [{ id: 2, context: 'external', state: 'success' }],
    [{ id: 1, context: 'external', state: 'failure' }],
  ], script: 'bash .github/scripts/reth-ci-status.sh old-sha' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout).map(c => c.state), [
    'SUCCESS', 'SUCCESS', 'SUCCESS', 'FAILURE', 'FAILURE', 'FAILURE', 'FAILURE', 'PENDING', 'SUCCESS',
  ]);
});

test('handles API responses larger than the operating system argument limit', () => {
  const pages = checks('success');
  pages[0].check_runs[0].output = { text: 'x'.repeat(200000) };
  const result = run({ polls: [pages], script: 'bash .github/scripts/reth-ci-status.sh old-sha' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout)[0].state, 'SUCCESS');
});
