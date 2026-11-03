const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const { runInNewContext } = require('node:vm');

const source = readFileSync(`${__dirname}/bench-slack-notify.js`, 'utf8');
const context = { repo: { owner: 'tempoxyz', repo: 'tempo' }, serverUrl: 'https://github.com', runId: 1 };

async function run({ kind = 'e2e', sig = 'good', env = {}, response = { ok: true, ts: '1.2' }, event = 'success' } = {}) {
  const calls = [], changes = { tps: { sig } };
  const summary = { config: {}, results: { baseline: {}, feature: {}, changes }, changes,
    wait_times: { persist: { title: 'Persist' } } };
  const module = { exports: {} };
  runInNewContext(source, {
    module, process: { env: { SLACK_BENCH_BOT_TOKEN: 'test', SLACK_BENCH_CHANNEL: 'CHANNEL', BENCH_ACTOR: 'actor', ...env } },
    require: name => name === 'fs' ? { readFileSync: file => JSON.stringify(
      file.endsWith('bench-slack-users.json') ? { actor: 'UACTOR' } : summary) } : require(name),
    fetch: async (_, request) => { calls.push(JSON.parse(request.body)); return { json: async () => response }; },
  });
  await module.exports[kind][event]({ context, core: { info() {}, warning() {} }, failedStep: 'build' });
  return calls;
}

// Test shared policy once; keep replay threading here and real Zones cases in its existing matrix.
test('shared routing and replay thread delivery', async () => {
  for (const [options, target] of [
    [{}, 'CHANNEL'],
    [{ env: { BENCH_SLACK: 'on-win' } }, 'CHANNEL'],
    [{ sig: 'neutral' }, 'UACTOR'],
    [{ sig: 'bad' }, 'UACTOR'],
    [{ sig: 'neutral', env: { BENCH_SLACK: 'on-win' } }, null],
    [{ env: { SLACK_BENCH_CHANNEL: '' } }, 'UACTOR'],
    [{ env: { SLACK_BENCH_CHANNEL: '', BENCH_SLACK: 'on-win' } }, null],
    [{ sig: 'neutral', env: { BENCH_ACTOR: 'unmapped' } }, null],
    [{ env: { SLACK_BENCH_BOT_TOKEN: '' } }, null],
    [{ event: 'failure', env: { BENCH_SLACK: 'on-win' } }, 'UACTOR'],
    [{ response: { ok: false } }, 'CHANNEL'],
    [{ kind: 'replay' }, 'CHANNEL'],
    [{ kind: 'replay', sig: 'neutral' }, 'UACTOR'],
    [{ kind: 'replay', response: { ok: false } }, 'CHANNEL'],
    [{ kind: 'replay', event: 'failure' }, 'UACTOR'],
  ]) {
    const calls = await run(options);
    const threaded = target && options.kind === 'replay' && options.event !== 'failure' && !options.response;
    assert.deepEqual(calls.map(c => c.channel), target ? Array(threaded ? 2 : 1).fill(target) : [], JSON.stringify(options));
    if (threaded) assert.equal(calls[1].thread_ts, '1.2');
  }
});

test('nightly failure posts failed jobs to the workflows channel', async () => {
  const calls = [];
  const module = { exports: {} };
  runInNewContext(source, {
    module, require,
    process: { env: { SLACK_BENCH_BOT_TOKEN: 'test', SLACK_WORKFLOWS_CHANNEL: 'CWORKFLOWS' } },
    fetch: async (_, request) => { calls.push(JSON.parse(request.body)); return { json: async () => ({ ok: true }) }; },
  });
  const github = { rest: { actions: { listJobsForWorkflowRun: async () => ({ data: { jobs: [
    { name: 'resolve-refs', conclusion: 'success', html_url: 'https://x/1' },
    { name: 'bench-zones / bench-zones', conclusion: 'failure', html_url: 'https://x/2' },
    { name: 'notify-failure', conclusion: null, html_url: 'https://x/3' },
  ] } }) } } };
  const ctx = { ...context, workflow: 'zone-benchmarks', sha: 'd8261641ce1b7876d451ac67bc58c8e2f92aa307' };
  await module.exports.nightlyFailure({ github, context: ctx, core: { info() {}, warning() {} } });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].channel, 'CWORKFLOWS');
  assert.equal(calls[0].text, 'Nightly zone-benchmarks failed on d8261641');
  const body = calls[0].blocks[0].text.text;
  assert.match(body, /bench-zones \/ bench-zones> \(failure\)/);
  assert.doesNotMatch(body, /resolve-refs|notify-failure/);

  calls.length = 0;
  const silent = { exports: {} };
  runInNewContext(source, { module: silent, require, process: { env: { SLACK_BENCH_BOT_TOKEN: 'test' } },
    fetch: async () => { calls.push(1); } });
  await silent.exports.nightlyFailure({ github, context: ctx, core: { info() {}, warning() {} } });
  assert.equal(calls.length, 0);
});
