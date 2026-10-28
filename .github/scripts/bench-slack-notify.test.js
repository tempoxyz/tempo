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
