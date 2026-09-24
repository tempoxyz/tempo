const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');

// Exercise the exact inline workflow script without executing external requests.
const workflow = readFileSync(join(__dirname, '../workflows/bench-nightly-failure.yml'), 'utf8');
const script = workflow.split('          script: |\n')[1]
  .split('\n').map(line => line.slice(12)).join('\n');
const notify = new (Object.getPrototypeOf(async function () {}).constructor)(
  'context', 'core', 'process', 'fetch', script);

async function run(overrides = {}, options = {}) {
  const calls = [];
  const context = {
    repo: options.repo || { owner: 'tempoxyz', repo: 'tempo' },
    payload: { workflow_run: {
      id: 35810193790,
      run_attempt: 1,
      name: 'bench-e2e-multi-region-scheduled',
      event: 'schedule',
      conclusion: 'failure',
      head_repository: { full_name: 'tempoxyz/tempo' },
      ...overrides,
    } },
  };
  let error;
  try {
    await notify(context, { info: () => {} }, {
      env: { SLACK_BENCH_BOT_TOKEN: options.missingToken ? '' : 'test-token' },
    }, async (url, request) => {
      calls.push({ url, ...request, body: JSON.parse(request.body) });
      if (options.networkError) throw new Error('connection lost');
      return {
        ok: !options.httpError, status: 503,
        json: async () => options.response || { ok: true, channel: 'C09KA1JNJ02', ts: '1.23' },
      };
    });
  } catch (err) { error = err; }
  return { calls, error };
}

for (const name of ['bench-e2e-scheduled', 'bench-e2e-multi-region-scheduled', 'bench-replay-scheduled']) {
  test(`${name} failure alerts the channel and mentions the on-call group`, async () => {
    const { calls, error } = await run({ name });
    assert.equal(error, undefined);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://slack.com/api/chat.postMessage');
    assert.equal(calls[0].body.channel, 'C09KA1JNJ02');
    assert.match(calls[0].body.text, /<!subteam\^S0C0784UDQF\|oncall-reth>/);
    assert.match(calls[0].body.text, /35810193790\/attempts\/1/);
  });
}

for (const overrides of [
  { event: 'workflow_dispatch' }, { event: 'push' },
  { conclusion: 'success' }, { conclusion: 'cancelled' }, { conclusion: 'skipped' },
  { name: 'unrelated-workflow' }, { head_repository: { full_name: 'fork/tempo' } },
]) {
  test(`ignores ${JSON.stringify(overrides)}`, async () => {
    const { calls, error } = await run(overrides);
    assert.equal(error, undefined);
    assert.deepEqual(calls, []);
  });
}

test('does not post from a fork of the notifier', async () => {
  assert.deepEqual((await run({}, { repo: { owner: 'fork', repo: 'tempo' } })).calls, []);
});

test('a timed-out rerun links to the failed attempt', async () => {
  const { calls, error } = await run({ conclusion: 'timed_out', run_attempt: 2 });
  assert.equal(error, undefined);
  assert.equal(calls.length, 1);
  assert.match(calls[0].body.text, /35810193790\/attempts\/2/);
});

for (const options of [
  { missingToken: true }, { httpError: true },
  { response: { ok: false, error: 'not_in_channel' } }, { networkError: true },
]) {
  test(`surfaces delivery failure without retrying: ${JSON.stringify(options)}`, async () => {
    const { calls, error } = await run({}, options);
    assert.ok(error);
    assert.equal(calls.length, options.missingToken ? 0 : 1);
  });
}
