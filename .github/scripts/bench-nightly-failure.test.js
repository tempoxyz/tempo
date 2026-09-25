const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');

// Exercise the existing scheduled workflow's inline notification without requests.
const workflow = readFileSync(join(__dirname, '../workflows/bench-e2e-multi-region-scheduled.yml'), 'utf8');
const step = workflow.split('      - name: Alert reth on-call\n')[1];
const script = step.split('          script: |\n')[1]
  .split('\n').map(line => line.slice(12)).join('\n');
const notify = new (Object.getPrototypeOf(async function () {}).constructor)(
  'context', 'core', 'process', 'fetch', script);

async function run(results = { 'bench-e2e-multi-region': 'failure' }, options = {}) {
  const calls = [];
  const context = {
    repo: options.repo || { owner: 'tempoxyz', repo: 'tempo' },
    eventName: options.event || 'schedule',
    runId: 35810193790,
  };
  let error;
  try {
    await notify(context, { info: () => {} }, {
      env: {
        SLACK_BENCH_BOT_TOKEN: options.missingToken ? '' : 'test-token',
        GITHUB_RUN_ATTEMPT: options.attempt || '1',
        BENCH_JOB_RESULTS: JSON.stringify(Object.fromEntries(
          Object.entries(results).map(([name, result]) => [name, { result }]))),
      },
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

for (const results of [
  { 'resolve-refs': 'failure', 'bench-e2e-multi-region': 'skipped', 'save-state': 'skipped' },
  { 'resolve-refs': 'success', 'bench-e2e-multi-region': 'failure', 'save-state': 'skipped' },
  { 'resolve-refs': 'success', 'bench-e2e-multi-region': 'success', 'save-state': 'failure' },
]) {
  test(`alerts on dependency failure: ${JSON.stringify(results)}`, async () => {
    const { calls, error } = await run(results);
    assert.equal(error, undefined);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://slack.com/api/chat.postMessage');
    assert.equal(calls[0].body.channel, 'C09KA1JNJ02');
    assert.match(calls[0].body.text, /<!subteam\^S0C0784UDQF\|oncall-reth>/);
    assert.match(calls[0].body.text, /35810193790\/attempts\/1/);
    const failedJob = Object.keys(results).find(name => results[name] === 'failure');
    assert.ok(calls[0].body.text.includes(`*Failed jobs:* ${failedJob}`));
  });
}

for (const event of ['workflow_dispatch', 'push']) {
  test(`ignores ${event}`, async () => {
    assert.deepEqual((await run(undefined, { event })).calls, []);
  });
}

for (const result of ['success', 'cancelled', 'skipped']) {
  test(`ignores ${result} jobs`, async () => {
    const { calls, error } = await run({ 'bench-e2e-multi-region': result });
    assert.equal(error, undefined);
    assert.deepEqual(calls, []);
  });
}

test('does not post from a fork', async () => {
  assert.deepEqual((await run(undefined, { repo: { owner: 'fork', repo: 'tempo' } })).calls, []);
});

test('a failed rerun links to its attempt', async () => {
  const { calls, error } = await run(undefined, { attempt: '2' });
  assert.equal(error, undefined);
  assert.equal(calls.length, 1);
  assert.match(calls[0].body.text, /35810193790\/attempts\/2/);
});

for (const options of [
  { missingToken: true }, { httpError: true },
  { response: { ok: false, error: 'not_in_channel' } }, { networkError: true },
]) {
  test(`surfaces delivery failure without retrying: ${JSON.stringify(options)}`, async () => {
    const { calls, error } = await run(undefined, options);
    assert.ok(error);
    assert.equal(calls.length, options.missingToken ? 0 : 1);
  });
}
