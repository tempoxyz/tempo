const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');

// Exercise the scheduled workflow's inline incident.io alert without requests.
const workflow = readFileSync(join(__dirname, '../workflows/bench-e2e-multi-region-scheduled.yml'), 'utf8');
const step = workflow.split('      - name: Update incident.io alert\n')[1];
const script = step.split('          script: |\n')[1]
  .split('\n').map(line => line.slice(12)).join('\n');
const notify = new (Object.getPrototypeOf(async function () {}).constructor)(
  'context', 'core', 'process', 'fetch', 'setTimeout', script);
const instant = callback => callback();

const FAILED = {
  'resolve-refs': 'success', 'bench-e2e-multi-region': 'failure', 'save-state': 'skipped',
};
const PASSED = {
  'resolve-refs': 'success', 'bench-e2e-multi-region': 'success', 'save-state': 'success',
};

async function run(results = FAILED, options = {}) {
  const calls = [];
  const logs = { warning: [], notice: [] };
  const context = {
    repo: options.repo || { owner: 'tempoxyz', repo: 'tempo' },
    eventName: options.event || 'schedule',
    runId: 35810193790,
  };
  const jobs = Object.fromEntries(Object.entries(results).map(([name, result]) => [name, {
    result,
    outputs: name === 'resolve-refs' ? { 'baseline-ref': 'aaaa', 'feature-ref': 'bbbb' } : {},
  }]));
  const responses = [...(options.responses || [{ ok: true, status: 202 }])];
  let error;
  try {
    await notify(context, {
      info: () => {},
      notice: m => logs.notice.push(m),
      warning: m => logs.warning.push(m),
    }, {
      env: {
        INCIDENT_IO_URL: options.missingSecrets ? '' : 'https://api.incident.io/v2/alert_events/http/source',
        INCIDENT_IO_TOKEN: options.missingSecrets ? '' : 'test-token',
        GITHUB_RUN_ATTEMPT: options.attempt || '1',
        BENCH_JOB_RESULTS: JSON.stringify(jobs),
      },
    }, async (url, request) => {
      calls.push({ url, ...request, body: JSON.parse(request.body) });
      const next = responses.length > 1 ? responses.shift() : responses[0];
      if (next === 'network') throw new Error('connection lost');
      return next;
    }, instant);
  } catch (err) { error = err; }
  return { calls, error, logs };
}

for (const results of [
  { 'resolve-refs': 'failure', 'bench-e2e-multi-region': 'skipped', 'save-state': 'skipped' },
  FAILED,
  { 'resolve-refs': 'success', 'bench-e2e-multi-region': 'success', 'save-state': 'failure' },
]) {
  test(`fires on dependency failure: ${JSON.stringify(results)}`, async () => {
    const { calls, error } = await run(results);
    assert.equal(error, undefined);
    assert.equal(calls.length, 1);
    const { url, headers, body } = calls[0];
    assert.equal(url, 'https://api.incident.io/v2/alert_events/http/source');
    assert.equal(headers.Authorization, 'Bearer test-token');
    assert.equal(body.status, 'firing');
    assert.equal(body.deduplication_key, 'tempo:bench-e2e-multi-region-nightly');
    assert.equal(body.metadata.team, 'reth');
    const failedJob = Object.keys(results).find(name => results[name] === 'failure');
    assert.ok(body.title.includes(failedJob));
    assert.match(body.description, /35810193790\/attempts\/1/);
    assert.match(body.description, /Baseline: aaaa/);
  });
}

test('resolves after a run that benchmarked and saved state', async () => {
  const { calls, error } = await run(PASSED);
  assert.equal(error, undefined);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].body.status, 'resolved');
  assert.equal(calls[0].body.deduplication_key, 'tempo:bench-e2e-multi-region-nightly');
});

test('a run with no new commit leaves the alert unchanged', async () => {
  const { calls, error } = await run({
    'resolve-refs': 'success', 'bench-e2e-multi-region': 'skipped', 'save-state': 'skipped',
  });
  assert.equal(error, undefined);
  assert.deepEqual(calls, []);
});

for (const event of ['workflow_dispatch', 'push']) {
  test(`ignores ${event}`, async () => {
    assert.deepEqual((await run(undefined, { event })).calls, []);
  });
}

test('does not send from a fork', async () => {
  assert.deepEqual((await run(undefined, { repo: { owner: 'fork', repo: 'tempo' } })).calls, []);
});

test('a failed rerun links to its attempt', async () => {
  const { calls } = await run(undefined, { attempt: '2' });
  assert.match(calls[0].body.source_url, /35810193790\/attempts\/2/);
});

test('missing secrets fail a firing alert', async () => {
  const { calls, error } = await run(undefined, { missingSecrets: true });
  assert.ok(error);
  assert.deepEqual(calls, []);
});

test('missing secrets only note a resolve', async () => {
  const { calls, error, logs } = await run(PASSED, { missingSecrets: true });
  assert.equal(error, undefined);
  assert.deepEqual(calls, []);
  assert.equal(logs.notice.length, 1);
});

test('retries a transient delivery failure', async () => {
  const { calls, error } = await run(undefined, { responses: ['network', { ok: true, status: 202 }] });
  assert.equal(error, undefined);
  assert.equal(calls.length, 2);
});

for (const response of ['network', { ok: false, status: 503 }]) {
  test(`surfaces a firing delivery failure after 3 attempts: ${JSON.stringify(response)}`, async () => {
    const { calls, error } = await run(undefined, { responses: [response] });
    assert.ok(error);
    assert.equal(calls.length, 3);
  });
}

test('a rerun does not resolve a newer page', async () => {
  const { calls, error } = await run(PASSED, { attempt: '2' });
  assert.equal(error, undefined);
  assert.deepEqual(calls, []);
});

test('a rerun can still fire', async () => {
  const { calls } = await run(FAILED, { attempt: '2' });
  assert.equal(calls[0].body.status, 'firing');
});

test('does not retry a client error', async () => {
  const { calls, error } = await run(undefined, { responses: [{ ok: false, status: 401 }] });
  assert.ok(error);
  assert.equal(calls.length, 1);
});

test('retries a rate limit', async () => {
  const { calls, error } = await run(undefined, { responses: [{ ok: false, status: 429 }, { ok: true, status: 202 }] });
  assert.equal(error, undefined);
  assert.equal(calls.length, 2);
});

test('a failed resolve only warns', async () => {
  const { calls, error, logs } = await run(PASSED, { responses: [{ ok: false, status: 503 }] });
  assert.equal(error, undefined);
  assert.equal(calls.length, 3);
  assert.equal(logs.warning.length, 1);
});
