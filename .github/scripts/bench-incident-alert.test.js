const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');

const alert = require('./bench-incident-alert.js');

const FAILED = { 'resolve-refs': 'success', bench: 'failure', 'save-state': 'skipped' };
const PASSED = { 'resolve-refs': 'success', bench: 'success', 'save-state': 'success' };

async function run(results = FAILED, options = {}) {
  const calls = [];
  const logs = { warning: [], notice: [] };
  const responses = [...(options.responses || [{ ok: true, status: 202 }])];
  let error;
  try {
    await alert({
      core: { info: () => {}, notice: m => logs.notice.push(m), warning: m => logs.warning.push(m) },
      context: {
        repo: options.repo || { owner: 'tempoxyz', repo: 'tempo' },
        eventName: options.event || 'schedule',
        runId: 35810193790,
      },
      env: {
        INCIDENT_IO_URL: options.missingSecrets ? '' : 'https://api.incident.io/v2/alert_events/http/source',
        INCIDENT_IO_TOKEN: options.missingSecrets ? '' : 'test-token',
        GITHUB_RUN_ATTEMPT: options.attempt || '1',
        BENCH_JOB_RESULTS: JSON.stringify(Object.fromEntries(
          Object.entries(results).map(([name, result]) => [name, { result }]))),
        ALERT_KEY: 'tempo:bench-test-nightly',
        ALERT_NAME: 'Nightly test benchmark',
        ALERT_WORKFLOW: 'bench-test-scheduled.yml',
        ALERT_RESOLVE_JOBS: 'bench,save-state',
        ALERT_DETAIL: options.detail || '',
        BENCH_BASELINE_REF: 'aaaa',
        BENCH_FEATURE_REF: 'bbbb',
      },
      fetch: async (url, request) => {
        calls.push({ url, ...request, body: JSON.parse(request.body) });
        const next = responses.length > 1 ? responses.shift() : responses[0];
        if (next === 'network') throw new Error('connection lost');
        return next;
      },
      setTimeout: callback => callback(),
    });
  } catch (err) { error = err; }
  return { calls, error, logs };
}

for (const results of [
  { 'resolve-refs': 'failure', bench: 'skipped', 'save-state': 'skipped' },
  FAILED,
  { 'resolve-refs': 'success', bench: 'success', 'save-state': 'failure' },
]) {
  test(`fires on a failed job: ${JSON.stringify(results)}`, async () => {
    const { calls, error } = await run(results);
    assert.equal(error, undefined);
    assert.equal(calls.length, 1);
    const { url, headers, body } = calls[0];
    assert.equal(url, 'https://api.incident.io/v2/alert_events/http/source');
    assert.equal(headers.Authorization, 'Bearer test-token');
    assert.equal(body.status, 'firing');
    assert.equal(body.deduplication_key, 'tempo:bench-test-nightly');
    assert.equal(body.metadata.team, 'reth');
    const failed = Object.keys(results).find(name => results[name] === 'failure');
    assert.equal(body.title, `Nightly test benchmark failed: ${failed}`);
    assert.match(body.description, /35810193790\/attempts\/1/);
    assert.match(body.description, /Baseline: aaaa/);
  });
}

test('includes the extra detail when firing', async () => {
  const { calls } = await run(FAILED, { detail: 'The nightly Docker build is 30h old' });
  assert.match(calls[0].body.description, /30h old/);
});

test('resolves only when every resolve job succeeded', async () => {
  const { calls, error } = await run(PASSED);
  assert.equal(error, undefined);
  assert.equal(calls[0].body.status, 'resolved');
  assert.equal(calls[0].body.title, 'Nightly test benchmark recovered');
});

test('a skipped benchmark leaves the alert unchanged', async () => {
  const { calls, error } = await run({ 'resolve-refs': 'success', bench: 'skipped', 'save-state': 'success' });
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

test('a rerun links to its attempt and can still fire', async () => {
  const { calls } = await run(FAILED, { attempt: '2' });
  assert.equal(calls[0].body.status, 'firing');
  assert.match(calls[0].body.source_url, /35810193790\/attempts\/2/);
});

test('a rerun does not resolve a newer page', async () => {
  const { calls, error } = await run(PASSED, { attempt: '2' });
  assert.equal(error, undefined);
  assert.deepEqual(calls, []);
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

for (const responses of [['network', { ok: true, status: 202 }], [{ ok: false, status: 429 }, { ok: true, status: 202 }]]) {
  test(`retries a transient failure: ${JSON.stringify(responses[0])}`, async () => {
    const { calls, error } = await run(undefined, { responses });
    assert.equal(error, undefined);
    assert.equal(calls.length, 2);
  });
}

for (const response of ['network', { ok: false, status: 503 }]) {
  test(`surfaces a firing delivery failure after 3 attempts: ${JSON.stringify(response)}`, async () => {
    const { calls, error } = await run(undefined, { responses: [response] });
    assert.ok(error);
    assert.equal(calls.length, 3);
  });
}

test('does not retry a client error', async () => {
  const { calls, error } = await run(undefined, { responses: [{ ok: false, status: 401 }] });
  assert.ok(error);
  assert.equal(calls.length, 1);
});

test('a failed resolve only warns', async () => {
  const { calls, error, logs } = await run(PASSED, { responses: [{ ok: false, status: 503 }] });
  assert.equal(error, undefined);
  assert.equal(calls.length, 3);
  assert.equal(logs.warning.length, 1);
});

// Each scheduled workflow pages through the shared script with its own key.
for (const [file, key, resolveJobs] of [
  ['bench-e2e-multi-region-scheduled.yml', 'tempo:bench-e2e-multi-region-nightly', 'bench-e2e-multi-region,save-state'],
  ['bench-e2e-scheduled.yml', 'tempo:bench-e2e-nightly', 'bench-e2e'],
  ['bench-replay-scheduled.yml', 'tempo:bench-replay-nightly-', 'bench-replay,save-state'],
]) {
  test(`${file} pages through incident.io, not Slack`, async () => {
    const workflow = readFileSync(join(__dirname, '../workflows', file), 'utf8');
    const job = workflow.split('\n  incident-io:\n')[1];
    assert.ok(job, 'incident-io job missing');
    assert.match(job, /require\('\.\/\.github\/scripts\/bench-incident-alert\.js'\)/);
    assert.ok(job.includes(`ALERT_KEY: ${key}`));
    assert.ok(job.includes(`ALERT_RESOLVE_JOBS: ${resolveJobs}`));
    assert.ok(job.includes("github.event_name == 'schedule'"));
    for (const name of resolveJobs.split(',')) {
      assert.match(job.split('\n')[0], new RegExp(`\\b${name}\\b`), `needs must include ${name}`);
    }
    assert.doesNotMatch(workflow, /chat\.postMessage/);
  });
}

test('scheduled replay failures do not also post to Slack', () => {
  const workflow = readFileSync(join(__dirname, '../workflows/bench-replay.yml'), 'utf8');
  const step = workflow.split('      - name: Send Slack notification (failure)\n')[1].split('\n')[0];
  assert.match(step, /github\.event_name != 'schedule'/);
});
