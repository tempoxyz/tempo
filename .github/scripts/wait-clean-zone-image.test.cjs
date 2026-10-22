const { test } = require('node:test');
const assert = require('node:assert/strict');
const wait = require('./wait-clean-zone-image.cjs');

function fixture(overrides = {}) {
  process.env.GITHUB_RUN_ATTEMPT = '2';
  let ticks = 0;
  const outputs = [];
  const actions = {
    getWorkflowRun: async () => ({ data: { head_sha: 'candidate', run_attempt: 2, ...overrides.run } }),
    listJobsForWorkflowRunAttempt: 'jobs', listWorkflowRunArtifacts: 'artifacts',
  };
  return {
    context: { repo: { owner: 'tempoxyz', repo: 'tempo' }, runId: 1, sha: 'candidate' },
    core: { info() {}, setOutput: (...args) => outputs.push(args) }, outputs,
    now: () => ticks, sleep: async ms => { ticks += ms; }, timeoutMs: 30000,
    github: { rest: { actions }, paginate: async (method, params) => {
      assert.equal(params.run_id, 1);
      if (method === 'jobs') {
        assert.equal(params.attempt_number, 2);
        return [{ name: 'Rebuild production tempo-zone image without cache',
          status: 'completed', conclusion: 'success', ...overrides.job }];
      }
      return overrides.artifacts || [{ name: 'clean-tempo-zone-image-2', id: 42, expired: false }];
    } },
  };
}
test('returns only the successful current attempt artifact', async () => {
  const f = fixture();
  assert.equal(await wait(f), 42);
  assert.deepEqual(f.outputs, [['artifact-id', 42]]);
});
for (const run of [{ head_sha: 'other' }, { run_attempt: 3 }]) {
  test(`rejects changed ownership ${JSON.stringify(run)}`, async () => {
    await assert.rejects(wait(fixture({ run })), /ownership or attempt changed/);
  });
}
test('fails immediately when independent rebuild fails', async () => {
  await assert.rejects(wait(fixture({ job: { conclusion: 'failure' } })), /rebuild failed/);
});
test('cannot schedule genesis while rebuild is running', async () => {
  await assert.rejects(wait(fixture({ job: { status: 'in_progress' } })), /Timed out/);
});
test('ignores previous-attempt and expired artifacts', async () => {
  await assert.rejects(wait(fixture({ artifacts: [
    { name: 'clean-tempo-zone-image-1', id: 9 },
    { name: 'clean-tempo-zone-image-2', id: 10, expired: true },
  ] })), /Timed out/);
});
