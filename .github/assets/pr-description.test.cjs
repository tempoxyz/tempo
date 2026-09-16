const { test } = require('node:test');
const assert = require('node:assert/strict');
const { validate, run } = require('./pr-description.cjs');
const valid = '## Problem\nExpired tokens stay cached.\n## Changes\nRefresh expired tokens.\n## Validation\nToken refresh test passed.';

test('accepts concise descriptions and optional sections', () => {
  assert.deepEqual(validate(valid + '\n## Rollout\nDeploy normally.'), []);
  assert.deepEqual(validate(valid.replace('Token refresh test passed.', 'Not run: documentation only.')), []);
});
test('rejects missing, comment-only, and placeholder sections', () => {
  assert.equal(validate(null).length, 3);
  assert.ok(validate(valid.replace('Expired tokens stay cached.', '<!-- explain why -->')).length);
  for (const value of ['TBD', '- [ ] TODO', '<describe problem>', '...']) {
    assert.ok(validate(valid.replace('Expired tokens stay cached.', value)).length, value);
  }
});
test('headings inside fences cannot satisfy required sections', () => {
  assert.equal(validate('```md\n' + valid + '\n```').length, 3);
  assert.equal(validate('~~~md\n' + valid + '\n~~~').length, 3);
});
test('rejects duplicates, permits CRLF and nested detail', () => {
  assert.ok(validate(valid + '\n## Changes\nAnother change').length);
  assert.deepEqual(validate(valid.replaceAll('\n', '\r\n')), []);
  assert.deepEqual(validate(valid + '\n### Manual\nVerify token refresh.'), []);
});

function fixture({ body = valid, group, associated = [], currentSha = 'head', failRead = false } = {}) {
  const statuses = [], failures = [];
  const context = { repo: { owner: 'tempoxyz', repo: 'tempo' }, serverUrl: 'https://github.com', runId: 1,
    payload: group ? { merge_group: group } : { pull_request: { number: 1, head: { sha: 'head' } } } };
  const github = { rest: { repos: {
    createCommitStatus: async value => statuses.push(value), listPullRequestsAssociatedWithCommit: () => {},
  }, pulls: { get: async () => {
    if (failRead) throw new Error('API unavailable');
    return { data: { body, head: { sha: currentSha } } };
  } } }, paginate: async () => associated };
  const summary = { addHeading: () => summary, addRaw: () => summary, write: async () => {} };
  return { github, context, core: { summary, setFailed: value => failures.push(value) }, statuses, failures };
}
test('reads current body rather than stale event body and reports on PR head', async () => {
  const f = fixture();
  f.context.payload.pull_request.body = 'stale';
  await run(f);
  assert.deepEqual(f.statuses.map(s => s.state), ['pending', 'success']);
  assert.ok(f.statuses.every(s => s.sha === 'head'));
});
test('invalid body fails; API error does not pass', async () => {
  const f = fixture({ body: '' }); await run(f);
  assert.equal(f.statuses.at(-1).state, 'failure');
  assert.equal(f.failures.length, 1);
  const error = fixture({ failRead: true });
  await assert.rejects(run(error), /API unavailable/);
  assert.equal(error.statuses.at(-1).state, 'error');
});
test('old push does not report success after head changes', async () => {
  const f = fixture({ currentSha: 'new-head' }); await run(f);
  assert.deepEqual(f.statuses.map(s => s.state), ['pending']);
});
test('merge queue validates associated PRs and fails closed if none are identified', async () => {
  const group = { head_sha: 'merge', base_ref: 'refs/heads/main' };
  const f = fixture({ group, associated: [{ number: 1, state: 'open', base: { ref: 'main' } }] });
  await run(f);
  assert.equal(f.statuses.at(-1).state, 'success');
  assert.equal(f.statuses.at(-1).sha, 'merge');
  const missing = fixture({ group });
  await assert.rejects(run(missing), /Cannot identify/);
  assert.equal(missing.statuses.at(-1).state, 'error');
});
