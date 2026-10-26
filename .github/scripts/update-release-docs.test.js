const assert = require('node:assert/strict');
const { test } = require('node:test');
const { updatePage, run } = require('./update-release-docs');

const release = {
  tagName: 'v1.16.1', publishedAt: '2026-10-14T23:31:30-07:00',
  isDraft: false, isPrerelease: false, body: 'Updates the mainnet identity.',
};
const table = `---\ntitle: Upgrades\n---\n\n## Node Operator Updates\n\n| Release | Date | Network | Description | Priority |\n|---------|------|---------|-------------|----------|\n| [v1.16.0](https://github.com/tempoxyz/tempo/releases/tag/v1.16.0) | Oct 6, 2026 | Testnet + Mainnet | Existing guidance | Required |\n| [v1.15.0](https://github.com/tempoxyz/tempo/releases/tag/v1.15.0) | Sep 24, 2026 | Testnet + Mainnet | Older guidance | Recommended |\n\n## T13\n\nUnrelated content\n`;

test('adds publication metadata in UTC, preserves existing guidance, and is idempotent', () => {
  const updated = updatePage(table, release);
  assert.equal(updated.replace(/^\| \[v1\.16\.1\].*\n/m, ''), table);
  assert.match(updated, /Oct 15, 2026 \| Review required/);
  assert.ok(updated.indexOf('[v1.16.1]') < updated.indexOf('[v1.16.0]'));
  assert.equal(updatePage(updated, release), updated);
});

test('backfills older releases in version order and labels prereleases', () => {
  const updated = updatePage(table, { ...release, tagName: 'v1.15.1' });
  assert.ok(updated.indexOf('[v1.16.0]') < updated.indexOf('[v1.15.1]'));
  assert.ok(updated.indexOf('[v1.15.1]') < updated.indexOf('[v1.15.0]'));
  assert.match(updatePage(table, { ...release, tagName: 'v1.17.0-rc.1', isPrerelease: true }),
    /<Badge variant="gray">Pre-release<\/Badge>/);
});

test('rejects unrelated tags, drafts, invalid dates, and a missing table before writing', () => {
  for (const tagName of ['zones/v0.3.6', 'tempo-alloy@1.16.0', 'v1.2.3\nmalicious']) {
    assert.throws(() => run({ ...release, tagName }, () => assert.fail('unexpected API call')));
  }
  assert.throws(() => updatePage(table, { ...release, isDraft: true }));
  assert.throws(() => updatePage(table, { ...release, publishedAt: 'invalid' }));
  assert.throws(() => updatePage('## Other\n', release));
  assert.throws(() => updatePage('## Node Operator Updates\nNo table\n', release));
});

function fakeApi({ existingPR = false, documented = false, existingBranch = false } = {}) {
  const writes = [];
  const initial = documented ? updatePage(table, release) : table;
  let branchContent = existingBranch ? `${updatePage(table, release)}\nMaintainer edit\n` : initial;
  return {
    writes,
    api(method, endpoint, payload) {
      if (method !== 'GET') {
        writes.push({ method, endpoint, payload });
        if (method === 'PUT') branchContent = Buffer.from(payload.content, 'base64').toString();
        return { html_url: 'https://github.com/tempoxyz/docs/pull/123' };
      }
      if (endpoint.endsWith('/docs')) return { default_branch: 'main' };
      if (endpoint.includes('/pulls?')) return existingPR ? [{ html_url: 'existing' }] : [];
      if (endpoint.includes('/git/ref/')) return { object: { sha: 'base-commit' } };
      if (endpoint.includes('/git/matching-refs/')) return existingBranch ? [{ ref: `refs/heads/automation/tempo-release-${release.tagName}` }] : [];
      if (endpoint.includes('/contents/')) return {
        sha: 'file-sha', content: Buffer.from(endpoint.endsWith('ref=base-commit') ? initial : branchContent).toString('base64'),
      };
      assert.fail(`Unexpected endpoint: ${endpoint}`);
    },
  };
}

test('opens one draft PR with the release notes and a commit based on the docs default branch', () => {
  const { api, writes } = fakeApi();
  run(release, api);
  assert.deepEqual(writes.map(({ method }) => method), ['POST', 'PUT', 'POST']);
  assert.equal(writes[0].payload.sha, 'base-commit');
  assert.equal(writes[2].payload.draft, true);
  assert.equal(writes[2].payload.base, 'main');
  assert.match(writes[2].payload.body, /Updates the mainnet identity\./);
  assert.equal(Buffer.from(writes[1].payload.content, 'base64').toString(), updatePage(table, release));
});

test('reruns never duplicate existing PRs, including closed PRs, or documented releases', () => {
  for (const options of [{ existingPR: true }, { documented: true }]) {
    const { api, writes } = fakeApi(options);
    run(release, api);
    assert.deepEqual(writes, []);
  }
});

test('resumes after a branch push without overwriting maintainer edits', () => {
  const { api, writes } = fakeApi({ existingBranch: true });
  run(release, api);
  assert.equal(writes.length, 1);
  assert.ok(writes[0].endpoint.endsWith('/pulls'));
});
