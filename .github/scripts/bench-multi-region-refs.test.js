const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');

// Execute the actual workflow script without adding a YAML runtime dependency.
const workflow = readFileSync(join(__dirname, '../workflows/bench-e2e-multi-region.yml'), 'utf8');
const step = workflow.split('      - name: Resolve baseline and feature refs\n')[1]
  .split('\n      - name:')[0];
const script = step.split('          script: |\n')[1]
  .split('\n').map(line => line.slice(12)).join('\n');
const resolveRefs = new (Object.getPrototypeOf(async function () {}).constructor)(
  'github', 'context', 'core', 'process', script);

const HEAD = '1'.repeat(40);
const MERGE_BASE = '2'.repeat(40);
const MAIN = '3'.repeat(40);
const OTHER = '4'.repeat(40);

async function run(env = {}, overrides = {}, failCompare = false) {
  const exported = {};
  const comparisons = [];
  const commits = new Map([
    [HEAD, HEAD], ['main', MAIN], ['old-main', MERGE_BASE], ['custom-feature', OTHER],
  ]);
  const github = { rest: { repos: {
    getCommit: async ({ owner, repo, ref }) => {
      assert.equal(`${owner}/${repo}`, 'tempoxyz/tempo');
      if (!commits.has(ref)) throw new Error(`Unknown ref: ${ref}`);
      return { data: { sha: commits.get(ref) } };
    },
    compareCommits: async (args) => {
      if (failCompare) throw new Error('No common ancestor');
      comparisons.push(args);
      return { data: { merge_base_commit: { sha: MERGE_BASE } } };
    },
  } } };
  const context = {
    repo: { owner: 'tempoxyz', repo: 'tempo' }, sha: HEAD,
    ref: 'refs/heads/feature', payload: {}, ...overrides,
  };
  await resolveRefs(github, context, {
    exportVariable: (name, value) => { exported[name] = value; }, info: () => {},
  }, { env });
  return { exported, comparisons };
}

test('dispatch defaults benchmark the selected head against its merge-base, not main vs main', async () => {
  const { exported, comparisons } = await run();
  assert.equal(exported.BENCH_INPUT_FEATURE, HEAD);
  assert.equal(exported.BENCH_INPUT_FEATURE_NAME, 'feature');
  assert.equal(exported.BENCH_INPUT_BASELINE, MERGE_BASE);
  assert.deepEqual(comparisons, [{ owner: 'tempoxyz', repo: 'tempo', base: 'main', head: HEAD }]);
});

test('scheduled explicit refs and labels are preserved and pinned', async () => {
  const { exported, comparisons } = await run({
    BENCH_INPUT_BASELINE: 'old-main', BENCH_INPUT_FEATURE: 'main',
    BENCH_INPUT_BASELINE_NAME: 'previous-nightly', BENCH_INPUT_FEATURE_NAME: 'current-nightly',
  });
  assert.equal(exported.BENCH_INPUT_BASELINE, MERGE_BASE);
  assert.equal(exported.BENCH_INPUT_FEATURE, MAIN);
  assert.equal(exported.BENCH_INPUT_BASELINE_NAME, 'previous-nightly');
  assert.equal(exported.BENCH_INPUT_FEATURE_NAME, 'current-nightly');
  assert.deepEqual(comparisons, []);
});

test('feature override retains bench-e2e merge-base semantics for the selected workflow head', async () => {
  const { exported, comparisons } = await run({ BENCH_INPUT_FEATURE: 'custom-feature' });
  assert.equal(exported.BENCH_INPUT_FEATURE, OTHER);
  assert.equal(comparisons[0].head, HEAD);
});

test('baseline override leaves feature at the selected head', async () => {
  const { exported, comparisons } = await run({ BENCH_INPUT_BASELINE: 'main' });
  assert.equal(exported.BENCH_INPUT_BASELINE, MAIN);
  assert.equal(exported.BENCH_INPUT_FEATURE, HEAD);
  assert.deepEqual(comparisons, []);
});

test('PR context uses the PR head and target branch instead of the synthetic merge commit', async () => {
  const { exported, comparisons } = await run({}, {
    sha: OTHER, payload: { pull_request: { head: { sha: HEAD, ref: 'feature' }, base: { ref: 'release' } } },
  });
  assert.equal(exported.BENCH_INPUT_FEATURE, HEAD);
  assert.equal(exported.BENCH_INPUT_FEATURE_NAME, 'feature');
  assert.equal(comparisons[0].base, 'release');
  assert.equal(comparisons[0].head, HEAD);
});

test('invalid refs fail instead of silently falling back to main', async () => {
  await assert.rejects(run({ BENCH_INPUT_FEATURE: 'missing' }), /Unknown ref/);
  await assert.rejects(run({ BENCH_INPUT_BASELINE: 'missing' }), /Unknown ref/);
});

test('merge-base lookup failures fail instead of substituting a different baseline', async () => {
  await assert.rejects(run({}, {}, true), /No common ancestor/);
});
