const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const { resolve, validateImages, render, report } = require('./docker-pr-status');

const sha = 'a'.repeat(40);
const digest = `sha256:${'b'.repeat(64)}`;
const context = {
  repo: { owner: 'tempoxyz', repo: 'tempo' },
  payload: { repository: { default_branch: 'main' }, workflow_run: { id: 456 } },
};
const status = { id: 456, attempt: 1, number: 123, mode: '', status: 'completed', conclusion: 'success' };
function images(mode = '') {
  const names = mode === 'profiling' ? ['tempo'] : ['tempo', 'tempo-localnet', 'tempo-sidecar', 'tempo-xtask'];
  const registries = mode === 'profiling' ? ['ghcr.io'] : ['ghcr.io', 'docker.io'];
  const prefix = mode === 'profiling' ? 'profiling-' : '';
  const tags = [`${prefix}pr-123`, `${prefix}sha-${sha.slice(0, 7)}`, ...(mode === 'nightly' ? ['nightly'] : [])];
  return { sha, images: names.map(name => ({ name, digest,
    tags: registries.flatMap(registry => tags.map(tag => `${registry}/tempoxyz/${name}:${tag}`)),
  })) };
}
function fixture(overrides = {}, comments = []) {
  const calls = [];
  const run = {
    id: 456, run_attempt: 1, event: 'workflow_dispatch', head_branch: 'main',
    head_repository: { full_name: 'tempoxyz/tempo' }, path: '.github/workflows/docker.yml',
    display_title: 'Docker PR #123', status: 'completed', conclusion: 'success', ...overrides,
  };
  const artifacts = [
    { id: 8, name: 'docker-pr-images-1', size_in_bytes: 1000 },
    { id: 9, name: 'docker-pr-images-2', size_in_bytes: 1000 },
  ];
  const github = {
    rest: {
      actions: { getWorkflowRun: async () => ({ data: run }), listWorkflowRunArtifacts: 'artifacts' },
      pulls: { get: async args => { calls.push(['pull', args]); return { data: {} }; } },
      issues: { listComments: 'comments',
        createComment: async args => { calls.push(['create', args]); },
        updateComment: async args => { calls.push(['update', args]); },
      },
    },
    paginate: async (method, args) => {
      calls.push([method, args]);
      return method === 'artifacts' ? artifacts : comments;
    },
  };
  return { github, calls, artifacts };
}

for (const mode of ['', 'nightly', 'profiling']) {
  test(`resolve and render ${mode || 'normal'} results with exact published references`, async () => {
    const f = fixture({ display_title: `Docker PR #123${mode ? ` ${mode}` : ''}`,
      path: `.github/workflows/docker${mode === 'profiling' ? '-profiling' : ''}.yml` });
    const actual = await resolve(f.github, context);
    assert.equal(actual.mode, mode);
    assert.equal(actual.number, 123);
    assert.equal(actual.artifactId, 8);
    const data = images(mode);
    assert.equal(validateImages(data, actual), data);
    const body = render(actual, data);
    assert.match(body, /Status: \*\*success\*\*/);
    assert.ok(body.includes(`ghcr.io/tempoxyz/tempo@${digest}`));
    assert.ok(body.includes(`/commit/${sha}`));
    for (const image of data.images) for (const tag of image.tags) assert.ok(body.includes(tag));
    assert.ok(body.includes('https://github.com/orgs/tempoxyz/packages/container/package/tempo'));
    assert.equal(body.includes('https://hub.docker.com'), mode !== 'profiling');
  });
}

for (const overrides of [
  { event: 'push' }, { head_branch: 'untrusted' },
  { head_repository: { full_name: 'someone/tempo' } }, { head_repository: null },
  { path: '.github/workflows/other.yml' }, { display_title: 'Docker PR #123 profiling' },
  { display_title: 'Docker PR #0' }, { display_title: 'Docker PR #9007199254740992' },
  { display_title: 'Docker PR #123 injected' }, { display_title: 'Regular build' },
  { display_title: 'Docker PR #123 (request 0)' },
  { display_title: 'Docker PR #123 (request 9007199254740992)' },
]) {
  test(`ignore unrelated or untrusted run: ${JSON.stringify(overrides)}`, async () => {
    const f = fixture(overrides);
    assert.equal(await resolve(f.github, context), null);
    assert.equal(f.calls.length, 0);
  });
}

test('ignore runs in another repository', async () => {
  const f = fixture();
  assert.equal(await resolve(f.github, { ...context, repo: { owner: 'fork', repo: 'tempo' } }), null);
});

test('missing PR fails before reading artifacts or commenting', async () => {
  const f = fixture();
  f.github.rest.pulls.get = async () => { throw new Error('Not found'); };
  await assert.rejects(resolve(f.github, context), /Not found/);
  assert.equal(f.calls.length, 0);
});

test('fresh API state wins over an old event and selects only this attempt artifact', async () => {
  const f = fixture({ run_attempt: 2 });
  const actual = await resolve(f.github, { ...context,
    payload: { ...context.payload, workflow_run: { id: 456, status: 'in_progress', run_attempt: 1 } } });
  assert.equal(actual.status, 'completed');
  assert.equal(actual.artifactId, 9);
});

test('ignore expired and oversized artifacts', async () => {
  for (const change of [{ expired: true }, { size_in_bytes: 100_001 }]) {
    const f = fixture();
    Object.assign(f.artifacts[0], change);
    assert.equal((await resolve(f.github, context)).artifactId, undefined);
  }
});

test('artifact lookup failure still permits reporting the final run status', async () => {
  const f = fixture({ conclusion: 'cancelled' });
  const paginate = f.github.paginate;
  f.github.paginate = async (method, args) => {
    if (method === 'artifacts') throw new Error('API unavailable');
    return paginate(method, args);
  };
  const actual = await resolve(f.github, context);
  const warnings = [];
  await report(f.github, context, { warning: text => warnings.push(text) }, actual);
  assert.equal(warnings.length, 1);
  assert.match(f.calls.find(([name]) => name === 'create')[1].body, /\*\*cancelled\*\*/);
});

for (const state of ['queued', 'in_progress', 'waiting']) {
  test(`${state} reports progress without guessing images`, async () => {
    const f = fixture({ status: state, conclusion: null });
    const actual = await resolve(f.github, context);
    assert.equal(actual.artifactId, undefined);
    assert.ok(!f.calls.some(([name]) => name === 'artifacts'));
    const body = render(actual);
    assert.ok(body.includes('Docker request accepted'));
    assert.ok(body.includes('https://github.com/tempoxyz/tempo/actions/runs/456'));
    assert.ok(body.includes(state === 'in_progress' ? '**running**' : '**queued**'));
    assert.ok(!body.includes('ghcr.io'));
  });
}

for (const conclusion of ['success', 'failure', 'cancelled', 'timed_out', 'skipped']) {
  test(`${conclusion} without artifact never claims images were published`, () => {
    const body = render({ ...status, conclusion });
    assert.ok(body.includes(`**${conclusion}**`));
    assert.match(body, /Published image details are unavailable/);
    assert.ok(!body.includes('ghcr.io'));
  });
}

test('failed post-push signing still reports the push and overall failure separately', () => {
  const body = render({ ...status, conclusion: 'failure' }, images());
  assert.match(body, /\*\*failure\*\*/);
  assert.match(body, /successful push step/);
});

for (const [name, change] of [
  ['source SHA', x => { x.sha = 'malformed'; }],
  ['image name', x => { x.images[0].name = 'other'; }],
  ['image count', x => { x.images.pop(); }],
  ['unexpected tag', x => { x.images[0].tags[0] = 'ghcr.io/tempoxyz/tempo:latest'; }],
  ['different PR', x => { x.images[0].tags[0] = 'ghcr.io/tempoxyz/tempo:pr-999'; }],
  ['Markdown', x => { x.images[0].tags[0] = '[click](https://example.com)'; }],
  ['duplicate tag', x => { x.images[0].tags[0] = x.images[0].tags[1]; }],
  ['digest', x => { x.images[0].digest = '`bad`'; }],
]) {
  test(`reject untrusted artifact ${name}`, () => {
    const data = images(); change(data);
    assert.throws(() => validateImages(data, status));
  });
}

test('create one comment then update that comment, not a user-supplied marker', async () => {
  const spoof = { id: 1, user: { login: 'human', type: 'User' }, body: '<!-- tempo-docker-run:456 -->\nspoof' };
  const f = fixture({}, [spoof]);
  await report(f.github, context, { warning() {} }, status);
  const created = f.calls.find(([name]) => name === 'create')[1];
  assert.equal(created.issue_number, 123);
  const botComment = { id: 77, user: { login: 'github-actions[bot]', type: 'Bot' }, body: created.body };
  const next = fixture({}, [spoof, botComment]);
  await report(next.github, context, { warning() {} }, { ...status, conclusion: 'cancelled' });
  assert.equal(next.calls.find(([name]) => name === 'update')[1].comment_id, 77);
  assert.ok(!next.calls.some(([name]) => name === 'create'));
});

test('duplicate lifecycle event does not mutate an unchanged comment', async () => {
  const f = fixture({}, [{ id: 77, user: { login: 'github-actions[bot]', type: 'Bot' }, body: render(status) }]);
  await report(f.github, context, { warning() {} }, status);
  assert.deepEqual(f.calls.map(([name]) => name), ['comments']);
});

for (const mode of ['', 'nightly', 'profiling']) {
  test(`${mode || 'normal'} requested event adopts the receipt before acknowledgement`, async () => {
    const receipt = { id: 77, user: { login: 'github-actions[bot]', type: 'Bot' },
      body: '<!-- tempo-docker-request:321 -->\nReceived command.' };
    const f = fixture({ status: 'queued', conclusion: null,
      display_title: `Docker PR #123${mode ? ` ${mode}` : ''} (request 321)`,
      path: `.github/workflows/docker${mode === 'profiling' ? '-profiling' : ''}.yml`,
    }, [receipt]);
    const actual = await resolve(f.github, context);
    assert.equal(actual.requestId, 321);
    assert.equal(actual.mode, mode);
    await report(f.github, context, { warning() {} }, actual);
    const updated = f.calls.find(([name]) => name === 'update')[1];
    assert.equal(updated.comment_id, 77);
    assert.ok(updated.body.startsWith('<!-- tempo-docker-run:456 -->\n<!-- tempo-docker-request:321 -->\n'));
    assert.ok(!f.calls.some(([name]) => name === 'create'));
    receipt.body = updated.body;
    // The direct acknowledgement uses the same run marker and current state.
    await report(f.github, context, { warning() {} }, { ...actual, status: 'in_progress' });
    assert.equal(f.calls.filter(([name]) => name === 'update').length, 2);
    assert.ok(!f.calls.some(([name]) => name === 'create'));
    await report(f.github, context, { warning() {} }, { ...actual, status: 'completed', conclusion: 'success' });
    assert.equal(f.calls.filter(([name]) => name === 'update').at(-1)[1].comment_id, 77);
  });
}

test('missing receipt falls back to one run comment which later events reuse', async () => {
  const actual = { ...status, requestId: 321 };
  const f = fixture();
  await report(f.github, context, { warning() {} }, actual);
  const created = f.calls.find(([name]) => name === 'create')[1];
  const next = fixture({}, [{ id: 77, user: { login: 'github-actions[bot]', type: 'Bot' }, body: created.body }]);
  await report(next.github, context, { warning() {} }, { ...actual, conclusion: 'cancelled' });
  assert.equal(next.calls.find(([name]) => name === 'update')[1].comment_id, 77);
  assert.ok(!next.calls.some(([name]) => name === 'create'));
});

test('receipt adoption rejects human markers and comments already linked to another run', async () => {
  for (const receipt of [
    { id: 77, user: { login: 'human', type: 'User' }, body: '<!-- tempo-docker-request:321 -->\nhello' },
    { id: 77, user: { login: 'github-actions[bot]', type: 'Bot' }, body: '<!-- tempo-docker-request:321 -->\n<!-- tempo-docker-run:999 -->\nhello' },
  ]) {
    const f = fixture({}, [receipt]);
    await report(f.github, context, { warning() {} }, { ...status, requestId: 321 });
    assert.ok(!f.calls.some(([name]) => name === 'update'));
    assert.ok(f.calls.some(([name]) => name === 'create'));
  }
});

test('a newer build uses a different comment rather than overwriting an older run', async () => {
  const f = fixture({}, [{ id: 77, user: { login: 'github-actions[bot]', type: 'Bot' }, body: render(status) }]);
  await report(f.github, context, { warning() {} }, { ...status, id: 789 });
  assert.ok(f.calls.some(([name]) => name === 'create'));
  assert.ok(!f.calls.some(([name]) => name === 'update'));
});

for (const problem of ['', 'invalid JSON', 'wrong tags', 'symlink', 'oversized']) {
  test(`artifact reader handles ${problem || 'valid JSON'} without executing it`, async t => {
    const previous = { downloaded: process.env.ARTIFACT_DOWNLOADED, temp: process.env.RUNNER_TEMP };
    process.env.ARTIFACT_DOWNLOADED = 'true';
    process.env.RUNNER_TEMP = '/tmp/report-fixture';
    t.after(() => {
      for (const [key, value] of [['ARTIFACT_DOWNLOADED', previous.downloaded], ['RUNNER_TEMP', previous.temp]]) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
      }
    });
    const data = images();
    if (problem === 'wrong tags') data.images[0].tags[0] = 'bad';
    t.mock.method(fs, 'lstatSync', filename => {
      assert.equal(filename, '/tmp/report-fixture/docker-pr-report/docker-pr-images.json');
      return { isFile: () => problem !== 'symlink', size: problem === 'oversized' ? 64_001 : 1000 };
    });
    t.mock.method(fs, 'readFileSync', () => problem === 'invalid JSON' ? '{' : JSON.stringify(data));
    const f = fixture();
    const warnings = [];
    await report(f.github, context, { warning: text => warnings.push(text) }, status);
    const body = f.calls.find(([name]) => name === 'create')[1].body;
    assert.equal(body.includes(`ghcr.io/tempoxyz/tempo@${digest}`), !problem);
    assert.equal(warnings.length, problem ? 1 : 0);
  });
}

test('status workflow handles acknowledgements and lifecycle events under the same lock', () => {
  const workflow = fs.readFileSync(path.join(__dirname, '../workflows/docker-pr-status.yml'), 'utf8');
  assert.match(workflow, /types: \[requested, in_progress, completed\]/);
  assert.ok(workflow.includes('group: docker-pr-status-${{ inputs.run_id || github.event.workflow_run.id }}'));
  assert.ok(workflow.includes('workflow_call:'));
  const dispatcher = fs.readFileSync(path.join(__dirname, '../workflows/docker-pr.yml'), 'utf8');
  assert.ok(dispatcher.includes('uses: ./.github/workflows/docker-pr-status.yml'));
  assert.ok(dispatcher.includes('run_id: ${{ needs.dispatch.outputs.run-id }}'));
  assert.match(workflow, /cancel-in-progress: false/);
  assert.ok(workflow.includes('ref: ${{ github.event.repository.default_branch }}'));
  assert.ok(workflow.includes('path: ${{ runner.temp }}/docker-pr-report'));
  assert.match(workflow, /pull-requests: write/);
  for (const name of ['docker.yml', 'docker-profiling.yml']) {
    const build = fs.readFileSync(path.join(__dirname, '../workflows', name), 'utf8');
    assert.ok(!build.includes('pull-requests: write'));
    assert.ok(!build.includes('issues: write'));
    assert.ok(build.includes('name: docker-pr-images-${{ github.run_attempt }}'));
  }
});

test('direct acknowledgement resolves the dispatched run and lifecycle events update its comment', async () => {
  const f = fixture({ status: 'in_progress', conclusion: null });
  const directContext = { ...context, payload: { repository: { default_branch: 'main' } } };
  const actual = await resolve(f.github, directContext, 456);
  await report(f.github, directContext, { warning() {} }, actual);
  const created = f.calls.find(([name]) => name === 'create')[1];
  assert.match(created.body, /Docker request accepted/);
  assert.match(created.body, /\*\*running\*\*/);
  const next = fixture({}, [{ id: 77, user: { login: 'github-actions[bot]', type: 'Bot' }, body: created.body }]);
  await report(next.github, context, { warning() {} }, await resolve(next.github, context));
  assert.equal(next.calls.find(([name]) => name === 'update')[1].comment_id, 77);
  assert.ok(!next.calls.some(([name]) => name === 'create'));
});

test('direct acknowledgement rejects invalid IDs and retains run provenance checks', async () => {
  for (const id of [undefined, 0, -1, NaN, 1.5]) {
    await assert.rejects(resolve(fixture().github, { ...context, payload: {} }, id), /Invalid build run ID/);
  }
  for (const overrides of [{ head_branch: 'feature' }, { path: '.github/workflows/other.yml' }, { event: 'push' }]) {
    const f = fixture(overrides);
    assert.equal(await resolve(f.github, context, 456), null);
    assert.equal(f.calls.length, 0);
  }
});

for (const mode of ['', 'nightly', 'profiling']) {
  test(`actual ${mode || 'normal'} collector script records build output as JSON`, async () => {
    const file = mode === 'profiling' ? 'docker-profiling.yml' : 'docker.yml';
    const yaml = fs.readFileSync(path.join(__dirname, '../workflows', file), 'utf8');
    const step = yaml.split('      - name: Record published PR images\n')[1].split('\n      - name: ')[0];
    assert.match(step, /if: inputs.pr_number != ''/);
    assert.ok(!step.includes('always()'));
    const script = step.split('          script: |\n')[1].split('\n').map(line => line.replace(/^ {12}/, '')).join('\n');
    const expected = images(mode);
    const env = { SOURCE_SHA: sha, RUNNER_TEMP: '/tmp/report-fixture', BUILD_METADATA: JSON.stringify(
      Object.fromEntries(expected.images.map(image => [image.name, { 'containerimage.digest': image.digest }]))),
    };
    for (const image of expected.images) env[`${image.name.toUpperCase().replaceAll('-', '_')}_TAGS`] = image.tags.join('\n');
    let written;
    vm.runInNewContext(script, { process: { env }, require: name => name === 'node:fs' ? {
      writeFileSync: (filename, data) => { assert.equal(filename, '/tmp/report-fixture/docker-pr-images.json'); written = JSON.parse(data); },
    } : require(name) });
    assert.deepEqual(written, expected);
  });
}
