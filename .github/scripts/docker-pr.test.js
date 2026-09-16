const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

// Execute the workflow's inline dispatcher without checking out or running PR code.
const yaml = fs.readFileSync(path.join(__dirname, '../workflows/docker-pr.yml'), 'utf8');
function scriptFor(name) {
  const step = yaml.split(`      - name: ${name}\n`)[1].split('\n      - name: ')[0].split('\n  acknowledge:')[0];
  return step.split('          script: |\n')[1].split('\n')
    .map(line => line.replace(/^ {12}/, '')).join('\n');
}
const detectScript = scriptFor('Detect Docker command');
const membershipScript = scriptFor('Check org membership');
const dispatchScript = scriptFor('Queue Docker build from comment');

test('dispatch uses the STS app token so build lifecycle reporters can run', () => {
  const step = yaml.split('      - name: Queue Docker build from comment\n')[1].split('\n  acknowledge:')[0];
  assert.ok(step.includes('github-token: ${{ steps.github-sts.outputs.token }}'));
  const policy = fs.readFileSync(path.join(__dirname, '../sts/docker-pr.sts.yaml'), 'utf8');
  assert.match(policy, /^  actions: write$/m);
  assert.match(policy, /^  members: read$/m);
  assert.match(policy, /^  pull_requests: read$/m);
  const dispatchJob = yaml.split('\n  dispatch:')[1].split('\n  acknowledge:')[0];
  assert.ok(!dispatchJob.includes('actions: write'));
});

for (const [workflow, prefix] of [
  ['docker.yml', 'docker-build'],
  ['docker-profiling.yml', 'docker-profiling-build'],
]) {
  test(`${workflow} preserves the supplied ref unless a PR number overrides it`, async () => {
    const build = fs.readFileSync(path.join(__dirname, '../workflows', workflow), 'utf8');
    const step = build.split('      - name: Resolve build source\n')[1].split('\n      - name: ')[0];
    assert.ok(step.includes('BRANCH_NAME: ${{ github.head_ref || github.ref_name }}'));
    const script = step.split('          script: |\n')[1].split('\n')
      .map(line => line.replace(/^ {12}/, '')).join('\n');
    for (const branch of ['main', 'feature/nested', 'v1.2.3', '123/merge']) {
      for (const number of ['', '123']) {
        const outputs = {};
        let lookups = 0;
        const summary = { addHeading() { return this; }, addTable() { return this; }, async write() {} };
        await vm.runInNewContext(`(async () => {${script}\n})()`, {
          process: { env: { PR_NUMBER: number, BRANCH_NAME: branch } },
          context: { sha: 'a'.repeat(40), repo: { owner: 'tempoxyz', repo: 'tempo' } },
          core: { setOutput: (key, value) => { outputs[key] = value; }, summary },
          github: { rest: { pulls: { get: async () => {
            lookups++;
            return { data: { state: 'open', head: {
              sha: 'b'.repeat(40), ref: 'pr/branch', repo: { full_name: 'tempoxyz/tempo' },
            } } };
          } } } },
        });
        assert.equal(outputs.branch, number ? 'pr/branch' : branch);
        assert.equal(outputs.sha, (number ? 'b' : 'a').repeat(40));
        assert.equal(lookups, number ? 1 : 0);
      }
    }
  });

  test(`${workflow} scopes cancellation to PR builds in its own namespace`, () => {
    const build = fs.readFileSync(path.join(__dirname, '../workflows', workflow), 'utf8');
    const concurrency = build.split('\nconcurrency:\n')[1].split('\n\n')[0];
    // Pin the grouping contract: repeated PR requests (nightly included) share a
    // group; other PRs, profiling, and individual non-PR runs remain independent.
    assert.equal(concurrency, [
      `  group: ${prefix}-` + "${{ inputs.pr_number && format('pr-{0}', inputs.pr_number) || format('run-{0}', github.run_id) }}",
      "  cancel-in-progress: ${{ github.event_name == 'workflow_dispatch' && inputs.pr_number != '' }}",
    ].join('\n'));
  });
}

function fixture(options = {}) {
  const command = options.command ?? '/docker';
  const calls = [];
  const links = [];
  const outputs = {};
  const summary = {
    addHeading() { return this; },
    addLink(text, url) { links.push(url); return this; },
    addRaw() { return this; },
    async write() {},
  };
  const repo = { owner: 'tempoxyz', repo: 'tempo' };
  const pr = {
    state: options.state || 'open',
    user: { login: 'pr-author' },
    head: { repo: options.deleted ? null : { full_name: options.repo || 'tempoxyz/tempo' } },
  };
  const record = (method, result, error) => async args => {
    calls.push({ method, args });
    if (error) throw error;
    return { data: result };
  };
  let recognized = false;
  const sandbox = {
    context: {
      repo, actor: 'requester',
      payload: { comment: { body: command, user: { login: 'comment-author' } },
        issue: { number: 123, pull_request: options.issue ? undefined : {} },
        repository: { default_branch: 'main' } },
    },
    process: { env: { GITHUB_RUN_ATTEMPT: options.attempt || '1' } },
    core: {
      info() {}, summary,
      setOutput(key, value) {
        outputs[key] = value;
        if (key === 'recognized') recognized = value;
      },
      setFailed(message) { throw new Error(message); },
    },
    github: { rest: {
      orgs: { checkMembershipForUser: async args => {
        calls.push({ method: 'membership', args });
        assert.equal(args.org, 'tempoxyz');
        const who = args.username === 'comment-author' ? 'commenter' : 'author';
        if (options[`${who}Error`]) throw options[`${who}Error`];
        return { status: options[`${who}Status`] ?? 204 };
      } },
      repos: { getCollaboratorPermissionLevel: record('permission',
        { permission: options.permission || 'write' }, options.permissionError) },
      pulls: { get: record('pull', pr, options.pullError) },
      actions: { createWorkflowDispatch: record('dispatch',
        { workflow_run_id: 456, html_url: 'https://github.com/tempoxyz/tempo/actions/runs/456' }, options.dispatchError) },
    } },
  };
  const execute = script => vm.runInNewContext(`(async () => {${script}\n})`, sandbox)();
  const run = async () => {
    // Model the job guard and default success() gating between workflow steps.
    if (options.issue || (options.attempt && options.attempt !== '1')) return;
    await execute(detectScript);
    if (!recognized) return;
    await execute(membershipScript);
    await execute(dispatchScript);
  };
  return { run, calls, links, outputs };
}

for (const [command, workflow, nightly = false] of [
  ['/docker', 'docker.yml'], ['/docker profiling', 'docker-profiling.yml'],
  ['/docker nightly', 'docker.yml', true],
  [' \n/docker\n ', 'docker.yml'],
]) {
  test(`${command.trim()} dispatches the trusted workflow`, async () => {
    const f = fixture({ command });
    await f.run();
    assert.deepEqual(f.calls.map(call => call.method), ['membership', 'pull', 'membership', 'permission', 'pull', 'dispatch']);
    assert.deepEqual(f.calls.filter(call => call.method === 'membership').map(call => call.args.username), ['comment-author', 'pr-author']);
    const dispatch = JSON.parse(JSON.stringify(f.calls.find(call => call.method === 'dispatch').args));
    assert.equal(dispatch.workflow_id, workflow);
    assert.equal(dispatch.ref, 'main');
    assert.deepEqual(dispatch.inputs, nightly ? { pr_number: '123', nightly: 'true' } : { pr_number: '123' });
    assert.equal(dispatch.return_run_details, true);
    assert.equal(f.calls.find(call => call.method === 'permission').args.username, 'comment-author');
    assert.deepEqual(f.links, ['https://github.com/tempoxyz/tempo/actions/runs/456']);
    assert.equal(f.outputs['run-id'], '456');
  });
}

for (const who of ['commenter', 'author']) {
  for (const status of [200, 403, 404]) {
    test(`${who} membership status ${status} blocks dispatch even with admin access`, async () => {
      const f = fixture({ permission: 'admin', [`${who}Status`]: status });
      await assert.rejects(f.run(), /not a member of tempoxyz/);
      assert.ok(!f.calls.some(call => call.method === 'permission' || call.method === 'dispatch'));
    });
  }
  test(`${who} membership lookup errors fail closed`, async () => {
    const f = fixture({ [`${who}Error`]: new Error('Membership API unavailable') });
    await assert.rejects(f.run(), /not a member of tempoxyz/);
    assert.ok(!f.calls.some(call => call.method === 'dispatch'));
  });
  test(`${who} membership status 302 matches the benchmark membership gate`, async () => {
    const f = fixture({ [`${who}Status`]: 302 });
    await f.run();
    assert.equal(f.calls.filter(call => call.method === 'dispatch').length, 1);
  });
}

for (const permission of ['read', 'triage', 'none']) {
  test(`${permission} access cannot queue a build request`, async () => {
    const f = fixture({ permission });
    await assert.rejects(f.run(), /write access/);
    assert.deepEqual(f.calls.map(call => call.method), ['membership', 'pull', 'membership', 'permission']);
  });
}

for (const permission of ['maintain', 'admin']) {
  test(`${permission} access can request a build`, async () => {
    const f = fixture({ permission });
    await f.run();
    assert.ok(f.calls.some(call => call.method === 'dispatch'));
  });
}

for (const options of [{ state: 'closed' }, { repo: 'contributor/tempo' }, { deleted: true }]) {
  test(`reject unsupported PR: ${JSON.stringify(options)}`, async () => {
    const f = fixture(options);
    await assert.rejects(f.run(), /open PR with a branch in this repository/);
    assert.ok(!f.calls.some(call => call.method === 'dispatch'));
  });
}

for (const options of [
  { issue: true }, { attempt: '2' }, { command: 'unrelated' }, { command: '__proto__' },
  { command: '> /docker' }, { command: '/docker-extra' },
  { command: '/docker profiling nightly' },
  { command: '/docker\nand some extra text' }, { command: '' },
]) {
  test(`ignore inactive request: ${JSON.stringify(options)}`, async () => {
    const f = fixture(options);
    await f.run();
    assert.equal(f.calls.length, 0);
  });
}

for (const stage of ['permission', 'pull', 'dispatch']) {
  test(`${stage} API failure does not retry the dispatch`, async () => {
    const f = fixture({ [`${stage}Error`]: new Error('API unavailable') });
    await assert.rejects(f.run(), /API unavailable/);
    assert.equal(f.calls.filter(call => call.method === 'dispatch').length, stage === 'dispatch' ? 1 : 0);
    assert.equal(f.outputs['run-id'], undefined);
  });
}
