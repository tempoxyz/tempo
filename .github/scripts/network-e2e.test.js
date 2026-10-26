const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

// PyYAML is also used by the adjacent workflow regression tests.
const [docker, network] = JSON.parse(execFileSync('python3', ['-c',
  'import json,sys,yaml; print(json.dumps([yaml.safe_load(open(p)) for p in sys.argv[1:]]))',
  ...['docker', 'network-e2e'].map(name => path.join(__dirname, `../workflows/${name}.yml`)),
], { encoding: 'utf8' }));
const step = (job, id) => job.steps.find(s => s.id === id);
const decision = step(network.jobs.detect, 'decision');
const submit = step(network.jobs.dispatch, 'submit');
const report = network.jobs.dispatch.steps.at(-1);

// Evaluate the boolean-expression subset these guards use, including GHA's
// missing-property value and implicit success() unless a status function exists.
function evaluate(expression, context, cancelled = false, success = true) {
  const source = expression.replace(/^\$\{\{\s*|\s*\}\}$/g, '')
    .replace(/\b(?:github|needs|steps|inputs)(?:\.[\w-]+)+/g, key =>
      JSON.stringify(key.split('.').reduce((v, k) => v?.[k], context) ?? ''));
  return vm.runInNewContext(source, {
    cancelled: () => cancelled, always: () => true, success: () => success,
    contains: (values, value) => values.includes(value), fromJSON: JSON.parse,
  });
}
function shouldBuild(context, cancelled = false) {
  const condition = network.jobs.build.if;
  const success = context.needs.detect.result === 'success';
  return (/\b(?:always|cancelled|success|failure)\(/.test(condition) || success) &&
    evaluate(condition, context, cancelled, success);
}
function fixture(event, required, detect = 'success', build = 'success', images = 'true') {
  return { github: { event_name: event, repository: 'tempoxyz/tempo', event: {} },
    needs: { detect: { result: detect, outputs: { required: String(required), images_required: images } },
      build: { result: build, outputs: { tempo_image_tag: 'build-42-1' } } } };
}
async function finalStatus(context, submitted, owner = '42-2') {
  const calls = [], failures = [];
  await vm.runInNewContext(`(async () => {${report.with.script}\n})()`, {
    process: { env: { SHA: 'a'.repeat(40), GITHUB_RUN_ATTEMPT: '2',
      DETECT_RESULT: context.needs.detect.result, REQUIRED: context.needs.detect.outputs.required,
      SUBMIT_RESULT: submitted } },
    context: { payload: context.github.event, runId: 42, repo: { owner: 'tempoxyz', repo: 'tempo' },
      serverUrl: 'https://github.com' },
    core: { setFailed: message => failures.push(message) },
    github: { paginate: { iterator: async function* () {
      yield { data: [{ context: 'other' }] };
      yield { data: [{ context: 'Tempo Network E2E', description: `${owner}: Preparing dispatch` }] };
    } }, rest: { repos: { listCommitStatusesForRef() {},
      createCommitStatus: async status => calls.push(status) } } },
  });
  return { calls, failures };
}

test('one queue orchestrator; non-queue Docker entry points remain available', () => {
  // YAML 1.1 interprets the workflow key "on" as true.
  assert.ok(!('merge_group' in docker.true));
  assert.ok('merge_group' in network.true);
  assert.deepEqual(docker.true.push, { branches: ['main', 'rc/*'], tags: ['tempo/v*.*.*'] });
  for (const event of ['workflow_call', 'workflow_dispatch', 'schedule']) assert.ok(event in docker.true);
  assert.equal(network.jobs.build.uses, './.github/workflows/docker.yml');
  assert.equal(network.jobs.build['continue-on-error'], undefined);
  assert.equal(docker.jobs['build-and-push']['continue-on-error'], undefined);
  assert.deepEqual(network.jobs.dispatch.needs, ['detect', 'build']);
  assert.equal(network.jobs.dispatch.if, 'always()');
});

test('queue skips only confirmed image-irrelevant changes, never required network tests', () => {
  for (const required of [true, false]) for (const detect of ['success', 'failure', 'skipped'])
    for (const images of ['true', 'false', '', undefined]) {
      const context = fixture('merge_group', required, detect);
      context.needs.detect.outputs.images_required = images;
      assert.equal(shouldBuild(context), required || detect !== 'success' || images !== 'false',
        `${required}/${detect}/${images}`);
      assert.equal(shouldBuild(context, true), false);
    }
  for (const changes of ['["images"]', '["consensus","images"]', '["consensus"]', '[]', '', undefined]) {
    const context = { steps: { paths: { outputs: { changes } } } };
    assert.equal(evaluate(network.jobs.detect.outputs.images_required, context), !changes || JSON.parse(changes).includes('images'));
  }
});

test('image input boundaries preserve runtime assets, build recipes, and unknown inputs', () => {
  const paths = step(network.jobs.detect, 'paths');
  assert.equal(paths.with.base, '${{ steps.target.outputs.base }}');
  assert.equal(paths.with.head, '${{ steps.target.outputs.sha }}');
  const filters = JSON.parse(execFileSync('python3', ['-c',
    'import json,sys,yaml; print(json.dumps(yaml.safe_load(sys.stdin.read())))',
  ], { input: paths.with.filters, encoding: 'utf8' }));
  // Only simple *, ** patterns are used here; negatives always veto positives.
  const matches = (file, pattern) => new RegExp('^' + pattern.split('**')
    .map(part => part.split('*').map(s => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*'))
    .join('.*') + '$').test(file);
  const needsImages = files => files.some(file =>
    filters.images.some(p => !p.startsWith('!') && matches(file, p)) &&
    !filters.images.some(p => p.startsWith('!') && matches(file, p.slice(1))));
  const excluded = ['docs/guide.md', 'contrib/Dockerfile', 'localnet/index.ts', 'tips/tip-1234.md',
    'crates/node/tests/it/main.rs', 'crates/zones/node/tests/it/e2e.rs'];
  const included = ['scripts/build.sh', 'tips/verify/src/main.rs', '.dockerignore', 'Dockerfile',
    'docker-bake.hcl', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml',
    '.github/workflows/docker.yml', 'mainnet-network-identity.json', 'future-inputs/new.json',
    'crates/node/tests/assets/test-genesis.json', 'crates/node/tests/new-fixture.json',
    'crates/node/src/lib.rs', 'crates/consensus/src/lib.rs', 'crates/node/README.md',
    'bin/tempo/main.rs', 'xtask/src/main.rs'];
  for (const file of excluded) assert.equal(needsImages([file]), false, file);
  for (const file of included) {
    assert.equal(needsImages([file]), true, file);
    assert.equal(needsImages([...excluded, file]), true, `mixed: ${file}`);
  }
  assert.equal(needsImages(excluded), false);
});

test('queue dispatch requires a successful image; skips do not hide build failures', async () => {
  for (const required of [true, false]) for (const images of ['true', 'false', ''])
    for (const build of ['success', 'failure', 'cancelled', 'skipped']) {
      const context = fixture('merge_group', required, 'success', build, images);
      assert.equal(shouldBuild(context), required || images !== 'false');
      const dispatch = evaluate(submit.if, context);
      assert.equal(dispatch, required && build === 'success');
      const { calls, failures } = await finalStatus(context, dispatch ? 'success' : 'skipped');
      assert.equal(calls.length, dispatch ? 0 : 1); // Argo owns submitted tests.
      if (!dispatch) assert.equal(calls[0].state, required ? 'failure' : 'success');
      assert.equal(failures.length, required && !dispatch ? 1 : 0);
    }
  for (const required of [true, false]) {
    const context = fixture('merge_group', required, 'failure');
    assert.equal(evaluate(submit.if, context), false);
    assert.equal((await finalStatus(context, 'skipped')).calls[0].state, 'failure');
  }
});

test('PR draft/path gating and fork rejection still fail closed', () => {
  assert.deepEqual(network.true.pull_request_target.types,
    ['opened', 'reopened', 'synchronize', 'ready_for_review', 'converted_to_draft']);
  for (const draft of [true, false]) for (const consensus of [true, false])
    for (const reth of [true, false]) for (const sameRepo of [true, false]) {
      const context = fixture('pull_request_target', false);
      context.github.event.pull_request = { draft, head: { repo: { full_name: sameRepo ? 'tempoxyz/tempo' : 'fork/tempo' } } };
      context.steps = { paths: { outputs: { changes: JSON.stringify(consensus ? ['consensus'] : []) } },
        reth: { outputs: { changed: String(reth) } } };
      const required = evaluate(decision.env.REQUIRED, context);
      assert.equal(required, !draft && (consensus || reth));
      const env = { REQUIRED: String(required), SAME_REPO: String(evaluate(decision.env.SAME_REPO, context)),
        GITHUB_OUTPUT: '/dev/null' };
      const result = spawnSync('bash', ['-eu', '-c', decision.run], { env });
      assert.equal(result.status, required && !sameRepo ? 1 : 0);
      context.needs.detect = { result: result.status ? 'failure' : 'success', outputs: { required: String(required) } };
      for (const images of ['true', 'false', '']) {
        context.needs.detect.outputs.images_required = images;
        assert.equal(shouldBuild(context), required && sameRepo);
      }
    }
});

test('skips, dispatch failures, and stale attempts preserve status ownership', async () => {
  const draft = fixture('pull_request_target', false, 'success', 'skipped');
  draft.github.event.pull_request = { draft: true };
  assert.match((await finalStatus(draft, 'skipped')).calls[0].description, /Draft PR; waiting for review$/);
  const context = fixture('merge_group', true);
  assert.equal((await finalStatus(context, 'failure')).calls[0].state, 'failure');
  for (const submitted of ['failure', 'skipped', 'success']) {
    assert.equal((await finalStatus(context, submitted, '43-1')).calls.length, 0);
  }
});

test('all images share the captured build-attempt tag, including dispatch-only reruns', async () => {
  const build = docker.jobs['build-and-push'];
  const source = step(build, 'source');
  assert.equal(source.env.BUILD_TAG, 'build-${{ github.run_id }}-${{ github.run_attempt }}');
  const outputs = {};
  const summary = { addHeading() { return this; }, addTable() { return this; }, async write() {} };
  await vm.runInNewContext(`(async () => {${source.with.script}\n})()`, {
    process: { env: { BUILD_TAG: 'build-42-1', PR_NUMBER: '', BRANCH_NAME: 'queue' } },
    context: { payload: {}, sha: 'a'.repeat(40) },
    core: { summary, setOutput: (key, value) => { outputs[key] = value; } },
  });
  assert.equal(outputs.image_tag, 'build-42-1');
  assert.equal(build.outputs.tempo_image_tag, '${{ steps.source.outputs.image_tag }}');
  assert.equal(docker.true.workflow_call.outputs.tempo_image_tag.value,
    '${{ jobs.build-and-push.outputs.tempo_image_tag }}');
  assert.equal(submit.env.IMAGE_TAG, '${{ needs.build.outputs.tempo_image_tag }}');
  for (const image of ['tempo', 'tempo-devnet', 'tempo-localnet', 'tempo-sidecar', 'tempo-xtask']) {
    assert.ok(step(build, `meta-${image}`).with.tags.includes('type=raw,value=${{ steps.source.outputs.image_tag }},priority=50'));
  }
  // The network run may now be attempt 2, but its successful build is still attempt 1.
  const context = fixture('merge_group', true);
  context.github.run_attempt = 2;
  assert.equal(evaluate(submit.env.IMAGE_TAG, context), 'build-42-1');
  // Stop before credentials/curl: the real shell guard must reject missing/mutable tags.
  const guard = submit.run.split('\ntrap')[0];
  for (const tag of ['build-42-1', '', 'latest', 'sha-abcdef0']) {
    assert.equal(spawnSync('bash', ['-c', guard], { env: { IMAGE_TAG: tag } }).status, tag === 'build-42-1' ? 0 : 1);
  }
  assert.ok(submit.run.includes('--arg tag "$IMAGE_TAG"'));
  assert.ok(submit.run.includes('tag:$tag'));
});
