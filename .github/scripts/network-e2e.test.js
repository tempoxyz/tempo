const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const [docker, network, zones] = JSON.parse(execFileSync('python3', ['-c',
  'import json,sys,yaml; print(json.dumps([yaml.safe_load(open(p)) for p in sys.argv[1:]]))',
  ...['docker', 'network-e2e', 'zones-docker'].map(name => path.join(__dirname, `../workflows/${name}.yml`)),
], { encoding: 'utf8' }));
const step = (job, id) => job.steps.find(s => s.id === id);
const roots = ['resolve-production-build-inputs', 'eif-toolchain'];
const submit = step(network.jobs.dispatch, 'submit');

// The guards use this boolean-expression subset; missing GHA properties are ''.
function evaluate(expression, context, cancelled = false) {
  const source = expression.replace(/^\$\{\{\s*|\s*\}\}$/g, '')
    .replace(/\b(?:github|needs|steps|inputs|env)(?:\.[\w-]+)+/g, key =>
      JSON.stringify(key.split('.').reduce((v, k) => v?.[k], context) ?? ''));
  return vm.runInNewContext(source, {
    cancelled: () => cancelled, contains: (values, value) => values.includes(value), fromJSON: JSON.parse,
    format: (template, ...values) => template.replace(/\{(\d+)\}/g, (_, i) => values[i]),
  });
}
function shouldRun(job, context, cancelled, success) {
  // A failed ancestor implicitly skips a job unless it has a status function.
  return (/\b(?:always|cancelled|success|failure)\(/.test(job.if) || success) &&
    evaluate(job.if, context, cancelled);
}

for (const [name, workflow, detector, output, jobs] of [
  ['Network', network, 'detect', 'images_required', ['build']],
  ['Zones', zones, 'detect-changes', 'required', roots],
]) {
  test(`${name}: skip only confirmed irrelevant queue changes, unless cancelled`, () => {
    const context = { github: { event_name: 'merge_group', repository: 'tempoxyz/tempo' }, inputs: {}, needs: {} };
    for (const changes of ['["images"]', '[]', '', undefined]) {
      context.steps = { paths: { outputs: { changes } } };
      assert.equal(evaluate(workflow.jobs[detector].outputs[output], context), changes !== '[]');
    }
    for (const [result, images, expected] of [
      ['success', 'true', true], ['success', 'false', false],
      ['success', '', true], ['success', undefined, true],
      ['failure', 'false', true], ['skipped', 'false', true],
    ]) {
      context.needs[detector] = { result, outputs: { required: 'false', [output]: images } };
      for (const id of jobs) {
        assert.equal(shouldRun(workflow.jobs[id], context, false, result === 'success'), expected, `${id}/${result}/${images}`);
        assert.equal(shouldRun(workflow.jobs[id], context, true, result === 'success'), false);
        context.needs[id] = { result: expected ? 'success' : 'skipped' };
      }
      if (workflow === zones) {
        assert.equal(shouldRun(zones.jobs['build-and-push'], context, false, result === 'success' && expected), expected);
      }
    }
  });
}

test('Network owns queue builds; required tests override image exclusions but need a successful build', () => {
  // PyYAML reads the workflow key "on" as true.
  assert.ok(!('merge_group' in docker.true) && 'merge_group' in network.true);
  assert.equal(network.jobs.build.uses, './.github/workflows/docker.yml');
  for (const required of ['true', 'false']) for (const result of ['success', 'failure', 'skipped']) {
    const context = { github: { event_name: 'merge_group' }, needs: {
      detect: { result: 'success', outputs: { required, images_required: 'false' } }, build: { result },
    } };
    assert.equal(shouldRun(network.jobs.build, context, false, true), required === 'true');
    assert.equal(evaluate(submit.if, context), required === 'true' && result === 'success');
  }
});

test('queue fallback cannot bypass PR draft/fork restrictions', () => {
  const decision = step(network.jobs.detect, 'decision');
  for (const draft of [true, false]) for (const sameRepo of [true, false]) {
    const context = { github: { event_name: 'pull_request_target', repository: 'tempoxyz/tempo', event: {
      pull_request: { draft, head: { repo: { full_name: sameRepo ? 'tempoxyz/tempo' : 'fork/tempo' } } },
    } }, steps: { paths: { outputs: { changes: '["consensus"]' } } }, inputs: {}, needs: {} };
    const required = evaluate(decision.env.REQUIRED, context);
    assert.equal(required, !draft);
    const result = spawnSync('bash', ['-eu', '-c', decision.run], { env: {
      REQUIRED: String(required), SAME_REPO: String(evaluate(decision.env.SAME_REPO, context)), GITHUB_OUTPUT: '/dev/null',
    } });
    assert.equal(result.status, !draft && !sameRepo ? 1 : 0);
    context.needs.detect = { result: result.status ? 'failure' : 'success', outputs: { required: String(required), images_required: 'true' } };
    assert.equal(shouldRun(network.jobs.build, context, false, !result.status), !draft && sameRepo);
    context.github.event_name = 'pull_request';
    context.github.repository = sameRepo ? 'tempoxyz/tempo' : 'fork/tempo';
    context.needs['detect-changes'] = { result: 'success', outputs: { required: 'true' } };
    for (const id of roots) assert.equal(shouldRun(zones.jobs[id], context, false, true), !draft && sameRepo);
  }
});

test('attempt tags are Network-only and dispatch reruns reuse the successful build tag', () => {
  const build = docker.jobs['build-and-push'];
  const source = step(build, 'source');
  for (const event of ['merge_group', 'pull_request_target', 'push', 'schedule', 'workflow_dispatch', 'workflow_call']) {
    const context = { github: { event_name: event, run_id: 42, run_attempt: 1 } };
    assert.equal(evaluate(source.env.BUILD_TAG, context),
      ['merge_group', 'pull_request_target'].includes(event) ? 'build-42-1' : '');
  }
  for (const tag of ['build-42-1', '']) {
    const context = { steps: { source: { outputs: { image_tag: tag } }, 'meta-tempo': { outputs: { version: 'sha-aaaaaaa' } } } };
    assert.equal(evaluate(build.outputs.tempo_image_tag, context), tag || 'sha-aaaaaaa');
    for (const name of ['tempo', 'tempo-devnet', 'tempo-localnet', 'tempo-sidecar', 'tempo-xtask']) {
      const line = step(build, `meta-${name}`).with.tags.split('\n').find(line => line.includes('value=${{ steps.source.outputs.image_tag }}'));
      // In particular, /docker reports must not receive an extra or empty tag.
      assert.ok(line?.includes('enable='));
      assert.equal(evaluate(line.split('enable=')[1], context), tag !== '');
    }
  }
  assert.equal(docker.true.workflow_call.outputs.tempo_image_tag.value, '${{ jobs.build-and-push.outputs.tempo_image_tag }}');
  assert.equal(evaluate(submit.env.IMAGE_TAG, { github: { run_id: 42, run_attempt: 2 },
    needs: { build: { outputs: { tempo_image_tag: 'build-42-1' } } } }), 'build-42-1');
  // Execute only the guard, before credentials and curl.
  for (const tag of ['build-42-1', '', 'latest', 'sha-abcdef0']) {
    assert.equal(spawnSync('bash', ['-c', submit.run.split('\ntrap')[0]], { env: { IMAGE_TAG: tag } }).status,
      tag === 'build-42-1' ? 0 : 1);
  }
});
