const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

async function notify(kind, changes, mode = 'on-win') {
  const calls = [];
  const summary = kind === 'e2e'
    ? { config: {}, results: { baseline: {}, feature: {}, changes } }
    : { changes };
  const sandbox = {
    module: { exports: {} },
    process: { env: {
      SLACK_BENCH_BOT_TOKEN: 'test-token',
      SLACK_BENCH_CHANNEL: 'C_TEST',
      BENCH_ACTOR: 'test-actor',
      BENCH_WORK_DIR: '/test-results',
      BENCH_SLACK: mode,
    } },
    require: name => name === 'fs' ? {
      readFileSync: file => JSON.stringify(file.endsWith('summary.json')
        ? summary : { 'test-actor': 'U_TEST' }),
    } : require(name),
    fetch: async (url, request) => {
      calls.push({ url, body: JSON.parse(request.body) });
      return { json: async () => ({ ok: true }) };
    },
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'bench-slack-notify.js'), 'utf8'), sandbox);
  await sandbox.module.exports[kind].success({
    core: { info() {}, warning(message) { assert.fail(message); } },
    context: { repo: { owner: 'test', repo: 'tempo' }, serverUrl: 'https://github.com', runId: 1 },
  });
  return calls;
}

for (const kind of ['e2e', 'replay']) {
  for (const [label, changes] of [
    ['neutral', { tps: { sig: 'neutral' } }],
    ['regression', { tps: { sig: 'bad' } }],
    ['mixed results', { tps: { sig: 'bad' }, block_time_mean: { sig: 'good' } }],
    ['informational gain only', { diagnostic: { sig: 'good', informational: true } }],
    ['missing measurements', {}],
  ]) {
    test(`${kind} on-win sends neither a channel message nor a DM for ${label}`, async () => {
      assert.equal((await notify(kind, changes)).length, 0);
    });
  }

  test(`${kind} on-win posts an improvement, ignoring informational regressions`, async () => {
    const calls = await notify(kind, {
      tps: { sig: 'good' }, diagnostic: { sig: 'bad', informational: true },
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.channel, 'C_TEST');
  });

  test(`${kind} always mode retains mixed-result channel notifications and regression DMs`, async () => {
    const mixed = await notify(kind, { tps: { sig: 'bad' }, block_time_mean: { sig: 'good' } }, 'always');
    assert.equal(mixed.length, 1);
    assert.equal(mixed[0].body.channel, 'C_TEST');
    const regression = await notify(kind, { tps: { sig: 'bad' } }, 'always');
    assert.equal(regression.length, 1);
    assert.equal(regression[0].body.channel, 'U_TEST');
  });
}
