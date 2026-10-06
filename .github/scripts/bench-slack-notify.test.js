const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

async function notify(kind, changes, mode = 'on-win', responses = [{ ok: true, ts: '123.456' }]) {
  const calls = [];
  const info = [];
  const warnings = [];
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
      const response = responses[calls.length - 1];
      assert.ok(response, 'unexpected Slack request');
      return { json: async () => response };
    },
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'bench-slack-notify.js'), 'utf8'), sandbox);
  await sandbox.module.exports[kind].success({
    core: { info(message) { info.push(message); }, warning(message) { warnings.push(message); } },
    context: { repo: { owner: 'test', repo: 'tempo' }, serverUrl: 'https://github.com', runId: 1 },
  });
  return { calls, info, warnings };
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
      assert.equal((await notify(kind, changes)).calls.length, 0);
    });
  }

  test(`${kind} on-win posts an improvement, ignoring informational regressions`, async () => {
    const { calls, info, warnings } = await notify(kind, {
      tps: { sig: 'good' }, diagnostic: { sig: 'bad', informational: true },
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.channel, 'C_TEST');
    assert.equal(warnings.length, 0);
    assert.ok(info.some(message => message.includes('Slack notification accepted (channel C_TEST, timestamp 123.456)')));
  });

  test(`${kind} always mode retains mixed-result channel notifications and regression DMs`, async () => {
    const { calls: mixed } = await notify(kind, { tps: { sig: 'bad' }, block_time_mean: { sig: 'good' } }, 'always');
    assert.equal(mixed.length, 1);
    assert.equal(mixed[0].body.channel, 'C_TEST');
    const { calls: regression } = await notify(kind, { tps: { sig: 'bad' } }, 'always');
    assert.equal(regression.length, 1);
    assert.equal(regression[0].body.channel, 'U_TEST');
  });

  test(`${kind} on-win reports a rejected post without claiming delivery or sending a DM`, async () => {
    const { calls, info, warnings } = await notify(kind, { tps: { sig: 'good' } }, 'on-win', [
      { ok: false, error: 'channel_not_found' },
    ]);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.channel, 'C_TEST');
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /channel_not_found/);
    assert.ok(!info.some(message => message.includes('notification accepted')));
    assert.ok(!info.some(message => message.includes('No significant')));
  });

  test(`${kind} always mode falls back to a DM only when the channel post was rejected`, async () => {
    const { calls, info, warnings } = await notify(kind, { tps: { sig: 'good' } }, 'always', [
      { ok: false, error: 'channel_not_found' },
      { ok: true, ts: '789.012' },
    ]);
    assert.deepEqual(calls.map(call => call.body.channel), ['C_TEST', 'U_TEST']);
    assert.equal(warnings.length, 1);
    const acknowledgements = info.filter(message => message.includes('notification accepted'));
    assert.equal(acknowledgements.length, 1);
    assert.match(acknowledgements[0], /channel U_TEST, timestamp 789.012/);
  });
}
