'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'tempo.nu'), 'utf8');
const start = source.indexOf('def dedup-args ');
const end = source.indexOf('\n}\n', start) + 3;
function merge(base, extra) {
  return JSON.parse(execFileSync('nu', ['--no-config-file', '-c',
    `${source.slice(start, end)}\ndedup-args ($env.BASE | from json) ($env.EXTRA | from json) | to json`],
    {encoding: 'utf8', env: {...process.env, BASE: JSON.stringify(base), EXTRA: JSON.stringify(extra)}}));
}
test('boolean overrides do not swallow the next follower isolation flag', () => {
  assert.deepEqual(merge(['--builder.disable-prewarming', '--engine.disable-execution-cache-sharing-with-builder',
    '--rpc-cache.max-blocks', '128'], ['--builder.disable-prewarming']),
  ['--engine.disable-execution-cache-sharing-with-builder', '--rpc-cache.max-blocks', '128', '--builder.disable-prewarming']);
});
test('valued, inline, repeated boolean, and empty overrides remain correct', () => {
  assert.deepEqual(merge(['--value', '128', '--boolean'], ['--value', '256']), ['--boolean', '--value', '256']);
  assert.deepEqual(merge(['--value=128', '--boolean'], ['--value=256']), ['--boolean', '--value=256']);
  assert.deepEqual(merge(['--a', '--b', '--c'], ['--a', '--b']), ['--c', '--a', '--b']);
  assert.deepEqual(merge(['--a'], []), ['--a']);
});
