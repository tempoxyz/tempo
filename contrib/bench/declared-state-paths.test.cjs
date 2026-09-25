'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const {resolveConfig} = require('./state-access-config.cjs');
const {ROUTER, SELECTORS, word, declaredRange, checkAccessList, inspectOpcodes, checkState} = require('./declared-state-path-validation.cjs');
const config = path.join(__dirname, 'configs/state-access-declared.json');
const calldata = (writing, start, count) => SELECTORS[writing ? 'declared_write' : 'declared_read'] + word(start).slice(2) + word(count).slice(2);
const range = declaredRange(calldata(false, 4093, 3), 'declared_read', 1, 3);
const list = [{address: ROUTER, storageKeys: range.keys}];
const HIGH = 1n << 255n;

test('declared suite contains only reads and writes, with native per-account limits', () => {
  const c = resolveConfig(config, [], {});
  assert.deepEqual(c.cases.map(x => x.scenario), ['declared_read', 'declared_write']);
  assert.equal(c.cases[0].operations_per_transaction, 128);
  assert.equal(resolveConfig(config, ['writes'], {}, 256).cases[0].operations_per_transaction, 256);
  for (const count of [0, 257, -1, 1.5]) assert.throws(() => resolveConfig(config, ['sload'], {}, count));
  assert.throws(() => resolveConfig(config, ['bytecode'], {}));
  assert.throws(() => resolveConfig(config, [], {}, 128));
});

test('calldata must stay in the full populated domain and match the recorded count', () => {
  assert.equal(range.start, 4093n);
  assert.equal(declaredRange(calldata(false, 0, 1), 'declared_read', 1, 1).start, 0n);
  for (const [start, count] of [[4094, 3], [0, 0], [0, 257]])
    assert.throws(() => declaredRange(calldata(false, start, count), 'declared_read', 1));
  assert.throws(() => declaredRange(calldata(true, 0, 3), 'declared_read', 1));
  assert.throws(() => declaredRange(calldata(false, 0, 3), 'declared_read', 1, 128));
});

test('signed list must cover exactly the called slots without duplicates or extra accounts', () => {
  checkAccessList(list, range);
  checkAccessList([{address: ROUTER, storageKeys: [...range.keys].reverse()}], range);
  for (const bad of [undefined, [], [...list, ...list], [{address: ROUTER, storageKeys: range.keys.slice(1)}],
    [{address: ROUTER, storageKeys: [range.keys[0], range.keys[0], range.keys[2]]}],
    [{address: ROUTER, storageKeys: [word(4092), ...range.keys.slice(1)]}]])
    assert.throws(() => checkAccessList(bad, range));
});

function trace(writing) {
  return {failed: false, structLogs: range.keys.flatMap(key => [
    {op: 'SLOAD', gasCost: 100, stack: [key]},
    ...(writing ? [{op: 'SSTORE', gasCost: 2900, stack: [word(1), key]}] : [])])};
}

test('opcode audit rejects cold, repeated, missing or undeclared storage accesses', () => {
  assert.equal(inspectOpcodes(trace(false), range, false).writes, 0);
  assert.equal(inspectOpcodes(trace(true), range, true).writes, 3);
  const cold = trace(false); cold.structLogs[0].gasCost = 2100;
  const extra = trace(false); extra.structLogs.push({op: 'SLOAD', gasCost: 100, stack: [word(9)]});
  const repeated = trace(false); repeated.structLogs[1] = repeated.structLogs[0];
  for (const bad of [cold, extra, repeated, {...trace(false), failed: true}])
    assert.throws(() => inspectOpcodes(bad, range, false));
  assert.throws(() => inspectOpcodes(trace(true), range, false));
  assert.throws(() => inspectOpcodes(trace(false), range, true));
});

test('write audit checks real nonzero changes, repeated toggles and returned value', () => {
  for (const toggled of [false, true]) {
    const before = Object.fromEntries(range.keys.map(k => [k, word((BigInt(k) + 1n) ^ (toggled ? HIGH : 0n))]));
    const after = Object.fromEntries(range.keys.map(k => [k, word(BigInt(before[k]) ^ HIGH)]));
    const actual = {[ROUTER]: {storage: before}};
    const diff = {pre: actual, post: {[ROUTER]: {storage: after}}};
    const result = range.keys.reduce((v, k) => v ^ BigInt(after[k]), 0n);
    assert.equal(checkState(actual, diff, word(result), range, true), 3);
    assert.throws(() => checkState(actual, diff, word(result ^ 1n), range, true));
    assert.throws(() => checkState(actual, {pre: actual, post: actual}, word(result), range, true));
    const deleted = structuredClone(diff); deleted.post[ROUTER].storage[range.keys[0]] = word(0);
    assert.throws(() => checkState(actual, deleted, word(result), range, true));
  }
});

test('read audit checks populated values, output and absence of persistent changes', () => {
  const storage = Object.fromEntries(range.keys.map(k => [k, word(BigInt(k) + 1n)]));
  const actual = {[ROUTER]: {storage}};
  const result = range.keys.reduce((v, k) => v ^ BigInt(storage[k]), 0n);
  assert.equal(checkState(actual, {pre: {}, post: {}}, word(result), range, false), 0);
  assert.throws(() => checkState(actual, {pre: actual, post: actual}, word(result), range, false));
  const empty = structuredClone(actual); empty[ROUTER].storage[range.keys[0]] = word(0);
  assert.throws(() => checkState(empty, {pre: {}, post: {}}, word(result), range, false));
});

const {slotsBetween, slotRate} = require('./analyze-declared-state-paths.cjs');
test('durable slot accounting counts inclusions and rejects gaps independently of gas pricing', () => {
  const blocks = [{number: 11, tx_count: 2}, {number: 12, tx_count: 0}, {number: 13, tx_count: 3}];
  assert.equal(slotsBetween(blocks, 10, 13, 128), 640);
  assert.equal(slotsBetween(blocks, 11, 12, 128), 0);
  assert.throws(() => slotsBetween(blocks.filter(b => b.number !== 12), 10, 13, 128));
  assert.deepEqual(slotRate(100000, 10), {slots: 100000, seconds: 10, slots_per_second: 10000, amortized_wall_ns_per_slot: 100000});
  assert.equal(slotRate(0, 10).amortized_wall_ns_per_slot, null);
});

const {execFileSync} = require('node:child_process');
test('native declared profile resolves isolation and rejects conflicting profiles', () => {
  const cwd = path.resolve(__dirname, '../..');
  const args = ['bench-e2e.nu', 'state-access-bloat-worst-case'];
  const result = JSON.parse(execFileSync('nu', [...args, '--declared-storage', '--case', 'writes', '--accesses', '256', '--dry-run'], {cwd, encoding: 'utf8'}));
  assert.equal(result.configuration.id, 'state-access-declared');
  assert.equal(result.configuration.cases[0].operations_per_transaction, 256);
  assert.equal(result.options.node_memory, '20G');
  assert.equal(result.options.node_swap_limit, '0');
  assert.equal(result.options.feature_env, '');
  for (const extra of [['--accesses', '257', '--case', 'sload'], ['--sized-transactions'], ['--max-transaction-size']])
    assert.throws(() => execFileSync('nu', [...args, '--declared-storage', '--dry-run', ...extra], {cwd, stdio: 'pipe'}));
});
test('native helper derives the declaration range from the full fixture and selected count', () => {
  const output = execFileSync('nu', ['-c', 'source contrib/bench/txgen/helpers.nu; $env.TXGEN_STATE_ACCESSES = "256"; txgen-configure-state-access-env contrib/bench/txgen/presets/declared_read.yml 100000; print $env.TXGEN_DECLARED_MAX_START'],
    {cwd: path.resolve(__dirname, '../..'), encoding: 'utf8'});
  assert.equal(output.trim().split('\n').at(-1), String(399999 * 4096 - 256));
});

const {canonicalWindow} = require('./analyze-state-path-controls.cjs');
const {summarizeBackpressure} = require('./analyze-declared-state-paths.cjs');
test('stalled slices retain their full wall duration and zero throughput', () => {
  assert.throws(() => canonicalWindow([], 1000, 121000));
  const zero = canonicalWindow([], 1000, 121000, {allowSparse: true});
  assert.equal(zero.duration_seconds, 120);
  assert.equal(zero.transactions, 0);
  assert.equal(zero.mgas_per_second, 0);
  const one = canonicalWindow([{number: 7, timestamp_ms: 10000, tx_count: 2, gas_used: 600000}], 1000, 121000, {allowSparse: true});
  assert.equal(one.transactions, 2);
  assert.equal(one.duration_seconds, 120);
  assert.equal(one.mgas_per_second, 0.005);
});
test('backpressure duty weights elapsed time and rejects missing gauges', () => {
  const sample = (t, active) => ({unix_ms: t, metrics: {reth_consensus_engine_beacon_backpressure_active: active}});
  const result = summarizeBackpressure([sample(0, 0), sample(5000, 1), sample(20000, 0)]);
  assert.equal(result.estimated_active_seconds, 15);
  assert.equal(result.active_fraction, 0.75);
  assert.throws(() => summarizeBackpressure([sample(0, undefined), sample(5000, 0)]));
});
