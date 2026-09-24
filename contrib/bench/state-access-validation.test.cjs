'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { inspectTrace, inspectPrestate, sampleEvenly, checkCursorAdvance, waitForBlock } = require('./state-access-validation.cjs');

function fixture() {
  const structLogs = [];
  function load(key, value) {
    structLogs.push({ op: 'SLOAD', depth: 1, gasCost: 2100, stack: [key.toString(16)] });
    structLogs.push({ op: 'POP', depth: 1, gasCost: 2, stack: [value.toString(16)] });
  }
  const cursor = (1n << 256n) - 1n;
  load(cursor, 7n);
  structLogs.push({ op: 'SSTORE', depth: 1, stack: ['8', cursor.toString(16)] });
  for (let i = 0n; i < 4096n; i++) load(i, i + 1n);
  return { failed: false, gas: 8916522, structLogs };
}

test('verifies the populated page, cold reads, and cursor', () => {
  const result = inspectTrace(fixture());
  assert.equal(result.page, '0');
  assert.equal(result.cursor_before, '7');
  assert.equal(result.cold_data_reads, 4096);
});
test('rejects reverted executions', () => assert.throws(() => inspectTrace({ ...fixture(), failed: true })));
test('rejects nonexistent fixture values', () => {
  const trace = fixture(); trace.structLogs[4].stack = ['0'];
  assert.throws(() => inspectTrace(trace), /populated fixture/);
});
test('rejects warm data reads', () => {
  const trace = fixture(); trace.structLogs[3].gasCost = 100;
  assert.throws(() => inspectTrace(trace), /cold-access/);
});
test('rejects duplicate storage reads', () => {
  const trace = fixture(); trace.structLogs[5].stack = ['0'];
  assert.throws(() => inspectTrace(trace), /duplicate/);
});
test('rejects an incorrect cursor increment', () => {
  const trace = fixture(); trace.structLogs[2].stack[0] = '9';
  assert.throws(() => inspectTrace(trace), /cursor did not increment/);
});
test('verifies actual transaction access-set values independently of opcode replay', () => {
  const storage = { ['0x' + 'f'.repeat(64)]: '0x7' };
  for (let i = 0; i < 4096; i++) storage['0x'+i.toString(16)] = '0x'+(i+1).toString(16);
  const state = { '0x535441544541434345535342454e434800000000': { storage } };
  assert.deepEqual(inspectPrestate(state), { start_slot: '0', cursor_before: '7' });
  storage['0x0'] = '0x0';
  assert.throws(() => inspectPrestate(state), /unpopulated/);
});
test('samples endpoints and the middle without duplication', () => {
  assert.deepEqual(sampleEvenly([0,1,2,3,4,5,6,7], 3), [0,3,7]);
  assert.deepEqual(sampleEvenly([0,1], 3), [0,1]);
});
test('checks the entire report against the committed cursor, including multi-transaction blocks', () => {
  const blocks = [{number:22,tx_count:1},{number:23,tx_count:2}];
  assert.equal(checkCursorAdvance('0x10','0x13',blocks).transactions, '3');
  assert.throws(() => checkCursorAdvance('0x10','0x12',blocks), /cursor advance/);
  assert.throws(() => checkCursorAdvance('0x10','0x13',[blocks[0],{number:24,tx_count:2}]), /block gap/);
});
test('waits for follower catchup and fails a stalled follower', async () => {
  const heads = ['0x14', '0x15', '0x16'];
  await waitForBlock(async method => {
    assert.equal(method, 'eth_blockNumber');
    return heads.shift();
  }, 22, 1000, 0);
  assert.equal(heads.length, 0);
  await assert.rejects(waitForBlock(async () => '0x14', 22, 0, 0), /did not reach/);
});
