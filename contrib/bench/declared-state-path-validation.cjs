'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const {ROUTER} = require('./history-state-path-validation.cjs');
const HIGH = 1n << 255n;
const word = value => '0x' + BigInt(value).toString(16).padStart(64, '0');
const SELECTORS = {declared_read: '0x4edb8fb8', declared_write: '0xaf92fa2f'};

function declaredRange(input, scenario, pageCount, expectedAccesses) {
  assert.ok(Object.hasOwn(SELECTORS, scenario), 'unknown declared workload');
  assert.match(input, /^0x[0-9a-fA-F]{136}$/, 'wrong declared calldata length');
  assert.equal(input.slice(0, 10).toLowerCase(), SELECTORS[scenario], 'wrong declared entry point');
  const start = BigInt('0x' + input.slice(10, 74)), count = Number(BigInt('0x' + input.slice(74)));
  assert.ok(Number.isSafeInteger(count) && count >= 1 && count <= 256, 'access count outside native pool limits');
  if (expectedAccesses !== undefined) assert.equal(count, expectedAccesses, 'calldata access count differs from preflight');
  assert.ok(Number.isSafeInteger(pageCount) && pageCount > 0);
  assert.ok(start + BigInt(count) <= BigInt(pageCount) * 4096n, 'range outside populated fixture');
  return {start, count, keys: Array.from({length: count}, (_, i) => word(start + BigInt(i)))};
}

function checkAccessList(accessList, range) {
  assert.ok(Array.isArray(accessList), 'missing transaction access list; rebuild txgen-tempo with access_list support');
  assert.equal(accessList.length, 1, 'expected exactly one declared storage account');
  assert.equal(accessList[0].address.toLowerCase(), ROUTER);
  const keys = accessList[0].storageKeys.map(word);
  assert.equal(new Set(keys).size, keys.length, 'duplicate declaration');
  assert.deepEqual([...keys].sort(), [...range.keys].sort(), 'access list differs from calldata targets');
}

function inspectOpcodes(trace, range, writing) {
  assert.equal(trace.failed, false, 'declared transaction reverted');
  const reads = [], writes = [], costs = {sload: {}, sstore: {}};
  for (const log of trace.structLogs) {
    if (!['SLOAD', 'SSTORE'].includes(log.op)) continue;
    assert.ok(log.stack?.length, 'missing opcode stack');
    const key = word('0x' + log.stack.at(-1).replace(/^0x/, ''));
    const gas = Number(log.gasCost), op = log.op.toLowerCase();
    costs[op][gas] = (costs[op][gas] || 0) + 1;
    if (log.op === 'SLOAD') {
      reads.push(key);
      assert.equal(gas, 100, 'declared SLOAD was not EIP-2930 warm');
    } else writes.push(key);
  }
  assert.deepEqual(reads, range.keys, 'unexpected, missing, or repeated storage read');
  assert.deepEqual(writes, writing ? range.keys : [], 'unexpected, missing, or repeated storage write');
  return {accesses: reads.length, writes: writes.length, gas_cost_histogram: costs};
}

function checkState(actual, diff, callOutput, range, writing) {
  const before = actual[ROUTER]?.storage || {};
  const normalized = Object.fromEntries(Object.entries(before).map(([k, v]) => [word(k), v]));
  assert.deepEqual(Object.keys(normalized).sort(), [...range.keys].sort(), 'prestate targets differ from declarations');
  const pre = diff.pre?.[ROUTER]?.storage || {}, post = diff.post?.[ROUTER]?.storage || {};
  assert.deepEqual(Object.keys(pre).map(word).sort(), writing ? [...range.keys].sort() : [], 'unexpected changed-slot prestate');
  assert.deepEqual(Object.keys(post).map(word).sort(), writing ? [...range.keys].sort() : [], 'unexpected changed-slot poststate');
  let accumulator = 0n;
  for (const key of range.keys) {
    const value = BigInt(normalized[key]);
    assert.equal(value & (HIGH - 1n), BigInt(key) + 1n, 'unpopulated fixture slot');
    if (writing) {
      assert.equal(BigInt(pre[key]), value, 'write prestate mismatch');
      const after = BigInt(post[key]);
      assert.ok(value !== 0n && after !== 0n, 'write allocated or cleared a slot');
      assert.equal(after ^ value, HIGH, 'write did not toggle high bit');
      accumulator ^= after;
    } else {
      assert.equal(value, BigInt(key) + 1n, 'read-only fixture was modified');
      accumulator ^= value;
    }
  }
  assert.equal(BigInt(callOutput), accumulator, 'returned accumulator mismatch');
  return writing ? range.count : 0;
}

function routerCalls(trace) {
  return [(trace.to || '').toLowerCase() === ROUTER ? trace : null,
    ...(trace.calls || []).flatMap(routerCalls)].filter(Boolean);
}

async function auditTransaction(rpc, hash, number, scenario, fixture, outputDirectory) {
  const transaction = await rpc('b', 'eth_getTransactionByHash', [hash]);
  assert.equal(Number(BigInt(transaction.blockNumber)), number, 'transaction block mismatch');
  const receipt = await rpc('b', 'eth_getTransactionReceipt', [hash]);
  assert.equal(BigInt(receipt.status), 1n, 'declared transaction receipt failed');
  const callTrace = await rpc('b', 'debug_traceTransaction', [hash, {tracer: 'callTracer'}]);
  const calls = routerCalls(callTrace);
  assert.equal(calls.length, 1, 'expected exactly one router call');
  const call = calls[0];
  assert.ok(!call.error && !(call.calls || []).length, 'router failed or made external calls');
  const range = declaredRange(call.input, scenario, fixture.page_count, fixture.declared_accesses);
  checkAccessList(transaction.accessList, range);
  const transactionOpcodes = await rpc('b', 'debug_traceTransaction', [hash, {disableStorage: true, disableMemory: true, disableStack: false}]);
  const writing = scenario === 'declared_write';
  const actual = await rpc('b', 'debug_traceTransaction', [hash, {tracer: 'prestateTracer', tracerConfig: {disableCode: true}}]);
  const diff = await rpc('b', 'debug_traceTransaction', [hash, {tracer: 'prestateTracer', tracerConfig: {diffMode: true, disableCode: true}}]);
  let replay = transactionOpcodes;
  let opcodeSource = 'actual-transaction';
  if (transactionOpcodes.structLogs?.length === 0) {
    // The current Tempo AA structured logger returns no opcodes (and failed:true)
    // even for successful receipts/call traces. Use the same RPC replay approach
    // as the history suite, with actual prestate and the actual signed list.
    assert.notEqual(call.from.toLowerCase(), ROUTER);
    const stateOverrides = {[call.from]: {nonce: '0x1'}, [ROUTER]: {stateDiff: actual[ROUTER].storage}};
    replay = await rpc('b', 'debug_traceCall', [{from: call.from, to: ROUTER, data: call.input,
      gas: '0x989680', accessList: transaction.accessList}, '0x' + (number - 1).toString(16),
      {disableStorage: true, disableMemory: true, disableStack: false, stateOverrides}]);
    opcodeSource = 'parent-state-call-with-actual-prestate-and-signed-access-list';
  }
  const traceFile = path.join(outputDirectory, `declared-trace-${hash}.json.gz`);
  fs.writeFileSync(traceFile, zlib.gzipSync(JSON.stringify({transaction, receipt, callTrace, transactionOpcodes, replay, actual, diff, opcodeSource})));
  const opcodes = inspectOpcodes(replay, range, writing);
  assert.equal('0x' + replay.returnValue.replace(/^0x/, ''), call.output, 'opcode replay output differs from actual execution');
  const changed = checkState(actual, diff, call.output, range, writing);
  return {hash, start: range.start.toString(), declared_slots: range.count, ...opcodes,
    changed_contract_slots: changed, opcode_source: opcodeSource, trace_file: traceFile,
    caveat: 'Signed declarations and actual router state effects verified. Opcode warmth is replay-checked when the native AA logger emits no opcodes; the replay uses actual prestate and the signed list. This does not prove physical cache residency or trace prewarming workers.'};
}
module.exports = {ROUTER, SELECTORS, word, declaredRange, checkAccessList, inspectOpcodes, checkState, auditTransaction};
