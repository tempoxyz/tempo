#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const ADDRESS = '0x535441544541434345535342454e434800000000';
const READS = 4096;
const CURSOR = (1n << 256n) - 1n;
const hex = value => `0x${BigInt(value).toString(16)}`;
const word = value => BigInt(value).toString(16).padStart(64, '0');
const stackTop = log => BigInt(`0x${log.stack.at(-1).replace(/^0x/, '')}`);

function inspectTrace(trace) {
  assert.equal(trace.failed, false, 'opcode call replay reverted');
  assert.ok(Array.isArray(trace.structLogs), 'opcode trace is required');
  const loads = [];
  const writes = [];
  for (let i = 0; i < trace.structLogs.length; i++) {
    const log = trace.structLogs[i];
    if (log.op === 'SSTORE') writes.push({ slot: stackTop(log), value: BigInt(`0x${log.stack.at(-2).replace(/^0x/, '')}`) });
    if (log.op !== 'SLOAD') continue;
    const next = trace.structLogs[i + 1];
    assert.ok(next && next.depth === log.depth, 'missing SLOAD result');
    loads.push({ slot: stackTop(log), value: stackTop(next), gas: Number(log.gasCost) });
  }
  const cursors = loads.filter(load => load.slot === CURSOR);
  const data = loads.filter(load => load.slot !== CURSOR);
  assert.equal(cursors.length, 1, 'expected one cursor read');
  assert.equal(data.length, READS, 'expected exactly 4096 data reads');
  assert.equal(new Set(data.map(load => load.slot.toString())).size, READS, 'duplicate data slots');
  assert.equal(writes.length, 1, 'expected only the cursor write');
  assert.equal(writes[0].slot, CURSOR, 'unexpected storage write');
  assert.equal(writes[0].value, (cursors[0].value + 1n) & CURSOR, 'cursor did not increment');
  const start = data[0].slot;
  assert.equal(start % BigInt(READS), 0n, 'unaligned benchmark page');
  for (const [index, load] of data.entries()) {
    assert.equal(load.slot, start + BigInt(index), 'non-contiguous page');
    assert.equal(load.value, load.slot + 1n, 'read does not match populated fixture');
    assert.equal(load.gas, 2100, 'data SLOAD was not charged cold-access gas');
  }
  return {
    data_reads: data.length,
    unique_data_slots: READS,
    cold_data_reads: data.length,
    start_slot: start.toString(),
    page: (start / BigInt(READS)).toString(),
    cursor_before: cursors[0].value.toString(),
    populated_values_verified: true,
    failed: trace.failed,
    trace_gas: trace.gas,
  };
}

function inspectPrestate(prestate) {
  const account = prestate[ADDRESS];
  assert.ok(account?.storage, 'transaction tracer did not record benchmark storage');
  const entries = Object.entries(account.storage).map(([key, value]) => ({ slot: BigInt(key), value: BigInt(value) }));
  const data = entries.filter(entry => entry.slot !== CURSOR).sort((a,b) => a.slot < b.slot ? -1 : 1);
  assert.equal(entries.length, READS + 1, 'unexpected transaction storage access set');
  assert.equal(data.length, READS, 'transaction did not access 4096 data slots');
  assert.equal(data[0].slot % BigInt(READS), 0n, 'unaligned transaction storage page');
  for (const [i, entry] of data.entries()) {
    assert.equal(entry.slot, data[0].slot + BigInt(i), 'non-contiguous transaction storage access set');
    assert.equal(entry.value, entry.slot + 1n, 'transaction accessed unpopulated fixture data');
  }
  return { start_slot: data[0].slot.toString(), cursor_before: entries.find(entry => entry.slot === CURSOR).value.toString() };
}

function sampleEvenly(items, count) {
  if (items.length <= count) return items;
  return Array.from({ length: count }, (_, i) => items[Math.floor(i * (items.length - 1) / (count - 1))]);
}

function checkCursorAdvance(before, after, blocks) {
  const sorted = [...blocks].sort((a,b) => a.number - b.number);
  assert.ok(sorted.length > 0, 'no reported blocks');
  for (let i = 1; i < sorted.length; i++) assert.equal(sorted[i].number, sorted[i-1].number + 1, 'report has a block gap');
  const transactions = sorted.reduce((sum, block) => sum + BigInt(block.tx_count), 0n);
  assert.equal(BigInt(after) - BigInt(before), transactions, 'cursor advance does not match all included transactions');
  return { first_block: sorted[0].number, last_block: sorted.at(-1).number, before: BigInt(before).toString(), after: BigInt(after).toString(), transactions: transactions.toString(), ok: true };
}

async function waitForBlock(rpc, number, timeoutMs = 600000, pollMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (BigInt(await rpc('eth_blockNumber')) < BigInt(number)) {
    assert.ok(Date.now() < deadline, `follower did not reach reported block ${number}`);
    await new Promise(resolve => setTimeout(resolve, pollMs));
  }
}

async function audit(options) {
  const endpoint = new URL(options.rpc);
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname), 'audit only supports local benchmark RPC');
  let id = 0;
  async function rpc(method, params = []) {
    const response = await fetch(endpoint, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
      signal: AbortSignal.timeout(120000),
    });
    assert.ok(response.ok, `${method}: HTTP ${response.status}`);
    const body = await response.json();
    assert.ok(!body.error, `${method}: ${JSON.stringify(body.error)}`);
    assert.notEqual(body.result, null, `${method}: missing result`);
    return body.result;
  }
  assert.equal(BigInt(await rpc('eth_chainId')), 1337n, 'unexpected chain');
  const report = JSON.parse(fs.readFileSync(options.report, 'utf8'));
  const scenario = report.metadata.scenario;
  assert.ok(['state_access_dependent', 'state_access_predictable', 'state_access_resident'].includes(scenario));
  const expectedPages = scenario === 'state_access_resident' ? 1n : BigInt(report.metadata.bloat_mib) * 4n - 1n;
  const method = scenario === 'state_access_predictable' ? 'touchPredictable' : 'touchStateDependent';
  const signature = Buffer.from(`${method}(bytes32,uint256)`).toString('hex');
  const selector = (await rpc('web3_sha3', [`0x${signature}`])).slice(0, 10);
  const sortedBlocks = [...report.blocks].sort((a,b) => a.number - b.number);
  assert.ok(sortedBlocks.length > 0, 'no reported blocks');
  await waitForBlock(rpc, sortedBlocks.at(-1).number);
  const before = await rpc('eth_getStorageAt', [ADDRESS, hex(CURSOR), hex(sortedBlocks[0].number - 1)]);
  const after = await rpc('eth_getStorageAt', [ADDRESS, hex(CURSOR), hex(sortedBlocks.at(-1).number)]);
  const cursorCheck = checkCursorAdvance(before, after, sortedBlocks);
  const candidates = report.blocks.filter(block => block.tx_count > 0 && block.gas_used > 8_000_000);
  assert.ok(candidates.length >= 8, 'too few workload blocks for an audit');
  const warm = candidates.filter(block => block.timestamp_ms >= candidates[0].timestamp_ms + 600000);
  const selected = sampleEvenly(warm.length >= 8 ? warm : candidates, 8);
  const receipts = [];
  const traceCandidates = [];
  for (const reported of selected) {
    const block = await rpc('eth_getBlockByNumber', [hex(reported.number), false]);
    assert.equal(Number(BigInt(block.gasUsed)), reported.gas_used, 'report gas differs from canonical block');
    const blockReceipts = await rpc('eth_getBlockReceipts', [hex(reported.number)]);
    assert.equal(blockReceipts.length, reported.tx_count, 'receipt count differs from report');
    let gas = 0n;
    for (const receipt of blockReceipts) {
      assert.equal(BigInt(receipt.status), 1n, `reverted transaction ${receipt.transactionHash}`);
      assert.equal(receipt.blockHash, block.hash, 'receipt belongs to a different block');
      gas += BigInt(receipt.gasUsed);
    }
    assert.equal(gas, BigInt(block.gasUsed), 'receipt gas sum differs from block gas');
    receipts.push({ block: reported.number, hash: block.hash, transactions: blockReceipts.length, successful: blockReceipts.length, gas: gas.toString() });
    traceCandidates.push(blockReceipts[0].transactionHash);
  }
  const traces = [];
  for (const hash of sampleEvenly(traceCandidates, 3)) {
    const tx = await rpc('eth_getTransactionByHash', [hash]);
    const calls = tx.calls || [{ to: tx.to, input: tx.input }];
    const call = calls.find(call => call.to?.toLowerCase() === ADDRESS);
    assert.ok(call, 'sample transaction does not call the benchmark contract');
    const input = call.input || call.data;
    assert.equal(input.slice(0, 10), selector, 'unexpected benchmark method');
    assert.equal(input.length, 138, 'unexpected calldata size');
    const salt = input.slice(10, 74);
    const pages = BigInt(`0x${input.slice(74)}`);
    assert.equal(pages, expectedPages, 'wrong active working set');
    const prestate = await rpc('debug_traceTransaction', [hash, { tracer: 'prestateTracer' }]);
    const actual = inspectPrestate(prestate);
    const artifact = JSON.parse(fs.readFileSync(path.join(__dirname, 'txgen/state-access-benchmark.json')));
    const runtime = typeof artifact.deployedBytecode === 'string' ? artifact.deployedBytecode : artifact.deployedBytecode.object;
    assert.equal(prestate[ADDRESS].code.toLowerCase(), runtime.toLowerCase(), 'on-chain bytecode differs from fixture');
    const callTrace = await rpc('debug_traceTransaction', [hash, { tracer: 'callTracer' }]);
    assert.ok(!callTrace.error, `transaction call tracer: ${callTrace.error}`);
    const callsInTrace = [];
    function walk(frame) { callsInTrace.push(frame); for (const child of frame.calls || []) walk(child); }
    walk(callTrace);
    const executed = callsInTrace.find(frame => frame.to?.toLowerCase() === ADDRESS && frame.input === input);
    assert.ok(executed && !executed.error, 'benchmark call did not succeed in transaction replay');
    // The Tempo AA default transaction logger omits opcode steps. Verify its actual
    // access set above, then cross-check opcodes in an explicit parent-state call.
    const parent = hex(BigInt(tx.blockNumber) - 1n);
    const trace = await rpc('debug_traceCall', [{ from: tx.from, to: ADDRESS, data: input, gas: tx.gas }, parent, { disableStorage: true, disableMemory: true, disableStack: false }]);
    const checked = inspectTrace(trace);
    assert.equal(checked.start_slot, actual.start_slot, 'call replay and transaction access sets differ');
    assert.equal(checked.cursor_before, actual.cursor_before, 'call replay and transaction pre-state differ');
    assert.equal(trace.returnValue.replace(/^0x/, ''), executed.output.replace(/^0x/, ''), 'call replay return value differs');
    const sequence = scenario === 'state_access_predictable' ? 0n : BigInt(checked.cursor_before);
    const digest = await rpc('web3_sha3', [`0x${salt}${word(sequence)}`]);
    const page = BigInt(digest) % pages;
    assert.equal(BigInt(checked.page), page, 'page does not match calldata and cursor');
    const tracePath = path.join(path.dirname(options.output), `trace-${hash}.json.gz`);
    fs.writeFileSync(tracePath, zlib.gzipSync(JSON.stringify({ transaction: tx, prestate, callTrace, parentStateOpcodeTrace: trace })));
    traces.push({ hash, page_count: pages.toString(), ...checked, trace_file: path.basename(tracePath), bytecode_verified: true, actual_transaction_access_set_verified: true, opcode_trace_kind: 'parent-state debug_traceCall, cross-checked with actual transaction access set and output', transaction_gas: Number(BigInt(callTrace.gasUsed)) });
    console.log(`Verified ${hash}: ${checked.data_reads} populated cold reads, page ${checked.page}`);
  }
  return {
    ok: true, scenario, expected_page_count: expectedPages.toString(),
    whole_report_cursor_check: cursorCheck,
    node: 'follower', report: options.report, audited_at: new Date().toISOString(),
    receipt_blocks: receipts, sampled_receipts: receipts.reduce((n, block) => n + block.transactions, 0),
    traces, sampling_only: true,
    caveat: 'Sampled receipts and transaction access/call traces verify real execution, not every transaction. Opcode counts use a parent-state call replay cross-checked against that transaction; its wrapper gas differs and is not used as the gas denominator. Traces run after load, outside archived metrics. The default AA transaction opcode logger is unsupported (no steps and an inconsistent failed flag).',
  };
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  assert.equal(command, 'audit', 'usage: state-access-validation.cjs audit --rpc URL --report FILE --output FILE');
  const options = {};
  for (let i = 0; i < args.length; i += 2) options[args[i].replace(/^--/, '')] = args[i + 1];
  assert.ok(options.output && options.report && options.rpc, 'missing arguments');
  let result;
  try { result = await audit(options); }
  catch (error) {
    result = { ok: false, error: error.message, stack: error.stack, audited_at: new Date().toISOString() };
    process.exitCode = 1;
  }
  fs.writeFileSync(options.output, JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result, null, 2));
}

module.exports = { inspectTrace, inspectPrestate, sampleEvenly, checkCursorAdvance, waitForBlock };
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
