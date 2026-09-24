'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const ROUTER = '0x535441544541434345535342454e434800000000';
const CURSOR = '0x' + 'f'.repeat(64);
const BASE = BigInt('0x6000000000000000000000000000000000000000');
const HIGH = 1n << 255n;
const word = value => '0x' + BigInt(value).toString(16).padStart(64, '0');
const top = (log, offset=1) => BigInt('0x' + log.stack.at(-offset).replace(/^0x/, ''));

function targetSet(prestate, writing, count) {
  if (writing) return new Set(Object.keys(prestate[ROUTER]?.storage || {}).filter(key => key !== CURSOR).map(key => word(key)));
  return new Set(Object.keys(prestate).filter(address => BigInt(address) >= BASE && BigInt(address) < BASE + BigInt(count)).map(address => address.toLowerCase()));
}

function overlap(actual, predicted) {
  assert.ok(actual.size > 0 && predicted.size > 0, 'empty target set');
  const matches = [...actual].filter(key => predicted.has(key)).length;
  return {actual_unique:actual.size, parent_state_unique:predicted.size, overlap:matches,
    parent_state_mismatch_fraction:1 - matches / actual.size};
}

function checkWriteDiff(diff) {
  const before = diff.pre?.[ROUTER]?.storage || {}, after = diff.post?.[ROUTER]?.storage || {};
  const slots = Object.keys(after).filter(key => key !== CURSOR);
  assert.equal(slots.length,1024,'expected 1024 changed data slots');
  for (const slot of slots) {
    const a = BigInt(before[slot] || 0), b = BigInt(after[slot] || 0);
    assert.ok(a > 0n && b > 0n,'zero/new/deleted storage encountered');
    assert.equal(a ^ b,HIGH,'write must toggle the high bit');
    assert.equal(a & (HIGH - 1n),BigInt(slot) + 1n,'unpopulated fixture slot');
  }
  assert.equal(BigInt(after[CURSOR]),BigInt(before[CURSOR] || 0) + 1n,'cursor increment missing');
  return slots.length;
}

function inspectOpcodes(trace, writing, reading = false) {
  assert.equal(trace.failed,false,'router replay reverted');
  const targets = new Set(), costs = {};
  let accesses = 0, cursorWrites = 0, dataWrites = 0;
  for (const log of trace.structLogs) {
    if (log.op === 'SSTORE') {
      if (top(log) === BigInt(CURSOR)) ++cursorWrites;
      else ++dataWrites;
    }
    if (writing || reading ? log.op === 'SLOAD' && top(log) !== BigInt(CURSOR) : log.op === 'EXTCODECOPY') {
      ++accesses;
      const target = top(log);
      targets.add(writing || reading ? word(target) : '0x' + target.toString(16).padStart(40,'0'));
      costs[log.gasCost] = (costs[log.gasCost] || 0) + 1;
      if (writing || reading) assert.equal(Number(log.gasCost),2100,'data SLOAD is not cold');
      else assert.ok([2603,103].includes(Number(log.gasCost)),'unexpected EXTCODECOPY gas');
    }
  }
  assert.equal(accesses,reading ? 4096 : writing ? 1024 : 128);
  assert.equal(cursorWrites,1);
  assert.equal(dataWrites,writing ? 1024 : 0);
  return {targets,accesses,costs,data_writes:dataWrites};
}

function routerCall(trace) {
  if ((trace.to || '').toLowerCase() === ROUTER) return trace;
  for (const child of trace.calls || []) { const found = routerCall(child); if (found) return found; }
}

async function auditTransaction(rpc, hash, number, scenario, fixture, outputDirectory) {
  assert.ok(['state_access_dependent','history_write','history_code'].includes(scenario));
  const writing = scenario === 'history_write', reading = scenario === 'state_access_dependent';
  const storage = writing || reading;
  const callTrace = await rpc('b','debug_traceTransaction',[hash,{tracer:'callTracer'}]);
  const call = routerCall(callTrace);
  assert.ok(call && !call.error,'missing/successless router call');
  const signature = reading ? 'touchStateDependent(bytes32,uint256)' : writing ? 'touchWrites(bytes32,uint256,bool)' : 'touchCode(bytes32,uint256,bool)';
  const selector = (await rpc('b','web3_sha3',['0x'+Buffer.from(signature).toString('hex')])).slice(0,10);
  assert.equal(call.input.slice(0,10),selector);
  assert.equal(call.input.length,reading ? 138 : 202,'wrong calldata length');
  const count = BigInt('0x'+call.input.slice(74,138));
  assert.equal(count,BigInt(storage ? fixture.page_count : fixture.code_count));
  if (!reading) assert.equal(BigInt('0x'+call.input.slice(138,202)),1n,'dependent mode required');
  const prestateOptions = {tracer:'prestateTracer',tracerConfig:{disableCode:true}};
  const actual = await rpc('b','debug_traceTransaction',[hash,prestateOptions]);
  const cursor = actual[ROUTER]?.storage?.[CURSOR] || '0x0';
  const parent = '0x'+(number-1).toString(16);
  const parentCursor = await rpc('b','eth_getStorageAt',[ROUTER,CURSOR,parent]);
  const request = {from:call.from,to:ROUTER,data:call.input,gas:'0x989680'};
  const speculative = await rpc('b','debug_traceCall',[request,parent,prestateOptions]);
  const actualTargets = targetSet(actual,storage,fixture.code_count);
  const mismatch = overlap(actualTargets,targetSet(speculative,storage,fixture.code_count));
  // Reproduce the actual transaction's cursor in a parent-state replay. The
  // real transaction's prestate and diff remain authoritative for stored values.
  const replay = await rpc('b','debug_traceCall',[request,parent,{disableStorage:true,disableMemory:true,
    disableStack:false,stateOverrides:{[ROUTER]:{stateDiff:{[CURSOR]:word(cursor)}}}}]);
  const opcodes = inspectOpcodes(replay,writing,reading);
  assert.deepEqual([...opcodes.targets].sort(),[...actualTargets].sort(),'replay differs from actual access set');
  let changed = 0, diff;
  if (writing) {
    diff = await rpc('b','debug_traceTransaction',[hash,{tracer:'prestateTracer',tracerConfig:{diffMode:true,disableCode:true}}]);
    changed = checkWriteDiff(diff);
  } else if (reading) {
    let accumulator = 0n;
    for (const slot of actualTargets) {
      const value = BigInt(actual[ROUTER].storage[slot]);
      assert.equal(value,BigInt(slot)+1n,'SLOAD fixture must be populated and unmodified');
      accumulator ^= value;
    }
    assert.equal(BigInt(call.output),accumulator,'SLOAD accumulator mismatch');
    assert.equal('0x'+replay.returnValue.replace(/^0x/,''),call.output,'SLOAD replay mismatch');
  } else {
    assert.equal('0x'+replay.returnValue.replace(/^0x/,''),call.output,'code accumulator mismatch');
    // Validate populated, distinct multi-page code without returning 24 MiB per trace.
    const hashes = new Set();
    for (const address of [...actualTargets].slice(0,3)) {
      const code = await rpc('b','eth_getCode',[address,parent]);
      assert.equal((code.length-2)/2,fixture.code_bytes);
      assert.equal(code.slice(2,4),'00');
      hashes.add(await rpc('b','web3_sha3',[code]));
    }
    assert.equal(hashes.size,3,'code hashes are deduplicated');
  }
  const traceFile = path.join(outputDirectory,`history-trace-${hash}.json.gz`);
  fs.writeFileSync(traceFile,zlib.gzipSync(JSON.stringify({callTrace,actual,speculative,replay,diff})));
  return {hash,cursor_before:BigInt(cursor).toString(),parent_cursor:BigInt(parentCursor).toString(),
    history_advanced:BigInt(cursor)>BigInt(parentCursor),...mismatch,accesses:opcodes.accesses,
    gas_cost_histogram:opcodes.costs,changed_contract_slots:changed,trace_file:traceFile,
    caveat:'Parent-state replay models current prewarming input; this is not an instrumented log of every prewarm worker. Other transactions may warm overlapping targets.'};
}

module.exports = {ROUTER,CURSOR,targetSet,overlap,checkWriteDiff,inspectOpcodes,auditTransaction};
