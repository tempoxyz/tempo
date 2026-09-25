#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFile} = require('node:child_process');
const {promisify, parseArgs} = require('node:util');
const {measurementTiming} = require('./state-path-timing.cjs');
const {loadOrigin} = require('./state-access-load-clock.cjs');
const {parseMemory} = require('./state-path-memory.cjs');
const historyValidation = require('./history-state-path-validation.cjs');
const declaredValidation = require('./declared-state-path-validation.cjs');
const {checkCursorAdvance} = require('./state-access-validation.cjs');
const execute = promisify(execFile);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const CONTRACT = '0x5fbdb2315678afecb367f032d93f642f64180aa3';
const RPC = {a: 'http://127.0.0.1:8545', b: 'http://127.0.0.1:8645'};

async function rpc(node, method, params = []) {
  const response = await fetch(RPC[node], {method: 'POST', headers: {'content-type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id: 1, method, params}), signal: AbortSignal.timeout(method.startsWith('debug_') ? 120000 : 20000)});
  assert.ok(response.ok, `${node} ${method}: HTTP ${response.status}`);
  const data = await response.json();
  assert.ok(!data.error, `${node} ${method}: ${JSON.stringify(data.error)}`);
  return data.result;
}

function frontier(checkpoint) {
  assert.ok(Number.isSafeInteger(checkpoint.block_number) && checkpoint.block_number >= 0);
  const unit = checkpoint.stage_checkpoint;
  assert.ok(unit === null || unit === undefined || Object.hasOwn(unit, 'Finish'), 'unexpected Finish checkpoint variant');
  const state = unit?.Finish?.partial_state_trie ?? checkpoint.block_number;
  assert.ok(Number.isSafeInteger(state) && state >= 0 && state <= checkpoint.block_number, 'invalid state frontier');
  return {block: checkpoint.block_number, state};
}

function checkpointCommand(options, node) {
  const datadir = options[`${node}-datadir`];
  if (options['checkpoint-tool']) return {file: options['checkpoint-tool'], args: [path.join(datadir, 'db')]};
  return {file: options.tempo, args: ['db', '--datadir', datadir,
    '--chain', path.join(datadir, '.bench-meta/genesis.json'), 'get', 'mdbx',
    'StageCheckpoints', '"Finish"', '--quiet', '--color', 'never']};
}

async function checkpoint(options, node) {
  const command = checkpointCommand(options, node);
  const {stdout} = await execute(command.file, command.args, {timeout: 15000, maxBuffer: 2 ** 20});
  return frontier(JSON.parse(stdout));
}

function parseIo(text) {
  const devices = {};
  for (const line of text.trim().split('\n').filter(Boolean)) {
    const [device, ...fields] = line.split(/\s+/);
    assert.match(device, /^\d+:\d+$/);
    const values = Object.fromEntries(fields.map(field => {
      const [key, value] = field.split('=');
      const number = Number(value);
      assert.ok(Number.isSafeInteger(number) && number >= 0, 'invalid I/O counter');
      return [key, number];
    }));
    devices[device] = values;
  }
  return devices;
}

function selectedMetrics(text) {
  const values = {};
  for (const line of text.split('\n')) {
    const match = /^(\w+)(\{[^}]*\})?\s+([\d.eE+-]+)$/.exec(line);
    if (!match) continue;
    const [, name, labels = '', value] = match;
    if (/^reth_db_bytecode_prefetch_(enabled|requests|requests_rw|bytes|errors|skipped_dirty)$/.test(name)) {
      assert.ok(Number.isFinite(Number(value)));
      values[name + labels] = Number(value);
      continue;
    }
    if (!/^(reth_tempo_payload_builder_(gas_used_sum|total_transactions_sum|block_build_stop_total|(total_normal_transaction_fill|total_transaction_execution|payload_finalization|sparse_trie_state_root_wait|builder_finish|payload_build)_duration_seconds_(sum|count))|reth_sync_execution_gas_processed_total|reth_consensus_engine_beacon_(executed_blocks|backpressure_active|backpressure_stall_duration_sum|persistence_duration_sum)|reth_sync_caching_(code|storage|account)_cache_(hits|misses)|reth_transaction_pool_aa_2d_pending_transactions)$/.test(name)) continue;
    const number = Number(value);
    assert.ok(Number.isFinite(number));
    values[name + labels] = number;
  }
  return values;
}

async function observation(options, withCheckpoint = true) {
  const result = {unix_ms: Date.now(), nodes: {}};
  for (const node of ['a', 'b']) {
    const sample = {};
    try {
      sample.head = Number(BigInt(await rpc(node, 'eth_blockNumber')));
      const response = await fetch(`http://127.0.0.1:${node === 'a' ? 9001 : 9101}/metrics`, {signal: AbortSignal.timeout(5000)});
      assert.ok(response.ok, `metrics HTTP ${response.status}`);
      sample.metrics = selectedMetrics(await response.text());
      const unit = `tempo-e2e-${node}-${options.phase.replaceAll('_', '-').replaceAll('.', '-')}.scope`;
      try {
        sample.io = parseIo(fs.readFileSync(`/sys/fs/cgroup/system.slice/${unit}/io.stat`, 'utf8'));
        sample.database_device = fs.readFileSync(`/sys/class/block/${node === 'a' ? 'nvme1n1' : 'nvme2n1'}/dev`, 'utf8').trim();
      }
      catch (error) { sample.io_error = String(error); }
      try { sample.memory = parseMemory(fs.readFileSync(`/sys/fs/cgroup/system.slice/${unit}/memory.stat`, 'utf8')); }
      catch (error) { sample.memory_error = String(error); }
      try {
        const group = `/sys/fs/cgroup/system.slice/${unit}`;
        sample.memory_limits = Object.fromEntries(['memory.max', 'memory.current', 'memory.swap.max', 'memory.swap.current']
          .map(file => [file, fs.readFileSync(`${group}/${file}`, 'utf8').trim()]));
        sample.memory_events = Object.fromEntries(fs.readFileSync(`${group}/memory.events`, 'utf8').trim().split('\n')
          .map(line => { const [key, value] = line.split(/\s+/); return [key, Number(value)]; }));
      } catch (error) { sample.memory_limits_error = String(error); }
      if (withCheckpoint) {
        sample.checkpoint_tool = options['checkpoint-tool'] || 'tempo db get';
        try {
          sample.persisted = await checkpoint(options, node);
          sample.head = Number(BigInt(await rpc(node, 'eth_blockNumber')));
        }
        catch (error) { sample.checkpoint_error = String(error); }
      }
    } catch (error) { sample.error = String(error); }
    sample.unix_ms = Date.now();
    result.nodes[node] = sample;
  }
  return result;
}

async function guardLocalChain() {
  for (const node of ['a', 'b']) assert.equal(BigInt(await rpc(node, 'eth_chainId')), 1337n, 'local chain 1337 required');
}

function primed(sample, target) {
  return target > 0 && ['a', 'b'].every(node => sample.nodes[node]?.persisted?.state >= target);
}

async function prime(options) {
  await guardLocalChain();
  const target = Math.max(1, Number(BigInt(await rpc('a', 'eth_blockNumber'))));
  const deadline = Date.now() + 180000, samples = [];
  for (const node of ['a', 'b']) {
    assert.ok(fs.existsSync(path.join(options[`${node}-datadir`], '.bench-meta/history-state-paths.json')), 'history fixture required');
    assert.equal(BigInt(await rpc(node, 'eth_getStorageAt', [historyValidation.ROUTER, historyValidation.CURSOR, 'latest'])), 0n, 'workload already started');
  }
  while (Date.now() < deadline) {
    const sample = await observation(options);
    samples.push(sample);
    if (primed(sample, target)) {
      const result = {ok: true, target_block: target, samples, primed_at: new Date().toISOString(),
        reason: 'Persist ordinary blocks before load: a block-zero Merkle checkpoint forces a whole-fixture rebuild on first pipeline catch-up.'};
      fs.writeFileSync(options.output, JSON.stringify(result, null, 2) + '\n');
      console.log(JSON.stringify({primed: true, target_block: target, frontiers: Object.fromEntries(['a', 'b'].map(node => [node, sample.nodes[node].persisted]))}));
      return;
    }
    if (samples.length % 6 === 1) console.log(`Waiting for both state/trie frontiers to persist through block ${target}`);
    await sleep(5000);
  }
  fs.writeFileSync(options.output, JSON.stringify({ok: false, target_block: target, samples}, null, 2) + '\n');
  throw new Error('pre-load persistence priming timed out');
}

async function watch(options) {
  await guardLocalChain();
  // Enable accounting only on the two benchmark scopes, without setting I/O limits.
  for (const node of ['a', 'b']) {
    const unit = `tempo-e2e-${node}-${options.phase.replaceAll('_', '-').replaceAll('.', '-')}.scope`;
    await execute('sudo', ['-n', 'systemctl', 'set-property', '--runtime', unit, 'IOAccounting=yes'], {timeout: 10000});
  }
  const deadline = Date.now() + Number(options.seconds) * 1000;
  let iteration = 0;
  while (Date.now() < deadline && !fs.existsSync(options.stop)) {
    const sample = await observation(options, iteration++ % 6 === 0);
    fs.appendFileSync(options.output, JSON.stringify(sample) + '\n');
    await sleep(5000);
  }
}

function callsToContract(trace) {
  const calls = [];
  function walk(call) {
    if ((call.to || '').toLowerCase() === CONTRACT) calls.push(call);
    for (const child of call.calls || []) walk(child);
  }
  walk(trace);
  return calls;
}

function checkCalls(trace, writing) {
  const calls = callsToContract(trace);
  assert.ok(calls.length > 0, 'no calls to deployed contract');
  for (const call of calls) assert.ok(!call.error, `contract call failed: ${call.error}`);
  const selectors = calls.map(call => call.input.slice(0, 10));
  const expected = writing ? ['0x095ea7b3'] : ['0x06fdde03', '0x95d89b41', '0x313ce567'];
  for (const selector of expected) assert.ok(selectors.includes(selector), `missing ${selector}`);
  if (writing) {
    const call = calls.find(call => call.input.startsWith(expected[0]));
    assert.equal(BigInt(call.output), 1n, 'approve did not return true');
    assert.equal(call.input.slice(34, 74).toLowerCase(), '000000000000000000000000000000000000dead');
    const amount = BigInt('0x' + call.input.slice(74, 138));
    assert.ok(amount >= 1n && amount <= 1000000n, 'approval amount outside ordinary bounded range');
  }
  return selectors;
}

function changedStorage(diff) {
  const before = diff.pre?.[CONTRACT]?.storage || {};
  const after = diff.post?.[CONTRACT]?.storage || {};
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter(key => BigInt(before[key] || '0x0') !== BigInt(after[key] || '0x0'));
}

function selectTraceCandidates(candidates, history, scenario, allowFirstSload = false) {
  if (allowFirstSload) assert.equal(scenario, 'state_access_dependent', 'first-transaction allowance is only for the 4096-SLOAD diagnostic control');
  let selected = history ? candidates.filter(block => block.tx_count > 1) : candidates;
  let policy = history ? 'non-first-required' : 'ordinary';
  const maxTx = ['history_read_max', 'history_code_max'].includes(scenario);
  const sized = ['history_read_sized', 'history_code_sized'].includes(scenario);
  if (selected.length < 3 && (allowFirstSload || maxTx || sized)) {
    selected = candidates;
    policy = sized ? 'sized-first-allowed' : maxTx ? 'max-size-first-allowed' : 'large-sload-control-first-allowed';
  }
  assert.ok(selected.length >= 3, 'insufficient non-first transaction samples for history audit');
  return {candidates: selected, policy};
}

function validateHistorySamples(traces, policy) {
  const advanced = traces.filter(trace => trace.history_advanced);
  if (!['large-sload-control-first-allowed', 'max-size-first-allowed', 'sized-first-allowed'].includes(policy))
    assert.ok(advanced.length > 0, 'no within-block history change sampled');
  if (advanced.length) assert.ok(advanced.reduce((sum, trace) => sum + trace.parent_state_mismatch_fraction, 0) / advanced.length > 0.9,
    'sampled parent-state access mismatch is not established');
}

async function audit(options) {
  await guardLocalChain();
  const report = JSON.parse(fs.readFileSync(options.report));
  const maxTx = ['history_read_max', 'history_code_max'].includes(report.metadata.scenario);
  const sized = ['history_read_sized', 'history_code_sized'].includes(report.metadata.scenario);
  const history = maxTx || sized || ['state_access_dependent', 'history_read', 'history_code', 'history_write'].includes(report.metadata.scenario);
  const declared = ['declared_read', 'declared_write'].includes(report.metadata.scenario);
  const writing = ['state_paths_write', 'history_write', 'declared_write'].includes(report.metadata.scenario);
  assert.ok(history || declared || writing || report.metadata.scenario === 'state_paths_read', 'unexpected control scenario');
  const contract = history || declared ? historyValidation.ROUTER : CONTRACT;
  const fixture = history || declared ? JSON.parse(fs.readFileSync(path.join(options['a-datadir'], '.bench-meta/history-state-paths.json'))) : null;
  if (fixture) fixture.page_count = Number(report.metadata.bloat_mib) * 4 - 1;
  if (declared) {
    const preflight = JSON.parse(fs.readFileSync(options.report.replace(/\.json$/, '.declared-preflight.json')));
    assert.equal(preflight.ok, true);
    assert.equal(preflight.scenario, report.metadata.scenario);
    assert.equal(preflight.page_count, fixture.page_count);
    fixture.declared_accesses = preflight.accesses;
  }
  if (sized) {
    const preflight = JSON.parse(fs.readFileSync(path.join(path.dirname(options.report), `max-tx-preflight-${options.phase}.json`)));
    assert.equal(preflight.scenario, report.metadata.scenario);
    assert.equal(preflight.ok, true);
    fixture.sized_accesses = preflight.accesses;
  }
  const blocks = [...report.blocks].sort((a, b) => a.number - b.number);
  assert.ok(blocks.length > 1);
  const endBlock = blocks.at(-1).number;
  const deadline = Date.now() + (history || declared ? (writing ? 1800000 : 600000) : 300000);
  while (Number(BigInt(await rpc('b', 'eth_blockNumber'))) < endBlock) {
    assert.ok(Date.now() < deadline, 'follower catch-up timed out');
    await sleep(2000);
  }
  const code = await rpc('b', 'eth_getCode', [contract, 'latest']);
  let cursorCheck;
  if (history || declared) {
    const artifact = JSON.parse(fs.readFileSync(path.join(__dirname, 'txgen/history-state-paths.json')));
    assert.equal(code.toLowerCase(), artifact.deployedBytecode.object.toLowerCase(), 'router artifact differs from executed code');
    if (history) {
      const before = await rpc('b', 'eth_getStorageAt', [contract, historyValidation.CURSOR, '0x' + (blocks[0].number - 1).toString(16)]);
      const after = await rpc('b', 'eth_getStorageAt', [contract, historyValidation.CURSOR, '0x' + endBlock.toString(16)]);
      cursorCheck = checkCursorAdvance(before, after, blocks);
      const nonempty = blocks.filter(block => block.tx_count > 0).length;
      cursorCheck.transactions_with_prior_workload_in_block = Number(cursorCheck.transactions) - nonempty;
      cursorCheck.history_advanced_fraction = cursorCheck.transactions_with_prior_workload_in_block / Number(cursorCheck.transactions);
    }
  } else assert.ok((code.length - 2) / 2 > 4096, 'expected an ordinary multi-page deployed contract');
  const timing = measurementTiming(report.metadata.run_duration_secs, options['warmup-seconds'] ?? 600);
  const origin = await loadOrigin(options.report.replace(/\.json$/, '.samples.ndjson.gz'));
  const historyCoverage = history ? historyValidation.measuredHistoryCoverage(blocks, timing,
    report.metadata.scenario === 'history_read' ? 0.9 : 0, origin) : null;
  const candidates = blocks.filter(block => block.tx_count > 0 && block.timestamp_ms >= origin + timing.from_ms && block.timestamp_ms <= origin + timing.to_ms);
  assert.ok(candidates.length >= 8, 'insufficient steady-state receipt samples');
  const receiptBlocks = Array.from({length:8},(_,i)=>candidates[Math.floor(i*(candidates.length-1)/7)]);
  const traceSelection = selectTraceCandidates(candidates, history, report.metadata.scenario, !!options['allow-first-sload-samples']);
  const traceCandidates = traceSelection.candidates;
  const traceBlocks = new Set([0,0.5,1].map(fraction=>traceCandidates[Math.floor(fraction*(traceCandidates.length-1))].number));
  const sampledBlocks = [...new Map([...receiptBlocks,...candidates.filter(block=>traceBlocks.has(block.number))].map(block=>[block.number,block])).values()];
  const receipts = [], traces = [];
  for (const reported of sampledBlocks) {
    const number = '0x' + reported.number.toString(16);
    const block = await rpc('b', 'eth_getBlockByNumber', [number, false]);
    const list = await rpc('b', 'eth_getBlockReceipts', [number]);
    assert.equal(list.length, reported.tx_count);
    let gas = 0n;
    for (const receipt of list) {
      assert.equal(BigInt(receipt.status), 1n, `revert: ${receipt.transactionHash}`);
      if (maxTx) assert.ok(BigInt(receipt.gasUsed) >= 29700000n && BigInt(receipt.gasUsed) <= 30000000n, 'transaction is not near the 30M gas cap');
      assert.equal(receipt.blockHash, block.hash);
      gas += BigInt(receipt.gasUsed);
    }
    assert.equal(gas, BigInt(block.gasUsed));
    assert.equal(gas, BigInt(reported.gas_used));
    receipts.push({block: reported.number, count: list.length, gas: gas.toString()});
    if (traceBlocks.has(reported.number)) {
      if (declared) {
        const hash = list.at(-1).transactionHash;
        traces.push(await declaredValidation.auditTransaction(rpc, hash, reported.number, report.metadata.scenario, fixture, path.dirname(options.output)));
        continue;
      }
      if (history) {
        const hash = list.at(-1).transactionHash;
        traces.push(await historyValidation.auditTransaction(rpc, hash, reported.number, report.metadata.scenario, fixture, path.dirname(options.output)));
        continue;
      }
      const hash = list[0].transactionHash;
      const trace = await rpc('b', 'debug_traceTransaction', [hash, {tracer: 'callTracer'}]);
      const selectors = checkCalls(trace, writing);
      const diff = await rpc('b', 'debug_traceTransaction', [hash, {tracer: 'prestateTracer', tracerConfig: {diffMode: true}}]);
      const changed = changedStorage(diff);
      assert.ok(writing ? changed.length > 0 : changed.length === 0, 'unexpected contract storage changes');
      const traceFile = path.join(path.dirname(options.output), `ordinary-trace-${hash}.json`);
      fs.writeFileSync(traceFile, JSON.stringify({trace, diff}, null, 2) + '\n');
      traces.push({hash, selectors, changed_contract_slots: changed.length, trace_file: traceFile});
    }
  }
  if (history) validateHistorySamples(traces, traceSelection.policy);
  // Wait for actual empty blocks, not just the legacy nonce-pool count (AA has a separate pool).
  let quietSince = null, quietTarget = null, previousHead = endBlock, quietBlocks = 0;
  while (Date.now() < deadline) {
    const head = Number(BigInt(await rpc('a', 'eth_blockNumber')));
    assert.ok(head >= previousHead, 'head regressed during drain');
    for (let number = previousHead + 1; number <= head; ++number) {
      const block = await rpc('a', 'eth_getBlockByNumber', ['0x' + number.toString(16), false]);
      if (block.transactions.length === 0) {
        if (quietSince === null) { quietSince = Date.now(); quietTarget = number; }
        ++quietBlocks;
      } else { quietSince = null; quietTarget = null; quietBlocks = 0; }
    }
    previousHead = head;
    if (quietSince !== null && quietBlocks >= 10 && Date.now() - quietSince >= 15000) break;
    await sleep(2000);
  }
  assert.ok(quietTarget !== null && quietSince !== null && quietBlocks >= 10 && Date.now() - quietSince >= 15000, 'workload did not drain');
  const drain = [];
  while (Date.now() < deadline) {
    const sample = await observation(options);
    drain.push(sample);
    if (['a', 'b'].every(node => sample.nodes[node].persisted?.state >= quietTarget)) {
      const result = {ok: true, scenario: report.metadata.scenario, contract, fixture, timing, cursor_check: cursorCheck,
        measured_history_coverage: historyCoverage,
        trace_sampling: {policy: declared ? 'declared-last-transaction' : traceSelection.policy, non_first_samples: traces.filter(trace => trace.history_advanced).length},
        runtime_code_bytes: (code.length - 2) / 2, receipts, traces,
        sampled_receipts: receipts.reduce((sum, row) => sum + row.count, 0),
        workload_end_block: endBlock, quiet_target_block: quietTarget,
        persisted_through_workload: true, drain,
        audited_at: new Date().toISOString(),
        caveat: declared
          ? 'Declared router storage reads are EIP-2930 warm; signed access lists match calldata and state effects. Current node prewarming is used unchanged. Gas warmth alone does not establish physical prefetch. Report whole-node I/O, wall time and durable progress as well as execution time.'
          : traceSelection.policy === 'sized-first-allowed'
          ? 'Sized transactions may be the first or only transaction in a block. Report measured history coverage; do not infer prewarming bypass from the router design alone.'
          : traceSelection.policy === 'max-size-first-allowed'
          ? 'Near-cap transactions may be the first or only transaction in a block. Cold-access and gas-cap checks passed; report actual history coverage rather than claiming within-block prewarming bypass.'
          : traceSelection.policy === 'large-sload-control-first-allowed'
          ? 'Large-SLOAD diagnostic control: first transactions may be sampled. Cold-read correctness is verified, but history-bypass coverage must not be inferred from these traces. Timed I/O and persistence are reported separately.'
          : history
          ? 'History-dependent targets verified by actual transaction traces and parent-state replays. Not a direct log of prewarming worker accesses or proof of a universal worst case. Physical I/O is measured separately. Quiet-tail persistence includes post-load transactions.'
          : 'Ordinary resident-working-set controls. Sampled correctness, not exhaustive. No cache-evasion or cold-code claim. Quiet-tail persistence includes post-load transactions; metrics during load are separate.'};
      fs.writeFileSync(options.output, JSON.stringify(result, null, 2) + '\n');
      console.log(JSON.stringify({audit_ok: true, scenario: result.scenario, runtime_code_bytes: result.runtime_code_bytes, persisted_through: quietTarget}));
      return;
    }
    await sleep(5000);
  }
  fs.writeFileSync(options.output, JSON.stringify({ok: false, quiet_target_block: quietTarget, drain}, null, 2) + '\n');
  throw new Error('state/trie persistence did not reach the drained workload within timeout');
}

async function main() {
  const {positionals, values: options} = parseArgs({allowPositionals: true, options:
    {...Object.fromEntries(['tempo', 'checkpoint-tool', 'a-datadir', 'b-datadir', 'phase', 'seconds', 'warmup-seconds', 'stop', 'output', 'report'].map(key => [key, {type: 'string'}])),
      'allow-first-sload-samples': {type: 'boolean'}}});
  assert.ok(['watch', 'audit', 'prime'].includes(positionals[0]));
  for (const key of ['tempo', 'a-datadir', 'b-datadir', 'phase', 'output']) assert.ok(options[key], `missing ${key}`);
  const bundledCheckpointTool = path.join(path.dirname(options.tempo), 'read_finish_checkpoint');
  options['checkpoint-tool'] ||= process.env.STATE_PATH_CHECKPOINT_TOOL ||
    (fs.existsSync(bundledCheckpointTool) ? bundledCheckpointTool : undefined);
  if (options['checkpoint-tool']) fs.accessSync(options['checkpoint-tool'], fs.constants.X_OK);
  if (positionals[0] === 'prime') await prime(options);
  else if (positionals[0] === 'watch') {
    assert.ok(Number(options.seconds) > 0 && Number(options.seconds) <= 3600 && options.stop);
    await watch(options);
  } else { assert.ok(options.report); await audit(options); }
}

module.exports = {frontier, checkpointCommand, parseIo, selectedMetrics, checkCalls, changedStorage, primed, selectTraceCandidates, validateHistorySamples};
if (require.main === module) main().catch(error => {console.error(error); process.exitCode = 1;});
