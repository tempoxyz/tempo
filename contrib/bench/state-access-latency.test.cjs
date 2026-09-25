'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const {execFileSync} = require('node:child_process');
const {resolveConfig} = require('./state-access-config.cjs');
const {eventsFromLogs,summarize} = require('./analyze-state-access-latency.cjs');
const {measuredHistoryCoverage} = require('./history-state-path-validation.cjs');
const {selectTraceCandidates,validateHistorySamples} = require('./state-path-observer.cjs');
test('sized presets keep the fixture signer mnemonic and valid fee-token address', () => {
  for (const scenario of ['history_read_sized','history_code_sized']) {
    const text = fs.readFileSync(path.join(__dirname,'txgen/presets',scenario+'.yml'),'utf8');
    assert.equal(/mnemonic: "([^"]+)"/.exec(text)[1],Array(11).fill('test').join(' ')+' junk');
    assert.equal(/fee_token: "([^"]+)"/.exec(text)[1],'0x20c0000000000000000000000000000000000000');
  }
});
test('sized configuration requires one bounded explicit case for overrides', () => {
  const file = path.join(__dirname,'configs/state-access-sized.json');
  assert.deepEqual(resolveConfig(file,[],{}).cases.map(c => c.operations_per_transaction),[7200,2250]);
  assert.equal(resolveConfig(file,['bytecode'],{},'3000').cases[0].operations_per_transaction,3000);
  for (const n of ['0','10801','-1','1.2']) assert.throws(() => resolveConfig(file,['bytecode'],{},n));
  assert.throws(() => resolveConfig(file,[],{},'3000'));
  assert.throws(() => resolveConfig(undefined,['sload'],{},'3000'));
});
test('native sized suite preserves cold-start controls and the exact requested count', () => {
  const plan = JSON.parse(execFileSync(process.env.NU_BIN || '/usr/local/bin/nu',
    ['--no-config-file','bench-e2e.nu','state-access-bloat-worst-case','--sized-transactions',
      '--case','bytecode','--accesses','2250','--dry-run'],{cwd:path.join(__dirname,'../..'),encoding:'utf8'}));
  assert.equal(plan.configuration.cases[0].scenario,'history_code_sized');
  assert.equal(plan.configuration.cases[0].operations_per_transaction,2250);
  assert.equal(plan.options.node_memory,'20G');
  assert.equal(plan.options.node_swap_limit,'0');
  assert.match(plan.options.feature_env,/RETH_BYTECODE_PREFETCH=1/);
});
test('attempt analysis includes canceled, boundary-crossing, invalid and unfinished work', () => {
  const log = (t,message,fields={},span={}) => ({timestamp:new Date(t).toISOString(),fields:{message,...fields},span});
  const events = eventsFromLogs([
    log(100,'New payload job created',{id:'a'}),
    log(110,'Bench transaction attempt started',{tx_hash:'tx',build_elapsed_us:10000},{id:'a'}),
    log(1300,'payload subscriber went away before the payload was resolved; killing the payload build',{}, {payload_id:'a'}),
    log(1610,'Bench transaction attempt finished',{tx_hash:'tx',execution_us:1500000,build_elapsed_us:1510000,cancelled:true,valid:true},{id:'a'}),
    log(200,'Bench transaction attempt started',{tx_hash:'pending',build_elapsed_us:0},{id:'b'}),
    log(300,'Bench transaction attempt started',{tx_hash:'invalid',build_elapsed_us:0},{id:'c'}),
    log(310,'Bench transaction attempt finished',{tx_hash:'invalid',execution_us:10000,build_elapsed_us:10000,cancelled:false,valid:false},{id:'c'}),
  ]);
  const result = summarize(events,0,1000);
  assert.equal(result.attempts_started,3);
  assert.equal(result.attempts_unfinished,1);
  assert.equal(result.valid_attempt_execution.p50_ms,1500);
  assert.equal(result.invalid_attempt_execution.count,1);
  assert.equal(result.cancelled_jobs,1);
  assert.equal(result.valid_attempts_on_cancelled_jobs,1);
  assert.equal(result.cancellation_after_job_creation.p50_ms,1200);
});
test('history coverage uses submission origin rather than delayed first inclusion', () => {
  const blocks = [{timestamp_ms:900,tx_count:1},{timestamp_ms:1500,tx_count:3}];
  assert.equal(measuredHistoryCoverage(blocks,{from_ms:500,to_ms:1000},0,0).transactions,1);
});
test('sized single-transaction blocks are audited without claiming history bypass', () => {
  const selection = selectTraceCandidates([{tx_count:1},{tx_count:1},{tx_count:1}],true,'history_code_sized');
  assert.equal(selection.policy,'sized-first-allowed');
  validateHistorySamples([{history_advanced:false}],selection.policy);
});
