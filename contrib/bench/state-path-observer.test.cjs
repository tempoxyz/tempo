'use strict';

require('node:test')('pre-load priming requires both durable state/trie frontiers, not just advancing heads', () => {
  const assert = require('node:assert/strict');
  const {primed} = require('./state-path-observer.cjs');
  const sample = {nodes: {a: {head: 100, persisted: {block: 50, state: 20}}, b: {head: 100, persisted: {block: 50, state: 0}}}};
  assert.equal(primed(sample, 10), false);
  sample.nodes.b.persisted.state = 10;
  assert.equal(primed(sample, 10), true);
  assert.equal(primed(sample, 0), false);
  delete sample.nodes.a.persisted;
  assert.equal(primed(sample, 10), false);
});
const test = require('node:test');
const assert = require('node:assert/strict');
const {frontier, checkpointCommand, parseIo, selectedMetrics, checkCalls, changedStorage} = require('./state-path-observer.cjs');
const target = '0x5fbdb2315678afecb367f032d93f642f64180aa3';

test('direct checkpoint helper only opens the existing MDBX directory', () => {
  const options = {tempo: '/bin/tempo', 'a-datadir': '/bench/a', 'checkpoint-tool': '/bin/read_finish_checkpoint'};
  assert.deepEqual(checkpointCommand(options, 'a'), {file: '/bin/read_finish_checkpoint', args: ['/bench/a/db']});
  delete options['checkpoint-tool'];
  const fallback = checkpointCommand(options, 'a');
  assert.equal(fallback.file, '/bin/tempo');
  assert.ok(fallback.args.includes('StageCheckpoints'));
  assert.ok(fallback.args.includes('get'));
});

test('legacy and split Finish frontiers retain state lag', () => {
  assert.deepEqual(frontier({block_number: 100, stage_checkpoint: null}), {block: 100, state: 100});
  assert.deepEqual(frontier({block_number: 100, stage_checkpoint: {Finish: {partial_state_trie: 90}}}), {block: 100, state: 90});
  assert.throws(() => frontier({block_number: 100, stage_checkpoint: {Finish: {partial_state_trie: 101}}}));
  assert.throws(() => frontier({block_number: 100, stage_checkpoint: {Execution: {}}}));
});

test('I/O parsing preserves per-device counters', () => {
  assert.deepEqual(parseIo('259:3 rbytes=4096 wbytes=8192 rios=1 wios=2\n'), {'259:3': {rbytes: 4096, wbytes: 8192, rios: 1, wios: 2}});
  assert.deepEqual(parseIo(''), {});
  assert.throws(() => parseIo('259:3 rbytes=-1'));
});

test('metrics retain source labels and exclude unrelated histograms', () => {
  const values = selectedMetrics('reth_sync_caching_code_cache_misses{source="builder"} 2\nreth_sync_caching_code_cache_misses{source="engine"} 3\nreth_sync_execution_gas_processed_total 1e6\nother_metric 7\n');
  assert.equal(values['reth_sync_caching_code_cache_misses{source="builder"}'], 2);
  assert.equal(values['reth_sync_caching_code_cache_misses{source="engine"}'], 3);
  assert.equal(values.reth_sync_execution_gas_processed_total, 1000000);
  assert.equal(Object.keys(values).length, 3);
});

test('read audit checks all real getter calls and call success', () => {
  const trace = {calls: ['0x06fdde03', '0x95d89b41', '0x313ce567'].map(input => ({to: target, input, output: '0x01'}))};
  assert.equal(checkCalls(trace, false).length, 3);
  trace.calls[0].error = 'execution reverted';
  assert.throws(() => checkCalls(trace, false));
});

test('metrics preserve execution and completion progress separately', () => {
  const values = selectedMetrics('reth_tempo_payload_builder_total_transaction_execution_duration_seconds_count 187\nreth_tempo_payload_builder_payload_finalization_duration_seconds_count 186\nreth_tempo_payload_builder_sparse_trie_state_root_wait_duration_seconds_sum 2.5\n');
  assert.equal(values.reth_tempo_payload_builder_total_transaction_execution_duration_seconds_count, 187);
  assert.equal(values.reth_tempo_payload_builder_payload_finalization_duration_seconds_count, 186);
  assert.equal(values.reth_tempo_payload_builder_sparse_trie_state_root_wait_duration_seconds_sum, 2.5);
});

test('write audit checks ordinary spender, bounded amount, and return value', () => {
  const call = {to: target, input: '0x095ea7b3' + 'dead'.padStart(64, '0') + '64'.padStart(64, '0'), output: '0x01'};
  assert.deepEqual(checkCalls({calls: [call]}, true), ['0x095ea7b3']);
  assert.throws(() => checkCalls({calls: [{...call, output: '0x00'}]}, true));
  assert.throws(() => checkCalls({calls: [{...call, input: '0x095ea7b3' + 'dead'.padStart(64, '0') + '0'.repeat(64)}]}, true));
});

test('storage diff distinguishes actual contract writes from fee-account writes', () => {
  assert.deepEqual(changedStorage({pre: {}, post: {'0x123': {storage: {'0x0': '0x1'}}}}), []);
  assert.deepEqual(changedStorage({pre: {[target]: {storage: {'0x0': '0x1'}}}, post: {[target]: {storage: {'0x0': '0x2'}}}}), ['0x0']);
  assert.deepEqual(changedStorage({pre: {[target]: {storage: {'0x0': '0x1'}}}, post: {[target]: {storage: {'0x0': '0x01'}}}}), []);
});
