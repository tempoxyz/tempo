'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { counterWindow, seriesKey, select, selectCoverage, hasPipelineExecution, metricsWindow, markdown } = require('./analyze-state-access.cjs');

test('labels patched controls against a historical reference without claiming a fixed binary', () => {
  const report = markdown([], {historicalReference: true});
  assert.match(report, /historical and unpatched/);
  assert.match(report, /not a same-binary comparison/);
  assert.doesNotMatch(report, /Node revision and database size are held fixed/);
  assert.match(markdown([]), /Node revision and database size are held fixed/);
});

test('uses counter deltas, not the sum of cumulative samples', () => {
  const points = [0, 5, 10, 15].map((t, i) => ({ offset_ms: t, value: 100 + i*10 }));
  assert.equal(counterWindow(points, 5, 15).delta, 20);
  assert.equal(counterWindow(points, 5, 15).first.offset_ms, 5);
});
test('rejects resets and duplicate scrapes', () => {
  assert.throws(() => counterWindow([{offset_ms:0,value:10},{offset_ms:1,value:0}],0,2), /reset/);
  assert.throws(() => counterWindow([{offset_ms:0,value:10},{offset_ms:0,value:11}],0,2), /duplicate/);
});
test('rejects insufficient coverage', () => assert.throws(() => counterWindow([],0,2), /samples/));
test('keeps execution sources and device counters separate', () => {
  assert.notEqual(seriesKey('cache', {node:'a',source:'builder'}),seriesKey('cache', {node:'b',source:'engine'}));
  assert.notEqual(seriesKey('reads', {device:'nvme1n1'}),seriesKey('reads', {device:'nvme2n1'}));
});
test('selects additive sums rather than histogram quantiles', () => {
  assert.ok(select('reth_consensus_engine_beacon_new_payload_thread_major_page_faults_sum'));
  assert.ok(!select('reth_consensus_engine_beacon_new_payload_thread_major_page_faults'));
  assert.ok(select('reth_sync_execution_execution_histogram_sum'));
  assert.ok(select('reth_transaction_pool_aa_2d_pending_transactions'));
});
test('detects pipeline work that invalidates payload-only normalization', () => {
  assert.ok(selectCoverage('reth_consensus_engine_beacon_pipeline_runs'));
  assert.ok(selectCoverage('reth_sync_total_elapsed'));
  assert.equal(hasPipelineExecution(0, 0), false);
  assert.equal(hasPipelineExecution(1, 0), true);
  assert.equal(hasPipelineExecution(0, 20), true);
  assert.notEqual(seriesKey('elapsed', {stage:'Execution'}), seriesKey('elapsed', {stage:'Bodies'}));
});
test('suppresses incomplete ratios but preserves raw counters and valid direct-path ratios', () => {
  const series = new Map();
  function add(name, delta, extra = {}) {
    const labels = { node: 'b', ...extra };
    series.set(seriesKey(name, labels), {name, labels, points: [{offset_ms:0,value:100}, {offset_ms:10000,value:100+delta}]});
  }
  add('reth_sync_execution_gas_processed_total', 1000);
  add('reth_sync_execution_execution_histogram_sum', 1);
  add('reth_sync_caching_storage_cache_misses', 10, {source:'engine'});
  add('reth_sync_caching_storage_cache_hits', 5, {source:'engine'});
  for (const suffix of ['major_page_faults', 'minor_page_faults', 'user_cpu_seconds', 'system_cpu_seconds']) {
    add(`reth_consensus_engine_beacon_new_payload_thread_${suffix}_sum`, 2);
  }
  add('reth_consensus_engine_beacon_pipeline_runs', 1);
  add('reth_sync_total_elapsed', 4, {stage:'Execution'});
  add('reth_consensus_engine_beacon_new_payload_syncing', 2);
  let measured = metricsWindow(series, 'b', 0, 10000);
  assert.equal(measured.storage_misses_per_mgas, null);
  assert.equal(measured.major_faults_per_mgas, null);
  assert.equal(measured.storage_misses, 10);
  assert.equal(measured.major_faults, 2);
  add('reth_consensus_engine_beacon_pipeline_runs', 0);
  add('reth_sync_total_elapsed', 0, {stage:'Execution'});
  measured = metricsWindow(series, 'b', 0, 10000);
  assert.equal(measured.storage_misses_per_mgas, 10000);
  assert.equal(measured.major_faults_per_mgas, null);
  add('reth_consensus_engine_beacon_new_payload_syncing', 0);
  assert.equal(metricsWindow(series, 'b', 0, 10000).major_faults_per_mgas, 2000);
  const lazyName = 'reth_sync_prewarm_transactions_histogram_sum';
  const lazyKey = seriesKey(lazyName, {node:'b'});
  series.set(lazyKey, {name:lazyName, labels:{node:'b'}, points:[{offset_ms:5000,value:12},{offset_ms:10000,value:20}]});
  measured = metricsWindow(series, 'b', 0, 10000);
  assert.equal(measured.prewarm.transactions_histogram_sum, null);
  assert.match(measured.optional_metric_coverage[0].reason, /partial window/);
  series.get(lazyKey).points = [{offset_ms:5000,value:12}];
  assert.equal(metricsWindow(series, 'b', 0, 10000).prewarm.transactions_histogram_sum, null);
  add('reth_sync_execution_gas_processed_total', 0);
  add('reth_sync_execution_execution_histogram_sum', 0);
  measured = metricsWindow(series, 'b', 0, 10000);
  assert.equal(measured.wall_clock_mgas_per_second, 0);
  assert.equal(measured.storage_misses, 10);
  assert.equal(measured.storage_misses_per_mgas, null);
  assert.equal(measured.execution_ms_per_mgas, null);
  assert.equal(measured.major_faults_per_mgas, null);
});
