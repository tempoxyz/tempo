'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {summarizeObserver, canonicalWindow, verifyBinaryProvenance} = require('./analyze-state-path-controls.cjs');
const {selectWrites} = require('./analyze-state-access.cjs');

function fixture() {
  const rows = Array.from({length: 41}, (_, i) => ({nodes: {a: {
    unix_ms: i * 5000, head: 100 + i, database_device: '259:0',
    metrics: {reth_tempo_payload_builder_gas_used_sum: 1000000 + i * 1000000},
    io: {'259:0': {rbytes: 100 + i * 4096, wbytes: 500 + i * 8192, rios: 10 + i, wios: 20 + 2 * i}},
    ...(i % 4 === 0 ? {persisted: {block: 95 + i, state: 90 + i}} : {})
  }}}));
  const measured = {gas_counter: {first: {unix_ms: 0}, last: {unix_ms: 200000}}};
  return {rows, measured};
}

test('patched controls must match the separately recorded binary hash', () => {
  const hash = 'a'.repeat(64);
  assert.equal(verifyBinaryProvenance({local_override: true, sha256: hash}, hash).sha256, hash);
  assert.throws(() => verifyBinaryProvenance({local_override: false, sha256: hash}, hash), /explicit local/);
  assert.throws(() => verifyBinaryProvenance({local_override: true, sha256: 'bad'}, hash), /SHA256/);
  assert.throws(() => verifyBinaryProvenance({local_override: true, sha256: hash}, 'b'.repeat(64)), /does not match/);
});

test('selects correct node-exporter disk write counters', () => {
  assert.equal(selectWrites('node_disk_written_bytes_total'), true);
  assert.equal(selectWrites('node_disk_writes_completed_total'), true);
  assert.equal(selectWrites('node_disk_write_bytes_total'), false);
});

test('canonical throughput sums gas in a half-open time window, not per-block rates', () => {
  const blocks = [0, 1, 2, 3].map(i => ({number: i, timestamp_ms: i * 1000, gas_used: 1000000, tx_count: 10}));
  const result = canonicalWindow(blocks, 1000, 3000);
  assert.equal(result.gas, '2000000');
  assert.equal(result.mgas_per_second, 1);
  assert.equal(result.transactions, 20);
  assert.throws(() => canonicalWindow([blocks[0], blocks[1], blocks[3]], 0, 3000), /contiguous/);
});

test('normalizes cgroup deltas with matching observer gas endpoints', () => {
  const {rows, measured} = fixture();
  const result = summarizeObserver(rows, 'a', measured);
  assert.equal(result.gas, 40000000);
  assert.equal(result.io.rbytes, 40 * 4096);
  assert.equal(result.io_per_mgas.rbytes, 4096);
  assert.equal(result.io_per_mgas.wbytes, 8192);
  assert.deepEqual(result.persistence_lag_blocks, {first: 10, last: 10, min: 10, median: 10, max: 10});
  assert.equal(result.backpressure_stall_seconds, null);
});

test('rejects gas and cgroup counter resets', () => {
  let {rows, measured} = fixture();
  rows[20].nodes.a.metrics.reth_tempo_payload_builder_gas_used_sum = 0;
  assert.throws(() => summarizeObserver(rows, 'a', measured), /reset/);
  ({rows, measured} = fixture());
  rows[20].nodes.a.io['259:0'].wbytes = 0;
  assert.throws(() => summarizeObserver(rows, 'a', measured), /reset/);
});

test('whole-node memory and I/O share gas endpoints; partial memory coverage fails', () => {
  const {rows, measured} = fixture();
  assert.equal(summarizeObserver(rows, 'a', measured).memory, null);
  for (const [i, row] of rows.entries()) row.nodes.a.memory = {
    pgfault: i * 20, pgmajfault: i * 2, workingset_refault_file: i * 5,
    file: 8192, file_mapped: 4096, file_dirty: 0, file_writeback: 0
  };
  const result = summarizeObserver(rows, 'a', measured);
  assert.equal(result.memory.per_mgas.pgmajfault, 2);
  assert.equal(result.memory.per_mgas.workingset_refault_file, 5);
  delete rows[20].nodes.a.memory;
  assert.throws(() => summarizeObserver(rows, 'a', measured), /memory coverage/);
});

test('rejects missing I/O or inadequate frontier coverage', () => {
  let {rows, measured} = fixture();
  delete rows[20].nodes.a.io;
  assert.throws(() => summarizeObserver(rows, 'a', measured), /missing cgroup/);
  ({rows, measured} = fixture());
  for (const row of rows) delete row.nodes.a.persisted;
  assert.throws(() => summarizeObserver(rows, 'a', measured), /frontier coverage/);
});

test('rejects non-advancing persistent state and truncated time coverage', () => {
  let {rows, measured} = fixture();
  for (const row of rows) if (row.nodes.a.persisted) row.nodes.a.persisted.state = 90;
  assert.throws(() => summarizeObserver(rows, 'a', measured), /did not advance/);
  ({rows, measured} = fixture());
  assert.throws(() => summarizeObserver(rows.slice(10), 'a', measured), /span/);
});
