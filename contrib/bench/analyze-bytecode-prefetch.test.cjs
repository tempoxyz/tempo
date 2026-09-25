'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const {prefetchWindow, readPrefetchRows} = require('./analyze-bytecode-prefetch.cjs');
const observer = {from_unix_ms: 10, to_unix_ms: 20};
const row = (time, enabled, requests = 0, errors = 0) => ({nodes: {a: {unix_ms: time, metrics: {
  reth_db_bytecode_prefetch_enabled: enabled, reth_db_bytecode_prefetch_requests: requests,
  reth_db_bytecode_prefetch_requests_rw: requests,
  reth_db_bytecode_prefetch_bytes: requests * 28672, reth_db_bytecode_prefetch_errors: errors,
}}}});
test('prefetch evidence uses only the observed window and counts hints, not I/O', () => {
  const result = prefetchWindow([row(0, 0), row(10, 1, 4), row(20, 1, 9), row(30, 1, 100)], 'a', observer, 1);
  assert.equal(result.requests, 5);
  assert.equal(result.hinted_bytes_per_request, 28672);
});
test('baseline can omit unregistered counters but must explicitly report disabled', () => {
  const rows = [10, 20].map(time => ({nodes: {a: {unix_ms: time, metrics: {reth_db_bytecode_prefetch_enabled: 0}}}}));
  assert.equal(prefetchWindow(rows, 'a', observer, 0).requests, 0);
  assert.throws(() => prefetchWindow(rows, 'a', observer, 1));
});
test('failed, unused, reset, or mismatched prefetch counters invalidate comparison', () => {
  assert.throws(() => prefetchWindow([row(10, 1, 4), row(20, 1, 9, 1)], 'a', observer, 1));
  assert.throws(() => prefetchWindow([row(10, 1, 4), row(20, 1, 4)], 'a', observer, 1));
  assert.throws(() => prefetchWindow([row(10, 1, 9), row(20, 1, 4)], 'a', observer, 1));
  assert.throws(() => prefetchWindow([row(10, 0), row(20, 1, 9)], 'a', observer, 1));
});

test('raw archive parsing normalizes the actual exporter prefix and separates nodes', async () => {
  const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), zlib = require('node:zlib');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'prefetch-metrics-test-'));
  try {
    const samples = [];
    for (const time of [10, 20]) for (const node of ['a', 'b']) {
      for (const [metric, value] of Object.entries(row(time, 1, time).nodes.a.metrics))
        samples.push({name: metric.replace(/^reth_/, 'reth_reth_'), labels: {node}, unix_ms: time, value});
    }
    const file = path.join(dir, 'samples.ndjson.gz');
    fs.writeFileSync(file, zlib.gzipSync(samples.map(JSON.stringify).join('\n') + '\n'));
    const rows = await readPrefetchRows(file);
    assert.equal(prefetchWindow(rows, 'a', observer, 1).requests, 10);
    assert.equal(prefetchWindow(rows, 'b', observer, 1).requests, 10);
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
