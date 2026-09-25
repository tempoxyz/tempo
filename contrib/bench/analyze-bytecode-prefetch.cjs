#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const zlib = require('node:zlib');
const {analyzeRun} = require('./analyze-state-access.cjs');
const {canonicalWindow, summarizeObserver} = require('./analyze-state-path-controls.cjs');

async function readPrefetchRows(filename) {
  const rows = new Map();
  const lines = readline.createInterface({input: fs.createReadStream(filename).pipe(zlib.createGunzip()), crlfDelay: Infinity});
  for await (const line of lines) {
    if (!/^\{"name":"reth_(?:reth_)?db_bytecode_prefetch_/.test(line)) continue;
    const sample = JSON.parse(line);
    const node = sample.labels.node;
    if (!['a', 'b'].includes(node)) continue;
    const key = `${node}:${sample.unix_ms}`;
    if (!rows.has(key)) rows.set(key, {nodes: {[node]: {unix_ms: sample.unix_ms, metrics: {}}}});
    // This experimental binary explicitly included reth in names, and the
    // exporter prefixes them again. Retain the actual names in raw artifacts.
    const name = sample.name.replace(/^reth_reth_/, 'reth_');
    rows.get(key).nodes[node].metrics[name] = sample.value;
  }
  return [...rows.values()];
}

function prefetchWindow(rows, node, observer, enabled) {
  const points = rows.map(row => row.nodes[node]).filter(point => point?.unix_ms >= observer.from_unix_ms && point.unix_ms <= observer.to_unix_ms);
  assert.ok(points.length >= 2, 'insufficient prefetch evidence');
  const prefix = 'reth_db_bytecode_prefetch_';
  for (const point of points) assert.equal(point.metrics[prefix + 'enabled'], enabled, 'wrong prefetch mode');
  const result = {enabled};
  for (const key of ['requests', 'requests_rw', 'bytes', 'errors']) {
    const values = points.map(point => point.metrics[prefix + key] ?? (enabled ? NaN : 0));
    assert.ok(values.every(Number.isFinite), `missing prefetch ${key}`);
    for (let i = 1; i < values.length; ++i) assert.ok(values[i] >= values[i - 1], 'prefetch counter reset');
    result[key] = values.at(-1) - values[0];
  }
  assert.equal(result.errors, 0, 'prefetch advice failed');
  if (enabled) assert.ok(result.requests > 0, 'prefetch was never exercised');
  else assert.equal(result.requests, 0, 'baseline issued prefetch requests');
  result.hinted_bytes_per_request = result.requests ? result.bytes / result.requests : null;
  return result;
}

async function main(directory) {
  assert.ok(directory, 'usage: analyze-bytecode-prefetch.cjs EXPERIMENT_DIR');
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'experiment.json')));
  assert.equal(manifest.status, 'complete', 'experiment is incomplete');
  assert.deepEqual(manifest.runs.map(run => run.enabled), [0, 1]);
  const runs = [];
  for (const entry of manifest.runs) {
    const suite = JSON.parse(fs.readFileSync(path.join(entry.directory, 'manifest.json')));
    assert.equal(suite.status, 'complete');
    assert.equal(suite.builds.feature.sha256, manifest.sha256);
    assert.deepEqual(suite.fixture, manifest.fixture);
    const run = await analyzeRun(entry.results_dir, entry.label);
    assert.ok(run.correctness?.ok && run.correctness.persisted_through_workload, 'correctness/durability audit failed');
    if (runs.length) {
      assert.deepEqual(suite.configuration, runs[0].configuration, 'workload configuration changed');
      for (const key of ['node_commit_sha', 'bloat_mib', 'accounts', 'target_tps', 'run_duration_secs', 'scenario'])
        assert.equal(run.metadata[key], runs[0].metadata[key], `mismatched ${key}`);
    }
    run.configuration = suite.configuration;
    const rows = fs.readFileSync(path.join(entry.results_dir, 'state-path-observer-feature-1.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const prefetchRows = await readPrefetchRows(path.join(entry.results_dir, 'report-feature-1.samples.ndjson.gz'));
    run.observer = {};
    run.prefetch = {};
    for (const [node, role] of [['a', 'builder'], ['b', 'follower']]) {
      run.observer[node] = summarizeObserver(rows, node, run[role]);
      run.prefetch[node] = prefetchWindow(prefetchRows, node, {
        from_unix_ms: run[role].gas_counter.first.unix_ms,
        to_unix_ms: run[role].gas_counter.last.unix_ms,
      }, entry.enabled);
    }
    const report = JSON.parse(fs.readFileSync(path.join(entry.results_dir, 'report-feature-1.json')));
    const from = run.builder.gas_counter.first.unix_ms, to = run.builder.gas_counter.last.unix_ms;
    run.canonical = canonicalWindow(report.blocks, from, to);
    for (const slice of run.trend) slice.canonical = canonicalWindow(report.blocks,
      slice.builder.gas_counter.first.unix_ms, slice.builder.gas_counter.last.unix_ms);
    const blocks = report.blocks.filter(block => block.timestamp_ms > from && block.timestamp_ms <= to);
    run.history = {transactions: blocks.reduce((sum, block) => sum + block.tx_count, 0),
      after_first: blocks.reduce((sum, block) => sum + Math.max(0, block.tx_count - 1), 0)};
    run.history.after_first_fraction = run.history.after_first / run.history.transactions;
    runs.push(run);
  }
  const [baseline, prefetch] = runs;
  const ratio = (before, after) => after / before;
  const ratios = {
    builder_execution: ratio(baseline.builder.aggregate_execution_mgas_per_second, prefetch.builder.aggregate_execution_mgas_per_second),
    follower_execution: ratio(baseline.follower.aggregate_execution_mgas_per_second, prefetch.follower.aggregate_execution_mgas_per_second),
    chain: ratio(baseline.canonical.mgas_per_second, prefetch.canonical.mgas_per_second),
    builder_read_requests_per_gas: ratio(baseline.observer.a.io_per_mgas.rios, prefetch.observer.a.io_per_mgas.rios),
    follower_read_requests_per_gas: ratio(baseline.observer.b.io_per_mgas.rios, prefetch.observer.b.io_per_mgas.rios),
    builder_read_bytes_per_gas: ratio(baseline.observer.a.io_per_mgas.rbytes, prefetch.observer.a.io_per_mgas.rbytes),
    follower_read_bytes_per_gas: ratio(baseline.observer.b.io_per_mgas.rbytes, prefetch.observer.b.io_per_mgas.rbytes),
  };
  fs.writeFileSync(path.join(directory, 'throughput.json'), JSON.stringify({ratios, runs}, null, 2) + '\n');
  const lines = ['# Targeted bytecode prefetch: end-to-end A/B', '',
    'Same binary, fixture, offered load, CPU sets, and memory limits. Each phase restores its scratch databases, runs for 1,200 seconds, and excludes the first 600 seconds. General read-ahead remains disabled. One sequential baseline/feature pair, not replicated confidence intervals.', '',
    '| Metric | Baseline | Prefetch | Ratio |', '| --- | ---: | ---: | ---: |'];
  const add = (label, before, after) => lines.push(`| ${label} | ${before.toFixed(3)} | ${after.toFixed(3)} | ${(after / before).toFixed(3)}x |`);
  add('Builder execution Mgas/s', baseline.builder.aggregate_execution_mgas_per_second, prefetch.builder.aggregate_execution_mgas_per_second);
  add('Follower execution Mgas/s', baseline.follower.aggregate_execution_mgas_per_second, prefetch.follower.aggregate_execution_mgas_per_second);
  add('Chain Mgas/s', baseline.canonical.mgas_per_second, prefetch.canonical.mgas_per_second);
  for (const [node, role] of [['a', 'Builder'], ['b', 'Follower']]) {
    add(`${role} read requests/Mgas`, baseline.observer[node].io_per_mgas.rios, prefetch.observer[node].io_per_mgas.rios);
    add(`${role} read MB/Mgas`, baseline.observer[node].io_per_mgas.rbytes / 1e6, prefetch.observer[node].io_per_mgas.rbytes / 1e6);
  }
  lines.push('', 'I/O counters cover each whole node on its database device, including prewarming and persistence. Prefetch byte counters measure hinted ranges, not actual disk reads. Execution rates are gas divided by execution time, not sustainable chain rates.', '');
  for (const run of runs) lines.push(`- ${run.label}: ${(100 * run.history.after_first_fraction).toFixed(2)}% of reported measured transactions follow another transaction in their block; correctness and durable catch-up passed. Prefetch evidence: ${JSON.stringify(run.prefetch)}.`);
  lines.push('', '## Time Slices and Scope', '',
    'The headline uses the entire prespecified measured window, not the best slice. These two-minute slices expose cache redistribution and catch-up effects; they are not independent replications.', '',
    '| Mode | Load seconds | Builder execution Mgas/s | Follower execution Mgas/s | Chain Mgas/s |',
    '| --- | --- | ---: | ---: | ---: |');
  for (const run of runs) for (const slice of run.trend) lines.push(
    `| ${run.label} | ${slice.from_seconds}-${slice.to_seconds} | ${slice.builder.aggregate_execution_mgas_per_second.toFixed(3)} | ${slice.follower.aggregate_execution_mgas_per_second.toFixed(3)} | ${slice.canonical.mgas_per_second.toFixed(3)} |`);
  lines.push('',
    `Follower read-byte ratio: ${ratios.follower_read_bytes_per_gas.toFixed(3)}x. Reduced requests must not be described as reduced page-cache misses or bandwidth.`,
    `Follower pipeline coverage: baseline ${JSON.stringify(baseline.follower.execution_coverage)}; prefetch ${JSON.stringify(prefetch.follower.execution_coverage)}. The analyzer suppresses execution-thread fault/cache ratios when pipeline coverage differs.`,
    'The nodes share host RAM, so cache allocation can change during a run. Faster blocks also change the fraction of transactions with a predecessor. These are measured end-to-end effects, not a fixed-trace isolated-I/O comparison.', '');
  lines.push('', `Binary SHA256: ${manifest.sha256}.`, '');
  const markdown = lines.join('\n');
  fs.writeFileSync(path.join(directory, 'throughput.md'), markdown);
  console.log(markdown);
}

module.exports = {prefetchWindow, readPrefetchRows};
if (require.main === module) main(process.argv[2]).catch(error => {console.error(error); process.exitCode = 1;});
