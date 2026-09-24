#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {analyzeRun} = require('./analyze-state-access.cjs');
const {summarizeMemory} = require('./state-path-memory.cjs');

function canonicalWindow(blocks, from, to) {
  assert.ok(to > from);
  const selected = blocks.filter(block => block.timestamp_ms > from && block.timestamp_ms <= to);
  assert.ok(selected.length > 1, 'insufficient canonical blocks');
  for (let i = 1; i < selected.length; ++i) assert.equal(selected[i].number, selected[i - 1].number + 1, 'non-contiguous canonical report');
  const gas = selected.reduce((sum, block) => sum + BigInt(block.gas_used), 0n);
  assert.ok(gas <= BigInt(Number.MAX_SAFE_INTEGER));
  const seconds = (to - from) / 1000;
  return {from_unix_ms: from, to_unix_ms: to, duration_seconds: seconds,
    gas: gas.toString(), blocks: selected.length, transactions: selected.reduce((sum, block) => sum + block.tx_count, 0),
    mgas_per_second: Number(gas) / seconds / 1e6,
    source: 'Canonical reported blocks with timestamps in (start,end]; not submitted transactions or builder attempts.'};
}

function summarizeObserver(rows, node, measured) {
  const from = measured.gas_counter.first.unix_ms, to = measured.gas_counter.last.unix_ms;
  const points = rows.map(row => row.nodes[node]).filter(point => point?.unix_ms >= from && point.unix_ms <= to);
  assert.ok(points.length >= 20, `insufficient observer coverage for ${node}`);
  assert.ok(points[0].unix_ms - from < 20000 && to - points.at(-1).unix_ms < 20000, 'observer does not span the measured window');
  const frontiers = points.filter(point => point.persisted).map(point => ({unix_ms: point.unix_ms,
    head: point.head, block: point.persisted.block, state: point.persisted.state,
    lag: point.head - point.persisted.state}));
  assert.ok(frontiers.length >= 8, 'insufficient durable-frontier coverage');
  assert.ok(frontiers.at(-1).state > frontiers[0].state, 'durable state did not advance');
  const lag = frontiers.map(point => point.lag).sort((a, b) => a - b);
  const first = points[0], last = points.at(-1);
  const device = first.database_device;
  assert.ok(device && points.every(point => point.database_device === device), 'database device changed or missing');
  const gasName = node === 'a' ? 'reth_tempo_payload_builder_gas_used_sum' : 'reth_sync_execution_gas_processed_total';
  const keys = ['rbytes', 'wbytes', 'rios', 'wios'];
  for (let i = 0; i < points.length; ++i) {
    const point = points[i];
    assert.ok(Number.isFinite(point.metrics?.[gasName]), 'missing observer gas counter');
    if (i) assert.ok(point.metrics[gasName] >= points[i - 1].metrics[gasName], 'observer gas counter reset');
    for (const key of keys) {
      assert.ok(Number.isSafeInteger(point.io?.[device]?.[key]), `missing cgroup ${key}`);
      if (i) assert.ok(point.io[device][key] >= points[i - 1].io[device][key], `cgroup ${key} reset`);
    }
  }
  const gas = last.metrics[gasName] - first.metrics[gasName];
  assert.ok(gas >= 0, 'negative observed gas');
  const io = Object.fromEntries(keys.map(key => [key, last.io[device][key] - first.io[device][key]]));
  const stallKey = 'reth_consensus_engine_beacon_backpressure_stall_duration_sum';
  const stalls = Number.isFinite(first.metrics[stallKey]) && Number.isFinite(last.metrics[stallKey]) ? last.metrics[stallKey] - first.metrics[stallKey] : null;
  return {from_unix_ms: first.unix_ms, to_unix_ms: last.unix_ms, gas, device, io,
    memory: summarizeMemory(points, gas),
    io_per_mgas: Object.fromEntries(keys.map(key => [key, gas > 0 ? io[key] / gas * 1e6 : null])),
    persistence_frontiers: frontiers,
    persistence_lag_blocks: {first: frontiers[0].lag, last: frontiers.at(-1).lag, min: lag[0], median: lag[Math.floor(lag.length / 2)], max: lag.at(-1)},
    backpressure_stall_seconds: stalls,
    scope: 'Node cgroup, database device only; includes prewarming, trie/persistence, and other node work, not execution-only. Observer gas endpoints align with its I/O snapshots.'};
}

function markdown(runs) {
  const fmt = value => value === null || value === undefined ? 'n/a' :
    value !== 0 && Math.abs(value) < 0.01 ? value.toExponential(2) : value.toFixed(2);
  const hasReference = runs.some(run => run.label === 'SLOAD reference');
  const controls = runs.filter(run => run.label !== 'SLOAD reference');
  const first = controls[0];
  const lines = ['# Ordinary state-path throughput', '',
    (hasReference && runs.some(run => run.provenance?.local_override)
      ? 'The ordinary controls use a locally patched node; the SLOAD reference is historical and unpatched, not a same-binary comparison. '
      : 'The controls use the same recorded node binary. ') +
    `${Number(first?.metadata.bloat_mib) === 0 ? 'Fresh genesis, no imported state bloat.' : `${first?.metadata.bloat_mib} MiB of state bloat.`} ` +
    `${first?.timing.duration_seconds ?? 1200}-second loads; first ${first?.timing.warmup_seconds ?? 600} seconds excluded. ` +
    'The ordinary controls have small active working sets and do not test cache evasion or cold-code access. Stop reasons below determine whether the configured transaction cap limited each run.', '',
    '| Case | Canonical wall Mgas/s | Builder wall Mgas/s | Follower wall Mgas/s | Follower execution Mgas/s | Follower major faults/Mgas |',
    '| --- | ---: | ---: | ---: | ---: | ---: |'];
  for (const run of runs) lines.push(`| ${run.label} | ${fmt(run.canonical.mgas_per_second)} | ${fmt(run.builder.wall_clock_mgas_per_second)} | ${fmt(run.follower.wall_clock_mgas_per_second)} | ${fmt(run.follower.aggregate_execution_mgas_per_second)} | ${fmt(run.follower.major_faults_per_mgas)} |`);
  lines.push('', '## Scope and validation', '');
  for (const run of runs) {
    if (run.provenance) lines.push(`- ${run.label}: binary SHA256 ${run.provenance.sha256}; local override ${run.provenance.local_override}.`);
    lines.push(`- ${run.label}: builder stop reasons ${JSON.stringify(run.builder.stop_reasons)}; pending AA pool ${JSON.stringify(run.builder.pending_pool)}; reverted transactions ${run.builder.builder_reverted_transactions}; invalid attempts ${run.builder.invalid_execution_attempts}.`);
    lines.push(`- ${run.label}: builder code misses/Mgas ${fmt(run.builder.other_caches.code.misses_per_mgas)}; follower code misses/Mgas ${fmt(run.follower.other_caches.code.misses_per_mgas)}.`);
    if (run.correctness?.contract) lines.push(`- ${run.label}: deployed runtime ${run.correctness.runtime_code_bytes} bytes; ${run.correctness.sampled_receipts} sampled receipts succeeded; ${run.correctness.traces.length} real transaction call/storage-diff checks passed; both durable state/trie frontiers reached quiet block ${run.correctness.quiet_target_block}.`);
    if (run.follower.execution_coverage.payload_fault_ratio_suppressed) lines.push(`- ${run.label}: follower fault/gas comparison suppressed because its execution coverage includes or may include uninstrumented paths.`);
  }
  lines.push('', '## Node I/O and persistence', '',
    'These counters cover each whole node on its database device, including prewarming and persistence. They are not execution-thread counters.' +
    (hasReference ? ' The SLOAD reference has device-wide counters but no matching cgroup/frontier observer; do not equate these scopes.' : ''), '',
    '| Case | Node | Read bytes/Mgas | Write bytes/Mgas | Read I/Os/Mgas | Write I/Os/Mgas | State lag: first/last/max blocks |',
    '| --- | --- | ---: | ---: | ---: | ---: | --- |');
  for (const run of runs) if (run.observer) for (const node of ['a', 'b']) {
    const s = run.observer[node], io = s.io_per_mgas, lag = s.persistence_lag_blocks;
    lines.push(`| ${run.label} | ${node} | ${fmt(io.rbytes)} | ${fmt(io.wbytes)} | ${fmt(io.rios)} | ${fmt(io.wios)} | ${lag.first}/${lag.last}/${lag.max} |`);
  }
  lines.push('', '## Interpretation', '',
    '- Wall-clock throughput includes inter-block waiting and bottlenecks; execution-only throughput is not a sustainable chain-rate claim.',
    '- A transaction-cap-limited result is throughput under that cap, not maximum execution capacity.',
    '- No cache misses in ordinary resident controls would not invalidate the cold SLOAD benchmark or establish a worst case.',
    '- Durable catch-up after load establishes that included work reached persistence, not that every submitted transaction was included. Expiring-nonce submissions can expire.',
    '- Fault/gas counters cover the follower payload thread, not all trie and persistence workers. Node I/O counters cover a broader scope.',
    '- Post-load receipt/tracing checks can create reads. Their I/O is not counted in the measured load window or described as persistence-only I/O.',
    '- The two nodes share host RAM despite separate CPU sets and database devices.', '');
  return lines.join('\n');
}

function verifyBinaryProvenance(provenance, expectedHash) {
  assert.equal(provenance.local_override, true, 'patched run must use an explicit local binary');
  assert.match(provenance.sha256, /^[0-9a-f]{64}$/, 'invalid binary SHA256');
  assert.equal(provenance.sha256, expectedHash, 'binary does not match the recorded patched build');
  return provenance;
}

async function main() {
  const suite = process.argv[2];
  assert.ok(suite, 'usage: analyze-state-path-controls.cjs SUITE_DIR');
  const manifest = JSON.parse(fs.readFileSync(path.join(suite, 'manifest.json')));
  const runs = manifest.reference_results ? [await analyzeRun(manifest.reference_results, 'SLOAD reference')] : [];
  assert.ok(manifest.cases.length > 0, 'no cases');
  for (const entry of manifest.cases) {
    assert.equal(entry.exit_code, 0, `failed run ${entry.scenario}`);
    const run = await analyzeRun(entry.results_dir, entry.scenario);
    if (manifest.build) {
      run.provenance = verifyBinaryProvenance(
        JSON.parse(fs.readFileSync(path.join(entry.results_dir, 'node-binary-feature.json'))),
        manifest.build.binary_sha256);
    }
    assert.ok(run.correctness?.ok && run.correctness.persisted_through_workload);
    if (runs.length) for (const key of ['node_commit_sha', 'bloat_mib', 'accounts', 'target_tps', 'run_duration_secs']) assert.equal(run.metadata[key], runs[0].metadata[key], `mismatched ${key}`);
    if (manifest.configuration?.bloat_mib === 0) assert.equal(Number(run.metadata.bloat_mib), 0, 'clean suite unexpectedly used bloat');
    const rows = fs.readFileSync(path.join(entry.results_dir, 'state-path-observer-feature-1.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    run.observer = {a: summarizeObserver(rows, 'a', run.builder), b: summarizeObserver(rows, 'b', run.follower)};
    runs.push(run);
  }
  for (const run of runs) {
    const report = JSON.parse(fs.readFileSync(path.join(run.directory, 'report-feature-1.json')));
    run.canonical = canonicalWindow(report.blocks, run.follower.gas_counter.first.unix_ms, run.follower.gas_counter.last.unix_ms);
  }
  fs.writeFileSync(path.join(suite, 'throughput.json'), JSON.stringify({runs}, null, 2) + '\n');
  const text = markdown(runs);
  fs.writeFileSync(path.join(suite, 'throughput.md'), text);
  console.log(text);
}

module.exports = {summarizeObserver, canonicalWindow, markdown, verifyBinaryProvenance};
if (require.main === module) main().catch(error => {console.error(error); process.exitCode = 1;});
