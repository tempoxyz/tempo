#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {analyzeRun} = require('./analyze-state-access.cjs');
const {canonicalWindow, summarizeObserver} = require('./analyze-state-path-controls.cjs');
const {summarizeDurability} = require('./state-path-durability.cjs');
const {checkMemory} = require('./run-sload-size-isolation.cjs');
const read = file => JSON.parse(fs.readFileSync(file));
const f = n => n == null ? 'n/a' : n.toFixed(3);

async function analyze(output) {
  const experiment = read(path.join(output, 'experiment.json'));
  const runs = [];
  for (const entry of experiment.runs.filter(entry => entry.status === 'complete' && entry.results_dir)) {
    const suite = read(path.join(entry.directory, 'manifest.json'));
    assert.equal(suite.status, 'complete');
    assert.equal(suite.builds.feature.sha256, experiment.sha256);
    assert.deepEqual(suite.fixture, experiment.fixture);
    assert.equal(suite.options.node_memory, '20G');
    assert.equal(suite.options.node_swap_limit, '0');
    assert.equal(suite.options.allow_first_sload_samples, entry.reads === 4096);
    assert.equal(suite.options.feature_env, 'RETH_BYTECODE_PREFETCH=1');
    assert.equal(suite.options.feature_args, entry.prewarming ? '' : '--builder.disable-prewarming --engine.disable-prewarming');
    for (const node of ['a', 'b']) {
      const evidence = read(path.join(entry.results_dir, `cache-eviction-feature-1-${node}.json`));
      assert.ok(evidence.measurement.resident_after <= 16, 'restored pages bypassed cgroup caps');
      assert.ok(!evidence.file.includes('.virgin'));
    }
    const r = await analyzeRun(entry.results_dir, entry.label);
    assert.equal(r.timing.duration_seconds, 1200);
    assert.equal(r.timing.warmup_seconds, 600);
    assert.ok(r.correctness.ok && r.correctness.persisted_through_workload);
    assert.ok(read(path.join(entry.results_dir, 'state-path-priming-feature-1.json')).ok);
    assert.equal(r.builder.builder_reverted_transactions, 0);
    assert.equal(r.builder.invalid_execution_attempts, 0);
    assert.ok(r.correctness.traces.length >= 3);
    for (const trace of r.correctness.traces) {
      assert.equal(trace.accesses, entry.reads);
      assert.equal(trace.actual_unique, entry.reads);
      assert.deepEqual(trace.gas_cost_histogram, {'2100': entry.reads});
      if (trace.history_advanced) assert.equal(trace.overlap, 0);
    }
    r.reads = entry.reads; r.prewarming_enabled = entry.prewarming;
    r.history = r.correctness.measured_history_coverage;
    if (entry.reads === 128) assert.ok(r.history.fraction >= 0.9);
    const rows = fs.readFileSync(path.join(entry.results_dir, 'state-path-observer-feature-1.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const report = read(path.join(entry.results_dir, 'report-feature-1.json'));
    r.observer = {}; r.durability = {}; r.isolation = {};
    for (const [node, role] of [['a','builder'], ['b','follower']]) {
      r.observer[node] = summarizeObserver(rows, node, r[role]);
      const o = r.observer[node];
      r.durability[node] = summarizeDurability(rows, node, report.blocks, o.from_unix_ms, o.to_unix_ms);
      const samples = rows.map(row => row.nodes[node]).filter(s => s.unix_ms >= o.from_unix_ms && s.unix_ms <= o.to_unix_ms);
      assert.ok(samples.length >= 100);
      samples.forEach(checkMemory);
      const files = samples.map(s => s.memory.file).sort((a,b) => a-b);
      r.isolation[node] = {samples: samples.length, file_gib: {
        first: samples[0].memory.file / 2 ** 30, last: samples.at(-1).memory.file / 2 ** 30,
        min: files[0] / 2 ** 30, max: files.at(-1) / 2 ** 30, median: files[Math.floor(files.length/2)] / 2 ** 30},
        memory_max: samples[0].memory_limits['memory.max'], swap_max: '0', oom: 0};
    }
    r.canonical = canonicalWindow(report.blocks, r.builder.gas_counter.first.unix_ms, r.builder.gas_counter.last.unix_ms);
    r.workload_reads_per_second = r.canonical.transactions * entry.reads / r.canonical.duration_seconds;
    r.gas_per_workload_read = Number(r.canonical.gas) / (r.canonical.transactions * entry.reads);
    r.builder_storage_misses_per_second = r.builder.storage_misses / r.builder.duration_seconds;
    for (const slice of r.trend) slice.canonical = canonicalWindow(report.blocks,
      slice.builder.gas_counter.first.unix_ms, slice.builder.gas_counter.last.unix_ms);
    runs.push(r);
  }
  const lines = ['# SLOAD transaction-size isolation', '',
    `Status: ${experiment.status}; ${runs.length}/4 completed cells. All rates below exclude 600 seconds of warmup from a 1,200-second load.`, '',
    `Same binary SHA256 ${experiment.sha256}, same fixture root ${experiment.fixture.state_root}, unchanged 100 GB populated storage corpus and code corpus, 1,000 offered TPS / 1,000 signers. Both nodes have a verified 20 GiB total-memory cap and no swap. Restored MDBX files are individually evicted and mincore-verified before startup; no global cache flush. CPU/device isolation is unchanged. Prefetch stays enabled in all cells.`, '',
    '| Reads/tx | Prewarming | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s | Canonical workload SLOAD/s | Follower durable Mgas/s | Follower backlog first/last Ggas |',
    '| ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |'];
  for (const r of runs) lines.push(`| ${r.reads} | ${r.prewarming_enabled ? 'on' : 'off'} | ${f(r.builder.aggregate_execution_mgas_per_second)} | ${f(r.follower.aggregate_execution_mgas_per_second)} | ${f(r.canonical.mgas_per_second)} | ${f(r.workload_reads_per_second)} | ${f(r.durability.b.persisted_mgas_per_second)} | ${f(r.durability.b.producer_backlog_gas.first/1e9)}/${f(r.durability.b.producer_backlog_gas.last/1e9)} |`);
  lines.push('', '## Cache and I/O', '',
    '| Cell | Node | File cache first/last GiB | File cache min/max GiB | Read requests/Mgas | Read MB/Mgas | Major faults/Mgas |',
    '| --- | --- | --- | --- | ---: | ---: | ---: |');
  for (const r of runs) for (const node of ['a','b']) {
    const c = r.isolation[node].file_gib, o = r.observer[node];
    lines.push(`| ${r.label} | ${node} | ${f(c.first)}/${f(c.last)} | ${f(c.min)}/${f(c.max)} | ${f(o.io_per_mgas.rios)} | ${f(o.io_per_mgas.rbytes/1e6)} | ${f(o.memory.per_mgas.pgmajfault)} |`);
  }
  lines.push('', '## Size effect', '');
  for (const enabled of [true, false]) {
    const small = runs.find(r => r.reads === 128 && r.prewarming_enabled === enabled);
    const big = runs.find(r => r.reads === 4096 && r.prewarming_enabled === enabled);
    if (!small || !big) continue;
    lines.push(`Prewarming ${enabled ? 'on' : 'off'}: small/large canonical gas throughput = ${f(small.canonical.mgas_per_second/big.canonical.mgas_per_second)}x; workload SLOAD/s = ${f(small.workload_reads_per_second/big.workload_reads_per_second)}x; gas per workload SLOAD = ${f(small.gas_per_workload_read/big.gas_per_workload_read)}x.`);
  }
  lines.push('', '## Correctness and time slices', '');
  for (const r of runs) {
    lines.push(`### ${r.label}`, '',
      `History eligibility ${(100*r.history.fraction).toFixed(2)}%; transactions/block ${JSON.stringify(r.history.transactions_per_block)}. Three cold-read traces passed; sampling policy ${JSON.stringify(r.correctness.trace_sampling)}. Cursor reconciled ${r.correctness.cursor_check.transactions} workload transactions; both nodes persisted through drain block ${r.correctness.quiet_target_block}.`, '',
      `Pipeline coverage: ${JSON.stringify(r.follower.execution_coverage)}.`, '',
      '| Load seconds | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s |', '| --- | ---: | ---: | ---: |');
    for (const s of r.trend) lines.push(`| ${s.from_seconds}-${s.to_seconds} | ${f(s.builder.aggregate_execution_mgas_per_second)} | ${f(s.follower.aggregate_execution_mgas_per_second)} | ${f(s.canonical.mgas_per_second)} |`);
    lines.push('');
  }
  lines.push('## Interpretation limits', '',
    'Production throughput is not sustainable end-to-end throughput if follower backlog grows. Execution-only rates exclude other work. A total-memory cap does not reserve identical file-cache bytes: heap usage and cache residency are recorded separately. Whole-node I/O includes prewarming, execution, trie and persistence; it is not direct opcode attribution. History eligibility plus sampled replay divergence does not instrument every actual prewarm worker. Sizes use separate entry points in the same router; full storage-domain coverage is retained. One sequential pass cannot provide confidence intervals or eliminate all time/order effects. Prewarming-off is a diagnostic control, not the production worst-case configuration.', '');
  fs.writeFileSync(path.join(output, 'throughput.json'), JSON.stringify({experiment, runs}, null, 2) + '\n');
  fs.writeFileSync(path.join(output, 'throughput.md'), lines.join('\n'));
  console.log(lines.slice(0, 9 + runs.length).join('\n'));
  return runs;
}
module.exports = {analyze};
if (require.main === module) analyze(path.resolve(process.argv[2])).catch(error => {console.error(error); process.exitCode = 1;});
