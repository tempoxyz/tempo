'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {analyzeRun} = require('../../contrib/bench/analyze-state-access.cjs');
const {canonicalWindow, summarizeObserver} = require('../../contrib/bench/analyze-state-path-controls.cjs');
const {summarizeDurability} = require('../../contrib/bench/state-path-durability.cjs');
const {measuredHistoryCoverage} = require('../../contrib/bench/history-state-path-validation.cjs');
const read = file => JSON.parse(fs.readFileSync(file));

async function main() {
  const suite = process.argv[2];
  assert.ok(suite, 'usage: node bench-results/sload-128-20260924-v2/analyze.cjs NATIVE_SUITE_DIR');
  const manifest = read(path.join(suite, 'manifest.json'));
  assert.equal(manifest.status, 'complete');
  assert.equal(manifest.cases.length, 1);
  assert.equal(manifest.cases[0].scenario, 'history_read');
  assert.equal(manifest.configuration.cases[0].operations_per_transaction, 128);
  assert.equal(manifest.configuration.cases[0].minimum_history_advanced_fraction, 0.9);
  assert.equal(manifest.configuration.duration, 1200);
  assert.equal(manifest.configuration.warmup, 600);
  assert.equal(manifest.options.feature_env, 'RETH_BYTECODE_PREFETCH=1');
  assert.equal(manifest.builds.feature.sha256, '5e4752f9d04cf152486487c6d4a33c91fa31011e6df9e7fa3760d0acd39b9f2d');
  const directory = manifest.cases[0].results_dir;
  const run = await analyzeRun(directory, 'SLOAD 128');
  assert.ok(run.correctness?.ok && run.correctness.persisted_through_workload);
  assert.ok(read(path.join(directory, 'state-path-priming-feature-1.json')).ok);
  assert.equal(run.builder.builder_reverted_transactions, 0);
  assert.equal(run.builder.invalid_execution_attempts, 0);
  for (const trace of run.correctness.traces) {
    assert.equal(trace.accesses, 128);
    assert.equal(trace.actual_unique, 128);
    assert.equal(trace.history_advanced, true);
    assert.equal(trace.overlap, 0);
    assert.deepEqual(trace.gas_cost_histogram, {'2100':128});
  }
  const rows = fs.readFileSync(path.join(directory, 'state-path-observer-feature-1.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
  const report = read(path.join(directory, 'report-feature-1.json'));
  run.observer = {};
  run.durability = {};
  for (const [node, role] of [['a','builder'], ['b','follower']]) {
    run.observer[node] = summarizeObserver(rows, node, run[role]);
    const o = run.observer[node];
    run.durability[node] = summarizeDurability(rows, node, report.blocks, o.from_unix_ms, o.to_unix_ms);
  }
  const from = run.builder.gas_counter.first.unix_ms, to = run.builder.gas_counter.last.unix_ms;
  run.canonical = canonicalWindow(report.blocks, from, to);
  run.history = measuredHistoryCoverage(report.blocks, run.timing, 0.9);
  assert.deepEqual(run.history, run.correctness.measured_history_coverage);
  for (const slice of run.trend) slice.canonical = canonicalWindow(report.blocks,
    slice.builder.gas_counter.first.unix_ms, slice.builder.gas_counter.last.unix_ms);
  const old = read('bench-results/state-access-bloat-20260924-122959-884/rerun-analysis.json').run;
  const bytecode = read('bench-results/bytecode-prefetch-e2e-20260924-v2/throughput.json').runs[1];
  assert.equal(run.metadata.node_commit_sha, bytecode.metadata.node_commit_sha);
  const f = n => n == null ? 'n/a' : n.toFixed(3);
  const lines = ['# 128-SLOAD history-dependent bloat rerun', '',
    '1,200-second load, 600-second excluded warmup, 1,000 offered TPS and 1,000 signers. Same archived node binary and prefetch setting as the bytecode-prefetch feature run. The router was extended; its hash and fixture state root changed, while both populated corpora were retained. Historical rows below are not an exact-fixture matched pair.', '',
    '| Workload | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s |',
    '| --- | ---: | ---: | ---: |'];
  for (const [label, r] of [['Original SLOAD 4096 (historical)', old], ['Bytecode + prefetch (historical)', bytecode], ['SLOAD 128', run]])
    lines.push(`| ${label} | ${f(r.builder.aggregate_execution_mgas_per_second)} | ${f(r.follower.aggregate_execution_mgas_per_second)} | ${f(r.canonical.mgas_per_second)} |`);
  lines.push('',
    `**The ${f(run.canonical.mgas_per_second)} Mgas/s production rate is not demonstrated sustainable end-to-end throughput.** The follower durably processed ${f(run.durability.b.persisted_mgas_per_second)} Mgas/s during the measured window, while its producer-to-durable backlog grew from ${f(run.durability.b.producer_backlog_gas.first/1e9)} to ${f(run.durability.b.producer_backlog_gas.last/1e9)} Ggas. Both nodes fully drained afterward; that catch-up is outside the timed load. Execution-only rates exclude non-execution wall time, and this single window's durable rate is not an asymptotic capacity estimate.`,
    '', '## History coverage and correctness', '',
    `Measured history coverage: ${(100*run.history.fraction).toFixed(2)}% (${run.history.non_first_transactions}/${run.history.transactions}), exceeding the required 90%.`,
    `Measured transactions/block histogram: ${JSON.stringify(run.history.transactions_per_block)}.`,
    `${run.correctness.traces.length} sampled non-first transactions each performed 128 unique, populated SLOADs charged 2,100 gas, with zero parent-state replay overlap. The cursor reconciles ${run.correctness.cursor_check.transactions} workload transactions and both nodes persisted through drained block ${run.correctness.quiet_target_block}.`,
    `Builder stops: ${JSON.stringify(run.builder.stop_reasons)}; pending pool: ${JSON.stringify(run.builder.pending_pool)}.`, '',
    '## Whole-node I/O and durability', '',
    '| Node | Read requests/Mgas | Read MB/Mgas | Major faults/Mgas | Durable Mgas/s | Backlog first/last Ggas |',
    '| --- | ---: | ---: | ---: | ---: | --- |');
  for (const node of ['a','b']) {
    const o = run.observer[node], d = run.durability[node];
    lines.push(`| ${node} | ${f(o.io_per_mgas.rios)} | ${f(o.io_per_mgas.rbytes/1e6)} | ${f(o.memory?.per_mgas.pgmajfault)} | ${f(d.persisted_mgas_per_second)} | ${f(d.producer_backlog_gas.first/1e9)}/${f(d.producer_backlog_gas.last/1e9)} |`);
  }
  lines.push('', '## Time slices', '', '| Load seconds | Builder execution Mgas/s | Follower execution Mgas/s | Chain Mgas/s |', '| --- | ---: | ---: | ---: |');
  for (const s of run.trend) lines.push(`| ${s.from_seconds}-${s.to_seconds} | ${f(s.builder.aggregate_execution_mgas_per_second)} | ${f(s.follower.aggregate_execution_mgas_per_second)} | ${f(s.canonical.mgas_per_second)} |`);
  lines.push('', '## Limits', '',
    'History coverage measures eligibility for the within-block bypass; replay validates sampled access-set divergence, not every actual prewarming worker. Whole-node I/O includes speculative work and persistence, not execution-only page misses. Gas throughput includes more per-transaction overhead than the old 4096-read workload. No global cache drop was performed and the nodes share RAM. A single run is not a confidence interval or proof of a universal worst case.', '',
    `Follower execution coverage: ${JSON.stringify(run.follower.execution_coverage)}.`, '',
    `Suite: ${suite}. Binary SHA256: ${manifest.builds.feature.sha256}.`, '');
  fs.writeFileSync(path.join(__dirname, 'throughput.json'), JSON.stringify({manifest, run}, null, 2)+'\n');
  fs.writeFileSync(path.join(__dirname, 'throughput.md'), lines.join('\n'));
  console.log(lines.join('\n'));
}
main().catch(error => {console.error(error);process.exitCode=1;});
