#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const readline = require('node:readline');
const {readTiming} = require('./state-path-timing.cjs');

const CACHE = 'reth_sync_caching_';
const BUILDER = 'reth_tempo_payload_builder_';
const EXEC = 'reth_sync_execution_';
const THREAD = 'reth_consensus_engine_beacon_new_payload_thread_';
const select = name => /^(reth_sync_caching_(storage|account|code)_cache_(hits|misses)|reth_sync_caching_txpool_snapshot_.*_(hits|misses)|reth_sync_execution_(gas_processed_total|execution_histogram_sum)|reth_consensus_engine_beacon_new_payload_thread_(major_page_faults|minor_page_faults|user_cpu_seconds|system_cpu_seconds)_sum|reth_tempo_payload_builder_(gas_used_sum|total_transactions_sum|parallel_transactions_executed_sum|reverted_transactions_sum|invalid_pool_transaction_execution_attempts_sum|payload_build_duration_seconds_sum|total_transaction_execution_duration_seconds_sum|normal_transaction_fill_idle_duration_seconds_sum|block_build_stop_total|pool_transactions_skipped_total)|reth_transaction_pool_(pending_pool_transactions|queued_pool_transactions|aa_2d_pending_transactions|aa_2d_queued_transactions|aa_2d_total_transactions)|reth_sync_prewarm_(transactions_histogram_sum|transaction_errors|execution_duration_sum|total_runtime_sum)|node_disk_(reads_completed_total|read_bytes_total)|node_vmstat_(pgmajfault|pswpin))$/.test(name);

const selectCoverage = name => /^(reth_consensus_engine_beacon_(pipeline_runs|new_payload_syncing)|reth_sync_total_elapsed)$/.test(name);
const selectWrites = name => /^node_disk_(writes_completed_total|written_bytes_total)$/.test(name);

function hasPipelineExecution(runs, seconds) {
  return (runs ?? 0) > 0 || (seconds ?? 0) > 0;
}

function seriesKey(name, labels) {
  return JSON.stringify([name, ...['node', 'source', 'reason', 'device', 'stage'].map(key => labels[key] || '')]);
}

async function loadSeries(filename) {
  const result = new Map();
  const lines = readline.createInterface({ input: fs.createReadStream(filename).pipe(zlib.createGunzip()), crlfDelay: Infinity });
  for await (const line of lines) {
    const name = /^\{"name":"([^"]+)"/.exec(line)?.[1];
    if (!name || (!select(name) && !selectCoverage(name) && !selectWrites(name))) continue;
    const sample = JSON.parse(line);
    const key = seriesKey(name, sample.labels);
    if (!result.has(key)) result.set(key, { name, labels: sample.labels, points: [] });
    result.get(key).points.push({ offset_ms: sample.offset_ms, unix_ms: sample.unix_ms, value: sample.value });
  }
  return result;
}

function counterWindow(points, from, to) {
  const window = points.filter(point => point.offset_ms >= from && point.offset_ms <= to);
  assert.ok(window.length >= 2, 'not enough counter samples');
  for (let i = 1; i < window.length; i++) {
    assert.ok(window[i].offset_ms > window[i - 1].offset_ms, 'unordered or duplicate samples');
    assert.ok(window[i].value >= window[i - 1].value, 'counter reset in measured window');
  }
  return { first: window[0], last: window.at(-1), delta: window.at(-1).value - window[0].value, samples: window.length };
}

function metricsWindow(series, node, from, to) {
  const source = node === 'a' ? 'builder' : 'engine';
  const optionalCoverage = [];
  function read(name, extra = {}, optional = false) {
    const entry = series.get(seriesKey(name, { node, ...extra }));
    if (!entry && optional) return null;
    assert.ok(entry, `missing metric ${name} ${node} ${JSON.stringify(extra)}`);
    if (optional && entry.points.filter(point => point.offset_ms >= from && point.offset_ms <= to).length < 2) {
      optionalCoverage.push({ metric: name, labels: extra, reason: 'fewer than two samples in this window' });
      return null;
    }
    return counterWindow(entry.points, from, to);
  }
  const gas = read(node === 'a' ? `${BUILDER}gas_used_sum` : `${EXEC}gas_processed_total`);
  assert.ok(gas.delta >= 0, 'negative executed gas');
  const deltas = {};
  function delta(name, extra = {}, optional = false) {
    const value = read(name, extra, optional);
    if (value === null) return null;
    if (optional && (value.first.offset_ms !== gas.first.offset_ms || value.last.offset_ms !== gas.last.offset_ms)) {
      optionalCoverage.push({ metric: name, labels: extra, reason: 'partial window; no zero baseline assumed', first_offset_ms: value.first.offset_ms, last_offset_ms: value.last.offset_ms });
      return null;
    }
    assert.equal(value.first.offset_ms, gas.first.offset_ms, `misaligned first sample ${name}`);
    assert.equal(value.last.offset_ms, gas.last.offset_ms, `misaligned last sample ${name}`);
    deltas[name + (extra.source ? `:${extra.source}` : '')] = value;
    return value.delta;
  }
  const misses = delta(`${CACHE}storage_cache_misses`, { source });
  const hits = delta(`${CACHE}storage_cache_hits`, { source });
  const execution = delta(node === 'a' ? `${BUILDER}total_transaction_execution_duration_seconds_sum` : `${EXEC}execution_histogram_sum`);
  const major = node === 'b' ? delta(`${THREAD}major_page_faults_sum`) : null;
  const minor = node === 'b' ? delta(`${THREAD}minor_page_faults_sum`) : null;
  const userCpu = node === 'b' ? delta(`${THREAD}user_cpu_seconds_sum`) : null;
  const systemCpu = node === 'b' ? delta(`${THREAD}system_cpu_seconds_sum`) : null;
  const build = node === 'a' ? delta(`${BUILDER}payload_build_duration_seconds_sum`) : null;
  const pipelineRuns = node === 'b' ? delta('reth_consensus_engine_beacon_pipeline_runs', {}, true) : null;
  const pipelineExecution = node === 'b' ? delta('reth_sync_total_elapsed', { stage: 'Execution' }, true) : null;
  const syncingPayloads = node === 'b' ? delta('reth_consensus_engine_beacon_new_payload_syncing', {}, true) : null;
  const unknownPipelineCoverage = node === 'b' && (pipelineRuns === null || optionalCoverage.some(item => item.metric === 'reth_sync_total_elapsed'));
  const mixedPaths = hasPipelineExecution(pipelineRuns, pipelineExecution) || unknownPipelineCoverage;
  // Downloaded blocks can also execute outside the new-payload resource guard.
  const incompleteFaultScope = mixedPaths || (node === 'b' && syncingPayloads === null) || (syncingPayloads ?? 0) > 0;
  const perMgas = value => value === null || gas.delta === 0 ? null : value / gas.delta * 1e6;
  const stopReasons = {};
  for (const entry of series.values()) {
    if (entry.name === `${BUILDER}block_build_stop_total` && entry.labels.node === node) {
      stopReasons[entry.labels.reason] = counterWindow(entry.points, from, to).delta;
    }
  }
  // Expiring-nonce transactions live in the AA2D pool, not the ordinary nonce pool.
  const pending = series.get(seriesKey('reth_transaction_pool_aa_2d_pending_transactions', { node }));
  const pendingValues = pending?.points.filter(point => point.offset_ms >= from && point.offset_ms <= to).map(point => point.value).sort((a,b) => a-b);
  const disk = {};
  for (const suffix of ['reads_completed_total', 'read_bytes_total', 'writes_completed_total', 'written_bytes_total']) {
    const entry = series.get(seriesKey(`node_disk_${suffix}`, { node: 'runner', device: node === 'a' ? 'nvme1n1' : 'nvme2n1' }));
    if (entry) {
      const measured = counterWindow(entry.points, from, to);
      assert.ok(Math.abs(measured.first.offset_ms - gas.first.offset_ms) < 1000, 'disk/engine scrape misalignment');
      assert.ok(Math.abs(measured.last.offset_ms - gas.last.offset_ms) < 1000, 'disk/engine scrape misalignment');
      disk[suffix] = measured.delta;
    }
  }
  const prewarm = {};
  for (const suffix of ['transactions_histogram_sum', 'transaction_errors', 'execution_duration_sum', 'total_runtime_sum']) {
    prewarm[suffix] = delta(`reth_sync_prewarm_${suffix}`, {}, true);
  }
  const otherCaches = {};
  for (const kind of ['account', 'code']) {
    const cacheMisses = delta(`${CACHE}${kind}_cache_misses`, {source}, true);
    const cacheHits = delta(`${CACHE}${kind}_cache_hits`, {source}, true);
    otherCaches[kind] = {misses: cacheMisses, hits: cacheHits, misses_per_mgas: mixedPaths ? null : perMgas(cacheMisses)};
  }
  return {
    node, source, from_offset_ms: gas.first.offset_ms, to_offset_ms: gas.last.offset_ms,
    duration_seconds: (gas.last.offset_ms - gas.first.offset_ms) / 1000,
    gas: gas.delta, gas_counter: gas,
    wall_clock_mgas_per_second: gas.delta / ((gas.last.offset_ms - gas.first.offset_ms) / 1000) / 1e6,
    other_caches: otherCaches,
    storage_misses: misses, storage_hits: hits,
    storage_misses_per_mgas: mixedPaths ? null : perMgas(misses), storage_miss_percent: misses + hits > 0 ? 100 * misses / (misses + hits) : null,
    execution_seconds: execution, execution_ms_per_mgas: gas.delta > 0 ? perMgas(execution) * 1000 : null,
    aggregate_execution_mgas_per_second: execution > 0 ? gas.delta / execution / 1e6 : null,
    payload_build_seconds: build, payload_build_ms_per_mgas: build === null || gas.delta === 0 ? null : perMgas(build) * 1000,
    major_faults: major, major_faults_per_mgas: incompleteFaultScope ? null : perMgas(major), minor_faults: minor,
    execution_coverage: { pipeline_runs: pipelineRuns, pipeline_execution_seconds: pipelineExecution, syncing_payloads: syncingPayloads, mixed_paths: mixedPaths, unknown_pipeline_coverage: unknownPipelineCoverage, engine_cache_ratio_suppressed: mixedPaths, payload_fault_ratio_suppressed: incompleteFaultScope },
    optional_metric_coverage: optionalCoverage,
    payload_thread_user_cpu_seconds: userCpu, payload_thread_system_cpu_seconds: systemCpu,
    builder_faults_not_measured: node === 'a',
    builder_reverted_transactions: node === 'a' ? delta(`${BUILDER}reverted_transactions_sum`) : null,
    invalid_execution_attempts: node === 'a' ? delta(`${BUILDER}invalid_pool_transaction_execution_attempts_sum`) : null,
    parallel_transactions_replayed: node === 'a' ? delta(`${BUILDER}parallel_transactions_executed_sum`, {}, true) : null,
    fill_idle_seconds: node === 'a' ? delta(`${BUILDER}normal_transaction_fill_idle_duration_seconds_sum`) : null,
    stop_reasons: stopReasons,
    pending_pool: pendingValues?.length ? { kind: 'aa_2d', min: pendingValues[0], median: pendingValues[Math.floor(pendingValues.length/2)], max: pendingValues.at(-1) } : null,
    prewarm,
    device_io: { ...disk, reads_per_mgas: perMgas(disk.reads_completed_total ?? null), bytes_per_gas: disk.read_bytes_total === undefined || gas.delta === 0 ? null : disk.read_bytes_total / gas.delta, writes_per_mgas: perMgas(disk.writes_completed_total ?? null), written_bytes_per_mgas: perMgas(disk.written_bytes_total ?? null), scope: 'device-wide, not execution-attributed' },
    counters: deltas,
  };
}

async function analyzeRun(directory, label, phase = 'feature-1') {
  assert.match(phase, /^(baseline|feature)-[1-9][0-9]*$/);
  const report = JSON.parse(fs.readFileSync(path.join(directory, `report-${phase}.json`)));
  const series = await loadSeries(path.join(directory, `report-${phase}.samples.ndjson.gz`));
  const correctnessPath = path.join(directory, `correctness-${phase}.json`);
  const correctness = fs.existsSync(correctnessPath) ? JSON.parse(fs.readFileSync(correctnessPath)) : null;
  const timing = readTiming(directory, report);
  const warmup = timing.from_ms, end = timing.to_ms;
  const hostVm = {};
  for (const name of ['node_vmstat_pgmajfault', 'node_vmstat_pswpin']) {
    const entry = series.get(seriesKey(name, { node: 'runner' }));
    if (entry) hostVm[name] = counterWindow(entry.points, warmup, end);
  }
  const result = {
    label, directory, scenario: report.metadata.scenario, metadata: report.metadata, timing,
    correctness, rpc_submissions: { sent: report.sent, accepted: report.success, failed: report.failed, not_execution_success: true },
    chain_stats_full_run: report.run_stats,
    host_vm: hostVm,
    builder: metricsWindow(series, 'a', warmup, end), follower: metricsWindow(series, 'b', warmup, end),
    trend: Array.from({ length: 5 }, (_, i) => ({
      from_seconds: (warmup + i * timing.slice_ms) / 1000,
      to_seconds: (warmup + (i + 1) * timing.slice_ms) / 1000,
      builder: metricsWindow(series, 'a', warmup + i*timing.slice_ms, warmup + (i+1)*timing.slice_ms),
      follower: metricsWindow(series, 'b', warmup + i*timing.slice_ms, warmup + (i+1)*timing.slice_ms),
    })),
  };
  fs.writeFileSync(path.join(directory, phase === 'feature-1' ? 'state-access-analysis.json' : `state-access-analysis-${phase}.json`), JSON.stringify(result, null, 2) + '\n');
  return result;
}

function markdown(runs, {historicalReference = false} = {}) {
  const fmt = value => value === null ? 'n/a' : value.toFixed(2);
  const lines = [
    '# State-access validation', '',
    (historicalReference
      ? 'The ordinary controls use a patched binary; the SLOAD reference is historical and unpatched. This is not a same-binary comparison. Database size is held fixed. '
      : 'Node revision and database size are held fixed. ') +
    'Each run uses its recorded duration and warmup exclusion. Rates use aligned cumulative-counter deltas, not arithmetic means of per-block throughput.', '',
    '| Case | Node | Storage misses/Mgas | Major faults/Mgas | Execution ms/Mgas | Cache miss % |',
    '| --- | --- | ---: | ---: | ---: | ---: |',
  ];
  for (const run of runs) for (const role of ['builder', 'follower']) {
    const m = run[role];
    lines.push(`| ${run.label} | ${role} | ${fmt(m.storage_misses_per_mgas)} | ${fmt(m.major_faults_per_mgas)} | ${fmt(m.execution_ms_per_mgas)} | ${fmt(m.storage_miss_percent)} |`);
  }
  lines.push('', '## Correctness and saturation', '');
  for (const run of runs) {
    const audit = run.correctness;
    const checkDescription = audit?.contract ? 'ordinary contract call/storage-diff checks passed (no opcode replay)' : 'transaction/access-set checks with parent-state opcode replay passed';
    lines.push(`- ${run.label}: ${audit?.ok ? `${audit.sampled_receipts} sampled receipts and ${audit.traces.length} ${checkDescription}` : audit ? 'correctness audit failed' : 'correctness audit not collected'}; builder reverted count ${run.builder.builder_reverted_transactions}; pending pool ${JSON.stringify(run.builder.pending_pool)}; stop reasons ${JSON.stringify(run.builder.stop_reasons)}.`);
    if (audit?.whole_report_cursor_check?.ok) {
      const cursor = audit.whole_report_cursor_check;
      lines.push(`- ${run.label} whole-window check: cursor advance equals all ${cursor.transactions} reported transactions across contiguous blocks ${cursor.first_block}-${cursor.last_block}.`);
    }
    if (run.host_vm.node_vmstat_pswpin) lines.push(`- ${run.label} host-wide swap-in counter delta: ${run.host_vm.node_vmstat_pswpin.delta} pages during the measured window (not attributed to either node).`);
    if (run.follower.execution_coverage.mixed_paths) lines.push(`- ${run.label} follower coverage warning: ${run.follower.execution_coverage.pipeline_runs} pipeline starts and ${fmt(run.follower.execution_coverage.pipeline_execution_seconds)} seconds of pipeline execution. Gas/time include mixed paths; engine-cache and payload-thread fault counters do not cover them all, so their per-gas ratios are suppressed. Cache miss percentage covers only observed engine-cache lookups.`);
    else if (run.follower.execution_coverage.payload_fault_ratio_suppressed) lines.push(`- ${run.label} follower fault coverage warning: ${run.follower.execution_coverage.syncing_payloads} payloads returned SYNCING. Downloaded-block execution can bypass the resource guard, so the fault/gas ratio is conservatively suppressed.`);
  }
  lines.push('', '## Measured-window stability', '', '| Case | Minutes | Follower faults/Mgas | Follower execution ms/Mgas | Builder execution ms/Mgas |', '| --- | --- | ---: | ---: | ---: |');
  for (const run of runs) for (const bucket of run.trend) lines.push(`| ${run.label} | ${bucket.from_seconds/60}-${bucket.to_seconds/60} | ${fmt(bucket.follower.major_faults_per_mgas)} | ${fmt(bucket.follower.execution_ms_per_mgas)} | ${fmt(bucket.builder.execution_ms_per_mgas)} |`);
  lines.push('', '## Interpretation limits', '',
    '- Major faults cover the follower payload-processing thread, not only SLOAD or every worker. The builder has no equivalent execution-thread counter in this run.',
    '- Pipeline catch-up shares the gas/time metrics but bypasses the payload-thread fault scope and engine cache. Intervals with pipeline starts or execution are not valid for those per-gas ratios.',
    '- The follower has no mempool ingress and disables builder prewarming/cache sharing. Engine payload prewarming remains a separate path. Judge the predictable control on the builder as well as the follower.',
    '- Ordinary contract controls have small active working sets; they do not establish cold-code or large-write-working-set behavior. Where included, the resident SLOAD control isolates active-working-set effects, not every workload difference.',
    '- A passing sampled audit does not prove every receipt succeeded. The all-build reverted counter and sampled receipts are reported independently.',
    '- Where opcode checks are reported, they use parent-state call replay matched to actual transaction prestate/call traces; replay wrapper gas is not used for normalization. Ordinary contract audits use real transaction call/storage-diff traces, not opcode replay.',
    '- Acceptance TPS is not executed TPS. A build-budget limit indicates builder saturation, not necessarily follower saturation.',
    '- A cold-SLOAD density bound is not a universal bound on physical I/O or execution time per gas.',
    '', 'Raw aligned counter endpoints and five equal-duration slices are saved in each run\'s state-access-analysis.json.', '');
  return lines.join('\n');
}

async function main() {
  const [suite, only] = process.argv.slice(2);
  assert.ok(suite, 'usage: analyze-state-access.cjs SUITE_DIR | RUN_DIR LABEL');
  if (only) {
    const result = await analyzeRun(suite, only);
    console.log(markdown([result]));
    return;
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(suite, 'manifest.json')));
  const runs = [];
  if (manifest.reference_results) runs.push(await analyzeRun(manifest.reference_results,
    manifest.build ? 'historical unpatched SLOAD reference' : 'original dependent'));
  for (const entry of manifest.cases) {
    assert.equal(entry.exit_code, 0, `run failed: ${entry.scenario}`);
    assert.ok(entry.results_dir, `missing results: ${entry.scenario}`);
    runs.push(await analyzeRun(entry.results_dir, entry.scenario));
  }
  fs.writeFileSync(path.join(suite, 'analysis.json'), JSON.stringify({ runs }, null, 2) + '\n');
  const report = markdown(runs, {historicalReference: Boolean(manifest.build && manifest.reference_results)});
  fs.writeFileSync(path.join(suite, 'validation.md'), report);
  console.log(report);
}

module.exports = { counterWindow, seriesKey, select, selectCoverage, selectWrites, hasPipelineExecution, metricsWindow, markdown, analyzeRun };
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
