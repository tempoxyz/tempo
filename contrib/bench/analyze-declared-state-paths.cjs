#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {analyzeRun} = require('./analyze-state-access.cjs');
const {canonicalWindow, summarizeObserver} = require('./analyze-state-path-controls.cjs');
const {summarizeDurability} = require('./state-path-durability.cjs');
const {loadOrigin} = require('./state-access-load-clock.cjs');
const {checkMemory} = require('./run-sload-size-isolation.cjs');
const read = file => JSON.parse(fs.readFileSync(file));

function slotsBetween(blocks, from, to, accesses) {
  const selected = blocks.filter(b => b.number > from && b.number <= to);
  assert.equal(selected.length, to - from, 'missing blocks in slot accounting');
  let count = 0;
  for (const [i, block] of selected.entries()) {
    assert.equal(block.number, from + i + 1);
    assert.ok(Number.isSafeInteger(block.tx_count) && block.tx_count >= 0);
    count += block.tx_count * accesses;
  }
  assert.ok(Number.isSafeInteger(count));
  return count;
}

function slotRate(slots, seconds) {
  assert.ok(Number.isSafeInteger(slots) && slots >= 0 && Number.isFinite(seconds) && seconds > 0);
  const rate = slots / seconds;
  return {slots, seconds, slots_per_second: rate,
    amortized_wall_ns_per_slot: rate > 0 ? 1e9 / rate : null};
}

function summarizeBackpressure(samples) {
  assert.ok(samples.length >= 2, 'insufficient backpressure samples');
  let activeMs = 0;
  for (let i = 1; i < samples.length; ++i) {
    const dt = samples[i].unix_ms - samples[i - 1].unix_ms;
    const active = samples[i - 1].metrics?.reth_consensus_engine_beacon_backpressure_active;
    assert.ok(dt > 0 && [0, 1].includes(active), 'invalid backpressure gauge or clock');
    activeMs += dt * active;
  }
  const ms = samples.at(-1).unix_ms - samples[0].unix_ms;
  return {observed_seconds: ms / 1000, estimated_active_seconds: activeMs / 1000,
    active_fraction: activeMs / ms, source: 'Time-weighted left-endpoint backpressure gauge; transitions have observer-sampling uncertainty.'};
}

async function analyze(directory) {
  const manifest = read(path.join(directory, 'manifest.json'));
  assert.equal(manifest.status, 'complete');
  assert.equal(manifest.configuration.id, 'state-access-declared');
  assert.equal(manifest.options.node_memory, '20G');
  assert.equal(manifest.options.node_swap_limit, '0');
  const runs = [];
  for (const entry of manifest.cases) {
    const workload = manifest.configuration.cases.find(c => c.scenario === entry.scenario);
    assert.ok(workload, 'unregistered declared case');
    const accesses = workload.operations_per_transaction;
    for (const side of ['baseline', 'feature']) {
      if (manifest.options.run_side !== 'comparison' && manifest.options.run_side !== side) continue;
      const provenance = read(path.join(entry.results_dir, `node-binary-${side}.json`));
      assert.equal(provenance.sha256, manifest.builds[side].sha256, 'binary drift');
      for (let pair = 1; pair <= manifest.options.run_pairs; ++pair) {
        const phase = `${side}-${pair}`;
        const r = await analyzeRun(entry.results_dir, `${entry.id}/${phase}`, phase);
        const report = read(path.join(entry.results_dir, `report-${phase}.json`));
        const preflight = read(path.join(entry.results_dir, `report-${phase}.declared-preflight.json`));
        assert.equal(preflight.ok, true);
        assert.equal(preflight.scenario, entry.scenario);
        assert.equal(preflight.accesses, accesses);
        for (const [key, expected] of Object.entries({scenario: entry.scenario, target_tps: manifest.configuration.tps,
          accounts: manifest.configuration.accounts, bloat_mib: manifest.configuration.fixture_requirements.bloat_mib,
          run_duration_secs: manifest.configuration.duration})) assert.equal(String(r.metadata[key]), String(expected), `configuration drift: ${key}`);
        assert.equal(r.timing.warmup_seconds, manifest.configuration.warmup);
        assert.ok(r.correctness?.ok && r.correctness.persisted_through_workload);
        assert.equal(r.correctness.scenario, entry.scenario);
        for (const key of ['state_root', 'router_code_hash', 'hashed_storage_entries'])
          assert.equal(r.correctness.fixture[key], manifest.fixture[key], `fixture drift: ${key}`);
        assert.ok(read(path.join(entry.results_dir, `state-path-priming-${phase}.json`)).ok);
        assert.equal(r.builder.builder_reverted_transactions, 0);
        assert.equal(r.builder.invalid_execution_attempts, 0);
        assert.ok(r.correctness.traces.length >= 3);
        for (const trace of r.correctness.traces) {
          assert.equal(trace.declared_slots, accesses);
          assert.equal(trace.accesses, accesses);
          assert.equal(trace.changed_contract_slots, entry.id === 'writes' ? accesses : 0);
          assert.deepEqual(trace.gas_cost_histogram.sload, {'100': accesses});
        }
        const origin = await loadOrigin(path.join(entry.results_dir, `report-${phase}.samples.ndjson.gz`));
        const from = origin + r.timing.from_ms, to = origin + r.timing.to_ms;
        // Use the entire configured measurement window, never shorten it to the
        // surviving counter archive or the last included transaction.
        r.canonical = canonicalWindow(report.blocks, from, to);
        r.slots = slotRate(r.canonical.transactions * accesses, (to - from) / 1000);
        r.existing_gas_per_slot = Number(r.canonical.gas) / r.slots.slots;
        r.accesses_per_transaction = accesses;
        r.provenance = provenance;
        r.generator_preflight = preflight;
        const rows = fs.readFileSync(path.join(entry.results_dir, `state-path-observer-${phase}.jsonl`), 'utf8').trim().split('\n').map(JSON.parse);
        r.observer = {}; r.durability = {};
        for (const [node, role] of [['a', 'builder'], ['b', 'follower']]) {
          const evidence = read(path.join(entry.results_dir, `cache-eviction-${phase}-${node}.json`));
          assert.ok(evidence.measurement.resident_after <= 16, 'restored file cache not evicted');
          assert.ok(!evidence.file.includes('.virgin'));
          const samples = rows.map(row => row.nodes[node]).filter(s => s?.unix_ms >= from && s.unix_ms <= to);
          assert.ok(samples.length >= 20 && samples[0].unix_ms - from < 20000 && to - samples.at(-1).unix_ms < 20000, 'observer does not cover full wall window');
          samples.forEach(checkMemory);
          r[role].backpressure = summarizeBackpressure(samples);
          r.observer[node] = summarizeObserver(rows, node, r[role]);
          const d = summarizeDurability(rows, node, report.blocks, from, to);
          d.slots = slotRate(slotsBetween(report.blocks, d.first_state, d.last_state, accesses), d.duration_seconds);
          const first = rows.map(row => row.nodes[node]).find(s => s?.unix_ms === d.from_unix_ms);
          const lastRow = rows.find(row => row.nodes[node]?.unix_ms === d.to_unix_ms);
          const firstRow = rows.find(row => row.nodes[node]?.unix_ms === first.unix_ms);
          d.backlog_slots = {first: slotsBetween(report.blocks, d.first_state, firstRow.nodes.a.head, accesses),
            last: slotsBetween(report.blocks, d.last_state, lastRow.nodes.a.head, accesses)};
          d.backlog_slots.growth = d.backlog_slots.last - d.backlog_slots.first;
          r.durability[node] = d;
        }
        for (const slice of r.trend) {
          slice.canonical = canonicalWindow(report.blocks, origin + slice.from_seconds * 1000, origin + slice.to_seconds * 1000, {allowSparse: true});
          slice.slots = slotRate(slice.canonical.transactions * accesses, slice.to_seconds - slice.from_seconds);
        }
        runs.push(r);
      }
    }
  }
  assert.ok(runs.length > 0);
  const f = n => n == null ? 'n/a' : n.toFixed(2);
  const lines = ['# Declared storage benchmark', '',
    'Slots are useful canonical operations, not gas counters, submissions, speculative attempts, or cache hits. A write slot includes one SLOAD plus one changed nonzero-to-nonzero SSTORE.', '',
    '| Case / phase | Slots/tx | Canonical slots/s | Canonical wall ns/slot | Builder durable slots/s | Follower durable slots/s | Follower backlog slots first/last |',
    '| --- | ---: | ---: | ---: | ---: | ---: | --- |'];
  for (const r of runs) lines.push(`| ${r.label} | ${r.accesses_per_transaction} | ${f(r.slots.slots_per_second)} | ${f(r.slots.amortized_wall_ns_per_slot)} | ${f(r.durability.a.slots.slots_per_second)} | ${f(r.durability.b.slots.slots_per_second)} | ${r.durability.b.backlog_slots.first}/${r.durability.b.backlog_slots.last} |`);
  lines.push('', 'The JSON retains builder/follower execution and prewarming counters, five time slices, database I/O, memory, durable frontiers, actual signed transaction traces, and tool/binary provenance.', '',
    'At 1 Ggas/s, one nanosecond corresponds numerically to one gas. The reported ns/slot includes transaction overhead, prewarming, execution, block cadence and other pipeline limits. It is an observed calibration input, not a recommended opcode price. Vary slots/transaction and offered load, check steady-state backlog and resource saturation, and repeat on reference hardware. Do not subtract write and read rates to infer an incremental SSTORE price.', '',
    'EIP-2930 marks slots warm for EVM gas accounting. Current speculative prewarming remains in use; this benchmark does not implement a direct access-list disk-prefetch scheduler. Warm opcodes do not prove cache residency. Growing durable backlog disqualifies canonical production as sustainable throughput; post-load drain alone does not fix that.', '');
  fs.writeFileSync(path.join(directory, 'declared-storage.json'), JSON.stringify({manifest, runs}, null, 2) + '\n');
  fs.writeFileSync(path.join(directory, 'declared-storage.md'), lines.join('\n'));
  console.log(lines.slice(0, 7 + runs.length).join('\n'));
  return runs;
}
module.exports = {slotsBetween, slotRate, summarizeBackpressure, analyze};
if (require.main === module) analyze(path.resolve(process.argv[2])).catch(error => {console.error(error); process.exitCode = 1;});
