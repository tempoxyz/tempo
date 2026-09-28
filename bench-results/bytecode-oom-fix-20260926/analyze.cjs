'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const {analyze} = require('../../contrib/bench/analyze-state-access-latency.cjs');
const read = file => JSON.parse(fs.readFileSync(file));
const lines = file => fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);

async function main() {
  const suite = read(path.join(__dirname, 'manifest.json'));
  assert.equal(suite.status, 'complete');
  const raw = path.resolve(__dirname, 'harness', suite.cases[0].results_dir);
  const analysis = await analyze(raw);
  const memory = lines(path.join(__dirname, 'memory-controls.jsonl'));
  const result = {raw, latency: analysis, memory: {}, guards: {}, follower_wall: {}};
  result.sync_injection = read(path.join(__dirname, 'sync-injection.json'));
  assert.ok(Date.parse(result.sync_injection.started_at) >= analysis.origin_unix_ms);
  assert.ok(Date.parse(result.sync_injection.resumed_at) < analysis.from_unix_ms,
    'fault injection must finish before measurement');
  for (const node of ['a', 'b']) {
    const samples = memory.map(row => row.nodes[node]);
    assert.equal(new Set(samples.map(s => s.pid)).size, 1, 'node restarted during validation');
    const events = samples.map(s => Object.fromEntries(s.memory_events.trim().split('\n').map(line => line.split(' '))));
    assert.ok(events.every(e => Number(e.oom_kill) === 0 && Number(e.oom) === 0));
    result.memory[node] = {samples: samples.length,
      max_sampled_anon_gib: Math.max(...samples.map(s => s.anon)) / 2 ** 30,
      cgroup_peak_gib: Math.max(...samples.map(s => s['memory.peak'])) / 2 ** 30,
      last_anon_gib: samples.at(-1).anon / 2 ** 30,
      last_file_gib: samples.at(-1).file / 2 ** 30,
      oom: 0, oom_kill: 0};
    const guards = [];
    for await (const line of readline.createInterface({input: fs.createReadStream(path.join(raw, `logs-feature-1-${node}/dev/reth.log`))})) {
      const row = JSON.parse(line);
      if (row.fields?.message === 'Committing execution batch at bytecode cache limit')
        guards.push({timestamp: row.timestamp, ...row.fields});
    }
    result.guards[node] = {count: guards.length, max_cached_bytecode_mib: guards.length ?
      Math.max(...guards.map(row => row.cached_bytecode_bytes)) / 2 ** 20 : null,
      first: guards[0], last: guards.at(-1)};
  }
  assert.ok(result.guards.b.count > 0, 'OOM-prone pipeline path was not exercised');
  const observer = lines(path.join(raw, 'state-path-observer-feature-1.jsonl'));
  const b = observer.map(row => row.nodes.b).filter(row => row.metrics);
  const first = b.find(row => row.unix_ms >= analysis.from_unix_ms);
  const last = b.findLast(row => row.unix_ms <= analysis.to_unix_ms);
  const gas = 'reth_sync_execution_gas_processed_total';
  result.follower_wall = {from_unix_ms: first.unix_ms, to_unix_ms: last.unix_ms,
    executed_mgas_per_wall_second: (last.metrics[gas] - first.metrics[gas]) / (last.unix_ms - first.unix_ms) / 1000,
    note: 'Execution gas counter over wall time, including pipeline work; not the normal engine execution-only rate.'};
  result.audit = read(path.join(raw, 'correctness-feature-1.json'));
  assert.equal(result.audit.ok, true);
  assert.equal(result.audit.persisted_through_workload, true);
  fs.writeFileSync(path.join(raw, 'latency-analysis.json'), JSON.stringify(analysis, null, 2) + '\n');
  fs.writeFileSync(path.join(__dirname, 'results.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({memory: result.memory, guards: result.guards,
    builder_mgas_s: analysis.completed_build_execution_mgas_per_second,
    chain_mgas_s: analysis.chain.mgas_per_second, follower_normal: analysis.follower,
    follower_wall: result.follower_wall, audit_ok: result.audit.ok}, null, 2));
}
main().catch(error => {console.error(error); process.exitCode = 1;});
