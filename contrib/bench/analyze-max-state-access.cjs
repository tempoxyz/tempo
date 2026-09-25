#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {analyzeRun} = require('./analyze-state-access.cjs');
const {canonicalWindow, summarizeObserver} = require('./analyze-state-path-controls.cjs');
const {summarizeDurability} = require('./state-path-durability.cjs');
const {checkMemory} = require('./run-sload-size-isolation.cjs');
const read = p => JSON.parse(fs.readFileSync(p));
const f = n => n == null ? 'n/a' : n.toFixed(3);
async function analyze(output) {
  const experiment = read(path.join(output,'experiment.json'));
  assert.equal(experiment.kind,'near-cap-state-access-pair');
  const runs = [];
  for (const entry of experiment.runs.filter(e => e.status === 'complete' && e.results_dir)) {
    const suite = read(path.join(entry.directory,'manifest.json'));
    assert.equal(suite.status,'complete');
    assert.equal(suite.builds.feature.sha256,experiment.sha256);
    assert.deepEqual(suite.fixture,experiment.fixture);
    assert.equal(suite.options.feature_env,'RETH_BYTECODE_PREFETCH=1');
    assert.equal(suite.options.feature_args,'');
    assert.equal(suite.options.node_memory,'20G');
    assert.equal(suite.options.node_swap_limit,'0');
    assert.ok(entry.live_evidence);
    for (const node of ['a','b']) {
      checkMemory(entry.live_evidence.nodes[node]);
      const e=read(path.join(entry.results_dir,`cache-eviction-feature-1-${node}.json`));
      assert.ok(e.measurement.resident_after<=16 && !e.file.includes('.virgin'));
    }
    const r = await analyzeRun(entry.results_dir,entry.label);
    assert.equal(r.timing.duration_seconds,1200); assert.equal(r.timing.warmup_seconds,600);
    assert.equal(r.scenario,entry.scenario);
    assert.ok(r.correctness.ok && r.correctness.persisted_through_workload);
    assert.ok(read(path.join(entry.results_dir,'state-path-priming-feature-1.json')).ok);
    r.preflight=read(path.join(entry.results_dir,'max-tx-preflight-feature-1.json'));
    assert.ok(r.preflight.ok);
    assert.equal(r.builder.builder_reverted_transactions,0);
    assert.equal(r.builder.invalid_execution_attempts,0);
    assert.ok(r.correctness.traces.length>=3);
    for (const t of r.correctness.traces) {
      assert.equal(t.accesses,entry.reads);
      if(entry.id==='sload') {
        assert.equal(t.actual_unique,entry.reads);
        assert.deepEqual(t.gas_cost_histogram,{'2100':entry.reads});
      } else {
        assert.ok(t.actual_unique>=entry.reads*0.99);
        assert.ok(t.gas_cost_histogram[2603]>=entry.reads*0.99);
      }
    }
    for(const receipt of r.correctness.receipts) {
      const gas=Number(receipt.gas)/receipt.count;
      assert.ok(gas>=29700000 && gas<=30000000);
    }
    r.operations_per_transaction=entry.reads; r.workload=entry.id;
    r.history=r.correctness.measured_history_coverage;
    const rows=fs.readFileSync(path.join(entry.results_dir,'state-path-observer-feature-1.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
    const report=read(path.join(entry.results_dir,'report-feature-1.json'));
    r.observer={}; r.durability={}; r.isolation={};
    for (const [node,role] of [['a','builder'],['b','follower']]) {
      r.observer[node]=summarizeObserver(rows,node,r[role]);
      const o=r.observer[node];
      r.durability[node]=summarizeDurability(rows,node,report.blocks,o.from_unix_ms,o.to_unix_ms);
      const samples=rows.map(row=>row.nodes[node]).filter(s=>s.unix_ms>=o.from_unix_ms && s.unix_ms<=o.to_unix_ms);
      assert.ok(samples.length>=100); samples.forEach(checkMemory);
      r.isolation[node]={file_cache_first_gib:samples[0].memory.file/2**30,file_cache_last_gib:samples.at(-1).memory.file/2**30};
      const c=canonicalWindow(report.blocks,o.from_unix_ms,o.to_unix_ms);
      r.observer[node].aligned_canonical=c;
      r.observer[node].read_requests_per_canonical_access=o.io.rios/(c.transactions*entry.reads);
      r.observer[node].io_per_canonical_mgas=Object.fromEntries(Object.entries(o.io).map(([k,v])=>[k,v/Number(c.gas)*1e6]));
    }
    r.canonical=canonicalWindow(report.blocks,r.builder.gas_counter.first.unix_ms,r.builder.gas_counter.last.unix_ms);
    r.operations_per_second=r.canonical.transactions*entry.reads/r.canonical.duration_seconds;
    r.gas_per_transaction=Number(r.canonical.gas)/r.canonical.transactions;
    for(const slice of r.trend) slice.canonical=canonicalWindow(report.blocks,slice.builder.gas_counter.first.unix_ms,slice.builder.gas_counter.last.unix_ms);
    runs.push(r);
  }
  const lines=['# Near-cap state-access transactions','',`Status: ${experiment.status}; ${runs.length}/2 audited runs. 1200s load, first 600s excluded.`, '',
    `Same binary ${experiment.sha256}, fixture root ${experiment.fixture.state_root}, prewarming enabled and bytecode page prefetch enabled. Per-node limits 20 GiB/no swap, verified cold restores, fixed CPU/device roles.`, '',
    '| Workload | Operations/tx | Gas/tx | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s | Follower durable Mgas/s | Backlog first/last Ggas |',
    '| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |'];
  for(const r of runs) lines.push(`| ${r.workload} | ${r.operations_per_transaction} | ${f(r.gas_per_transaction)} | ${f(r.builder.aggregate_execution_mgas_per_second)} | ${f(r.follower.aggregate_execution_mgas_per_second)} | ${f(r.canonical.mgas_per_second)} | ${f(r.durability.b.persisted_mgas_per_second)} | ${f(r.durability.b.producer_backlog_gas.first/1e9)}/${f(r.durability.b.producer_backlog_gas.last/1e9)} |`);
  lines.push('','## Whole-node I/O','','| Workload | Node | Read requests/Mgas | Read MB/Mgas | Major faults/Mgas | File cache first/last GiB |','| --- | --- | ---: | ---: | ---: | --- |');
  for(const r of runs) for(const node of ['a','b']) {
    const o=r.observer[node], c=r.isolation[node];
    lines.push(`| ${r.workload} | ${node} | ${f(o.io_per_mgas.rios)} | ${f(o.io_per_mgas.rbytes/1e6)} | ${f(o.memory.per_mgas.pgmajfault)} | ${f(c.file_cache_first_gib)}/${f(c.file_cache_last_gib)} |`);
  }
  lines.push('','## Audits And Stability','');
  for(const r of runs) {
    lines.push(`### ${r.workload}`,'',`History eligibility ${(100*r.history.fraction).toFixed(3)}%; tx/block ${JSON.stringify(r.history.transactions_per_block)}. Sampling: ${JSON.stringify(r.correctness.trace_sampling)}. All sampled receipts succeeded near the 30M cap, access counts and populated targets passed, cursor reconciled ${r.correctness.cursor_check.transactions} transactions, both nodes durably caught up.`, '',
      `Follower execution coverage: ${JSON.stringify(r.follower.execution_coverage)}.`, '',
      '| Load seconds | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s |','| --- | ---: | ---: | ---: |');
    for(const s of r.trend) lines.push(`| ${s.from_seconds}-${s.to_seconds} | ${f(s.builder.aggregate_execution_mgas_per_second)} | ${f(s.follower.aggregate_execution_mgas_per_second)} | ${f(s.canonical.mgas_per_second)} |`);
    lines.push('');
  }
  lines.push('## Limits','','Near-cap transactions may occupy entire blocks; do not infer within-block bypass from workload design alone. Actual history eligibility is reported. Parent replays do not instrument prewarm workers. Whole-node I/O includes speculation, execution, trie and persistence; read requests are not unique cache misses. Execution-only throughput can include pipeline replay. Growing follower backlog means production throughput is not demonstrated sustainable end-to-end throughput. Equal memory caps do not reserve equal file cache. One sequential pair has no confidence interval. Random code draws can repeat; audited cold/unique fraction must exceed 99%.','');
  fs.writeFileSync(path.join(output,'throughput.json'),JSON.stringify({experiment,runs},null,2)+'\n');
  fs.writeFileSync(path.join(output,'throughput.md'),lines.join('\n'));
  console.log(lines.slice(0,8+runs.length).join('\n'));
  return runs;
}
module.exports={analyze};
if(require.main===module) analyze(path.resolve(process.argv[2])).catch(e=>{console.error(e);process.exitCode=1;});
