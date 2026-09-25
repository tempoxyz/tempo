'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {analyzeRun}=require('./analyze-state-access.cjs');
const {summarizeObserver,canonicalWindow,verifyBinaryProvenance}=require('./analyze-state-path-controls.cjs');
const {summarizeDurability}=require('./state-path-durability.cjs');
const {verifyCaseConfiguration}=require('./state-access-config.cjs');
async function main() {
  const suite=process.argv[2],manifest=JSON.parse(fs.readFileSync(path.join(suite,'manifest.json'))),runs=[];
  const registered=manifest.configuration.cases;
  const expected=registered?.map(c=>c.scenario) || ['history_write','history_code'];
  assert.deepEqual(manifest.cases.map(c=>c.scenario),expected,'missing, duplicated, or out-of-order requested workloads');
  for(const entry of manifest.cases) {
    assert.equal(entry.exit_code,0,`failed ${entry.scenario}`);
    const run=await analyzeRun(entry.results_dir,entry.scenario);
    assert.ok(run.correctness?.ok && run.correctness.persisted_through_workload,'audit/persistence incomplete');
    if(manifest.configuration.persistence_priming_required) {
      run.priming=JSON.parse(fs.readFileSync(path.join(entry.results_dir,'state-path-priming-feature-1.json')));
      assert.ok(run.priming.ok && run.priming.target_block>0,'pre-load persistence was not primed');
    }
    run.provenance=verifyBinaryProvenance(JSON.parse(fs.readFileSync(path.join(entry.results_dir,'node-binary-feature.json'))),manifest.build.binary_sha256);
    const rows=fs.readFileSync(path.join(entry.results_dir,'state-path-observer-feature-1.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
    run.observer={a:summarizeObserver(rows,'a',run.builder),b:summarizeObserver(rows,'b',run.follower)};
    if(manifest.configuration.whole_node_memory_required) for(const node of ['a','b'])
      assert.ok(run.observer[node].memory,'required whole-node fault coverage missing');
    const report=JSON.parse(fs.readFileSync(path.join(entry.results_dir,'report-feature-1.json')));
    if(registered) verifyCaseConfiguration(manifest,entry,
      JSON.parse(fs.readFileSync(path.join(entry.results_dir,'summary-config.json'))),report.metadata,run.correctness.fixture);
    run.canonical=canonicalWindow(report.blocks,run.follower.gas_counter.first.unix_ms,run.follower.gas_counter.last.unix_ms);
    run.durability=Object.fromEntries(['a','b'].map(node=>[node,summarizeDurability(rows,node,report.blocks,run.observer[node].from_unix_ms,run.observer[node].to_unix_ms)]));
    for(const slice of run.trend) slice.canonical=canonicalWindow(report.blocks,slice.follower.gas_counter.first.unix_ms,slice.follower.gas_counter.last.unix_ms);
    runs.push(run);
  }
  fs.writeFileSync(path.join(suite,'throughput.json'),JSON.stringify({manifest,runs},null,2)+'\n');
  const f=n=>n==null?'n/a':Number(n).toFixed(3);
  const lines=['# History-dependent state paths','',
    `Unique code corpus: ${manifest.fixture.code_count} x ${manifest.fixture.code_bytes} bytes. Original populated 100000 MiB storage import retained.`,
    `${manifest.configuration.duration}s load; ${manifest.configuration.warmup}s warmup excluded; no artificial transaction cap; prewarming unchanged.`,
    registered ? `Matched configuration: ${manifest.configuration.id}; ${manifest.configuration.tps} offered TPS; ${manifest.configuration.accounts} accounts; identical node binary and restored fixture verified.` : 'Historical two-case suite, not a matched SLOAD comparison.',
    '', 'Execution rates divide executed gas by instrumented execution time. Wall rates use elapsed time; chain gas counts canonical included transactions. Durable rates include state/trie persistence. Execution counters may include replays.',
    '', '| Case | Builder execution Mgas/s | Follower execution Mgas/s | Chain Mgas/s | Follower durable Mgas/s |',
    '| --- | ---: | ---: | ---: | ---: |'];
  for(const run of runs) lines.push(`| ${run.label} | ${f(run.builder.aggregate_execution_mgas_per_second)} | ${f(run.follower.aggregate_execution_mgas_per_second)} | ${f(run.canonical.mgas_per_second)} | ${f(run.durability.b.persisted_mgas_per_second)} |`);
  lines.push('', '| Case | Builder executed wall Mgas/s | Follower executed wall Mgas/s |', '| --- | ---: | ---: |');
  for(const run of runs) lines.push(`| ${run.label} | ${f(run.builder.wall_clock_mgas_per_second)} | ${f(run.follower.wall_clock_mgas_per_second)} |`);
  lines.push('','## Durable progress','',
    'Gas in canonical blocks crossed by each durable state/trie frontier, measured between frontier observations. Batched commits are stepwise. Backlog is relative to the producer, not the follower\'s potentially stale head. A growing backlog invalidates a sustainable producer-rate claim.',
    '', '| Case | Node | Durable Mgas/s | Producer-to-durable backlog first/last/max blocks | Backlog first/last Ggas |',
    '| --- | --- | ---: | --- | --- |');
  for(const run of runs) for(const node of ['a','b']) {
    const d=run.durability[node],b=d.producer_backlog_blocks,g=d.producer_backlog_gas;
    lines.push(`| ${run.label} | ${node} | ${f(d.persisted_mgas_per_second)} | ${b.first}/${b.last}/${b.max} | ${f(g.first/1e9)}/${f(g.last/1e9)} |`);
  }
  lines.push('','## Whole-node I/O','',
    '| Case | Node | Read I/Os/Mgas | Read bytes/Mgas | Write bytes/Mgas | Persistence lag first/last/max |',
    '| --- | --- | ---: | ---: | ---: | --- |');
  for(const run of runs) for(const node of ['a','b']) {
    const o=run.observer[node],lag=o.persistence_lag_blocks;
    lines.push(`| ${run.label} | ${node} | ${f(o.io_per_mgas.rios)} | ${f(o.io_per_mgas.rbytes)} | ${f(o.io_per_mgas.wbytes)} | ${lag.first}/${lag.last}/${lag.max} |`);
  }
  lines.push('','## Whole-node faults','',
    'Cgroup counters aligned with each node\'s executed-gas counter. These include prewarming, persistence and catch-up execution. Major faults and file refaults are not unique-page counts or cache-miss percentages.',
    '', '| Case | Node | Major faults/Mgas | File refaults/Mgas | File cache first/last GiB |',
    '| --- | --- | ---: | ---: | --- |');
  for(const run of runs) for(const node of ['a','b']) {
    const m=run.observer[node].memory;
    lines.push(`| ${run.label} | ${node} | ${f(m?.per_mgas.pgmajfault)} | ${f(m?.per_mgas.workingset_refault_file)} | ${f(m ? m.gauges.file.first / 2**30 : null)}/${f(m ? m.gauges.file.last / 2**30 : null)} |`);
  }
  lines.push('','## Validation','');
  for(const run of runs) {
    const audit=run.correctness;
    if (audit.measured_history_coverage) {
      const h=audit.measured_history_coverage;
      lines.push(`- ${run.label}: measured-window history coverage ${(100*h.fraction).toFixed(2)}% (${h.non_first_transactions}/${h.transactions}); required ${(100*h.minimum_required).toFixed(0)}%; transactions/block histogram ${JSON.stringify(h.transactions_per_block)}.`);
    }
    lines.push(`- ${run.label}: ${(audit.cursor_check.history_advanced_fraction * 100).toFixed(2)}% of all included workload transactions have a preceding transaction in their block; first transactions are not claimed to evade matching parent-state prewarming.`);
    lines.push(`- ${run.label}: ${audit.sampled_receipts} successful sampled receipts; ${audit.traces.length} actual access-set/opcode-replay checks; parent-state mismatch fractions ${audit.traces.map(t=>f(t.parent_state_mismatch_fraction)).join(', ')}; both persistence frontiers reached ${audit.quiet_target_block}.`);
    lines.push(`- ${run.label}: builder stop reasons ${JSON.stringify(run.builder.stop_reasons)}; pending pool ${JSON.stringify(run.builder.pending_pool)}; code-cache misses/Mgas (builder/follower) ${f(run.builder.other_caches.code.misses_per_mgas)}/${f(run.follower.other_caches.code.misses_per_mgas)}.`);
  }
  lines.push('','## Time slices','',
    '| Case | Load seconds | Canonical Mgas/s | Follower executed wall Mgas/s |',
    '| --- | --- | ---: | ---: |');
  for(const run of runs) for(const s of run.trend)
    lines.push(`| ${run.label} | ${s.from_seconds}-${s.to_seconds} | ${f(s.canonical.mgas_per_second)} | ${f(s.follower.wall_clock_mgas_per_second)} |`);
  lines.push('','## Limits','',
    '- Writes vary populated slots in the original single storage tree; bytecode reads vary account addresses. This is not a multi-account storage-write experiment.',
    '- Parent-state replay establishes the history dependency, not an instrumented record of every prewarm worker. Other transactions can warm overlapping targets; the first transaction can match.',
    '- Payload-thread fault/gas ratios are suppressed when catch-up bypasses their instrumentation. Whole-node cgroup faults and I/O have broader coverage, including prewarming for transactions that may never be included; I/Os are not individual cache misses.',
    '- Timed-load metrics exclude post-load traces. Durable catch-up verifies completion, not that delayed writes have no steady-state cost. Inspect lag and time slices.',
    '- Whole-node per-gas denominators are executed gas, which can include replays, not strictly finally charged canonical gas. Growing write backlog means the window ratios do not capture all eventual persistence work for that window.',
    '- Execution-only gas rate is not sustainable chain throughput. Both nodes share host RAM.',
    registered ? '- Only cases in this manifest form the matched comparison. Older results are historical. One run per workload does not establish variance, an asymptotic capacity, or a universal worst case.' : '- The archived original SLOAD result used a different unpatched binary; these results alone do not establish a same-binary ranking or a universal worst case.','');
  fs.writeFileSync(path.join(suite,'throughput.md'),lines.join('\n'));
  console.log(lines.join('\n'));
}
if(require.main===module) main().catch(error=>{console.error(error);process.exitCode=1;});
