'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {analyzeRun}=require('../../contrib/bench/analyze-state-access.cjs');
const {summarizeMemory}=require('../../contrib/bench/state-path-memory.cjs');
const {summarizeDurability}=require('../../contrib/bench/state-path-durability.cjs');
const {checkMemory}=require('../../contrib/bench/run-sload-size-isolation.cjs');
const {fullWindow}=require('./full-window.cjs');
const root=__dirname, result='bench-results/20260925-141345-022';
const read=p=>JSON.parse(fs.readFileSync(p));
const write=(p,v)=>fs.writeFileSync(p,JSON.stringify(v,null,2)+'\n');
function canonical(blocks,from,to) {
  assert.ok(to>from);
  const selected=blocks.filter(b=>b.timestamp_ms>from && b.timestamp_ms<=to);
  const gas=selected.reduce((s,b)=>s+Number(b.gas_used),0);
  return {from_unix_ms:from,to_unix_ms:to,duration_seconds:(to-from)/1000,gas:String(gas),blocks:selected.length,
    transactions:selected.reduce((s,b)=>s+b.tx_count,0),mgas_per_second:gas/((to-from)/1000)/1e6,
    source:'Canonical gas in the fixed metric window. Empty time slices remain zero; no minimum-block filter.'};
}
function observerSummary(rows,node,window) {
  const from=window.from_unix_ms,to=window.to_unix_ms;
  const points=rows.map(r=>r.nodes[node]).filter(p=>p.unix_ms>=from && p.unix_ms<=to);
  assert.ok(points.length>=100);points.forEach(checkMemory);
  const first=points[0],last=points.at(-1),device=first.database_device;
  assert.ok(first.unix_ms-from<20000 && to-last.unix_ms<20000);
  const name=node==='a'?'reth_tempo_payload_builder_gas_used_sum':'reth_sync_execution_gas_processed_total';
  for(let i=0;i<points.length;i++) {
    const p=points[i];assert.equal(p.database_device,device);
    for(const key of ['rbytes','wbytes','rios','wios']) {
      assert.ok(Number.isSafeInteger(p.io[device][key]));
      if(i)assert.ok(p.io[device][key]>=points[i-1].io[device][key]);
    }
    assert.ok(Number.isFinite(p.metrics[name]));
    if(i){assert.ok(p.metrics[name]>=points[i-1].metrics[name]);assert.ok(p.head>=points[i-1].head);}
  }
  const gas=last.metrics[name]-first.metrics[name],seconds=(last.unix_ms-first.unix_ms)/1000;
  const io=Object.fromEntries(['rbytes','wbytes','rios','wios'].map(k=>[k,last.io[device][k]-first.io[device][k]]));
  const prefetch={};
  for(const k of ['requests','bytes','errors']) {
    const name='reth_db_bytecode_prefetch_'+k;
    prefetch[k]=Number.isFinite(first.metrics[name]) && Number.isFinite(last.metrics[name])
      ? last.metrics[name]-first.metrics[name] : null;
    if(prefetch[k]!==null)assert.ok(prefetch[k]>=0);
  }
  assert.equal(first.metrics.reth_db_bytecode_prefetch_enabled,1);assert.equal(last.metrics.reth_db_bytecode_prefetch_enabled,1);
  if(prefetch.errors!==null)assert.equal(prefetch.errors,0);
  const pending=points.map(p=>p.metrics.reth_transaction_pool_aa_2d_pending_transactions);
  return {from_unix_ms:first.unix_ms,to_unix_ms:last.unix_ms,duration_seconds:seconds,gas,device,io,
    io_per_mgas:Object.fromEntries(Object.entries(io).map(([k,v])=>[k,gas>0?v/gas*1e6:null])),
    read_MB_per_second:io.rbytes/seconds/1e6,read_requests_per_second:io.rios/seconds,
    memory:summarizeMemory(points,gas),head_first:first.head,head_last:last.head,prefetch,
    pending_min:Math.min(...pending),pending_max:Math.max(...pending),
    scope:'Whole-node database-device I/O, including unsuccessful proposals and prewarming. Sparse canonical denominator; not opcode-attributed cache misses.'};
}
async function main() {
  const previous=read(root+'/throughput.json'),experiment=read('bench-results/max-state-access-20260925-v4/experiment.json');
  assert.notEqual(experiment.status,'running');
  const sload=previous.runs.find(r=>r.workload==='sload');assert.ok(sload);
  assert.equal(previous.experiment.sha256,experiment.sha256);assert.deepEqual(previous.experiment.fixture,experiment.fixture);
  assert.deepEqual(previous.experiment.tools,experiment.tools);
  const audit=read(root+'/bytecode-sparse-audit.json');assert.ok(audit.ok && audit.exhaustive && audit.persisted_through_workload);
  const r=await analyzeRun(result,'bytecode-10800-sparse'),report=read(result+'/report-feature-1.json');
  assert.equal(r.timing.duration_seconds,1200);assert.equal(r.timing.warmup_seconds,600);
  assert.equal(r.scenario,'history_code_max');assert.equal(read(result+'/node-binary-feature.json').sha256,experiment.sha256);
  for(let i=1;i<report.blocks.length;i++)assert.equal(report.blocks[i].number,report.blocks[i-1].number+1);
  r.preflight=read(result+'/max-tx-preflight-feature-1.json');assert.ok(r.preflight.ok);
  assert.ok(read(result+'/state-path-priming-feature-1.json').ok);
  for(const side of ['a','b']) {
    checkMemory(experiment.runs[0].live_evidence.nodes[side]);
    const evict=read(`${result}/cache-eviction-feature-1-${side}.json`);
    assert.ok(evict.measurement.resident_after<=16 && !evict.file.includes('.virgin'));
  }
  for(const trace of audit.traces) {
    assert.equal(trace.accesses,10800);assert.ok(trace.actual_unique>=10692);assert.ok(trace.gas_cost_histogram[2603]>=10692);
    assert.equal(trace.history_advanced,false);
  }
  r.workload='bytecode';r.operations_per_transaction=10800;r.correctness=audit;r.sparse_outcome=true;
  r.full_window=await fullWindow(result,r);
  sload.full_window=await fullWindow(sload.directory,sload);
  sload.trimmed_scrape_canonical=sload.canonical;sload.canonical=sload.full_window.canonical;
  sload.gas_per_transaction=Number(sload.canonical.gas)/sload.canonical.transactions;
  const from=r.full_window.from_unix_ms,to=r.full_window.to_unix_ms;
  r.canonical=canonical(report.blocks,from,to);
  r.full_window_audited_transactions=audit.traces.filter(t=>report.blocks.some(b=>b.number===t.block && b.timestamp_ms>from && b.timestamp_ms<=to)).length;
  assert.equal(r.canonical.transactions,r.full_window_audited_transactions);
  r.gas_per_transaction=Number(r.canonical.gas)/r.canonical.transactions;
  r.operations_per_second=r.canonical.transactions*10800/r.canonical.duration_seconds;
  r.history={fraction:0,transactions:r.canonical.transactions,non_first_transactions:0,transactions_per_block:{1:r.canonical.blocks}};
  const rows=fs.readFileSync(result+'/state-path-observer-feature-1.jsonl','utf8').trim().split('\n').map(JSON.parse);
  const allBlocks=read(root+'/bytecode-canonical-backlog.json');
  r.observer={};r.durability={};r.isolation={};
  for(const [side,role]of [['a','builder'],['b','follower']]) {
    const o=observerSummary(rows,side,r.full_window);r.observer[side]=o;
    r.durability[side]=summarizeDurability(rows,side,allBlocks,o.from_unix_ms,o.to_unix_ms);
    const c=o.memory.gauges.file;r.isolation[side]={file_cache_first_gib:c.first/2**30,file_cache_last_gib:c.last/2**30};
  }
  const sloadRows=fs.readFileSync(path.join(sload.directory,'state-path-observer-feature-1.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
  const sloadBlocks=read(path.join(sload.directory,'report-feature-1.json')).blocks;
  sload.trimmed_scrape_observer=sload.observer;sload.observer={};
  for(const side of ['a','b']) {
    const o=observerSummary(sloadRows,side,sload.full_window);sload.observer[side]=o;
    sload.durability[side]=summarizeDurability(sloadRows,side,sloadBlocks,o.from_unix_ms,o.to_unix_ms);
    const c=o.memory.gauges.file;sload.isolation[side]={file_cache_first_gib:c.first/2**30,file_cache_last_gib:c.last/2**30};
  }
  for(const t of r.trend)t.canonical=canonical(report.blocks,t.builder.gas_counter.first.unix_ms,t.builder.gas_counter.last.unix_ms);
  const combinedExperiment={...previous.experiment,status:'complete-with-sparse-outcome',finished_at:new Date().toISOString(),
    runs:[previous.experiment.runs.find(e=>e.id==='sload'),{...experiment.runs[0],results_dir:result,status:'measured-sparse-audited',
      original_status:experiment.runs[0].status,exhaustive_audit:path.join(root,'bytecode-sparse-audit.json')}],
    limits:previous.experiment.limits+' Bytecode failed the ordinary minimum-receipt audit because production nearly stalled. All included transactions were audited afterward. Do not treat its completed-build rate as sustainable capacity.'};
  const runs=[sload,r];write(root+'/experiment.json',combinedExperiment);write(root+'/throughput.json',{experiment:combinedExperiment,runs});
  const f=n=>n==null?'n/a':n.toFixed(3);
  const lines=['# Near-cap state-access results','',
    '1200s offered load, first 600s excluded; same binary, populated fixture, 20 GiB/node with no swap, verified cold restores, prewarming and bytecode prefetch enabled.',
    '', '| Workload | Operations/tx | Gas/tx | Builder execution Mgas/s | Follower execution Mgas/s | Chain Mgas/s | Measured txs |',
    '| --- | ---: | ---: | ---: | ---: | ---: | ---: |'];
  for(const x of runs)lines.push(`| ${x.workload} | ${x.operations_per_transaction} | ${f(x.gas_per_transaction)} | ${f(x.full_window.builder.aggregate_execution_mgas_per_second)} | ${f(x.full_window.follower.aggregate_execution_mgas_per_second)} | ${f(x.canonical.mgas_per_second)} | ${x.canonical.transactions} |`);
  lines.push('','Bytecode is a near-stall/liveness result, not a clean steady-state execution throughput estimate. Its usual eight-receipt audit failed; the post-load exhaustive audit checked every included transaction. Successful-build metrics omit work canceled before metric recording. Both workloads have 0% within-block history eligibility at this size.','',
    '| Workload | Node | Read requests/Mgas | Read MB/Mgas | Major faults/Mgas | File cache first/last GiB | Follower durable Mgas/s |',
    '| --- | --- | ---: | ---: | ---: | --- | ---: |');
  for(const x of runs)for(const side of ['a','b']) {
    const o=x.observer[side],c=x.isolation[side];
    lines.push(`| ${x.workload} | ${side} | ${f(o.io_per_mgas.rios)} | ${f(o.io_per_mgas.rbytes/1e6)} | ${f(o.memory.per_mgas.pgmajfault)} | ${f(c.file_cache_first_gib)}/${f(c.file_cache_last_gib)} | ${side==='b'?f(x.durability.b.persisted_mgas_per_second):'n/a'} |`);
  }
  lines.push('','Whole-node reads include speculation, aborted proposals, trie work and persistence. Per-gas ratios have a very small included-gas denominator in bytecode; they are not unique misses per opcode. The durable frontier did not advance during the sparse bytecode window, but all included work reached both databases during post-load validation.','',
    'Timing correction: bench trimmed the raw scrape archive before the last included block, removing idle time. The headline uses the exact 600-second wall window reconstructed from complete node logs and canonical block timestamps; execution durations match the retained scrape counters exactly over their overlapping interval. In throughput.json, full_window contains these authoritative rates; builder/follower retain the original trimmed-scrape analysis for comparison. Observer I/O uses its aligned snapshots inside that full window.','',
    'Original manifests and logs retain their failures. SLOAD used an RPC-only nonce override to repair its post-load replay audit; the zero-transaction malformed-preset bytecode attempt is excluded. This report does not relabel those original runs as ordinary suite passes.','');
  fs.writeFileSync(root+'/throughput.md',lines.join('\n'));console.log(lines.slice(0,9).join('\n'));
}
main().catch(e=>{console.error(e);process.exitCode=1;});
