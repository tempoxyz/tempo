'use strict';
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'../..');
const {analyze}=require(path.join(root,'contrib/bench/analyze-declared-state-paths.cjs'));
const {readLogs,eventsFromLogs,summarize}=require(path.join(root,'contrib/bench/analyze-state-access-latency.cjs'));
const {loadOrigin}=require(path.join(root,'contrib/bench/state-access-load-clock.cjs'));
async function main(){
 const experiment=JSON.parse(fs.readFileSync(path.join(__dirname,'experiment.json')));
 const runs=await analyze(experiment.suite_dir);
 for(const r of runs){
  const dir=r.directory;
  const origin=await loadOrigin(path.join(dir,'report-feature-1.samples.ndjson.gz'));
  const from=origin+r.timing.from_ms,to=origin+r.timing.to_ms;
  const capture=JSON.parse(fs.readFileSync(path.join(__dirname,'event-capture.json')));
  if(Date.parse(capture.started_at)>=from-5000)throw new Error('Timing capture did not precede the measured window');
  const seen=new Set();let prefixCompletions=0;
  const logs=(await readLogs(path.join(__dirname,'events-a.jsonl'))).filter(x=>Date.parse(x.timestamp)>=origin-15000&&Date.parse(x.timestamp)<=to+90000).filter(x=>{
   const f=x.fields||{},id=x.spans?.find(s=>s.name==='build_payload')?.id??x.span?.id,key=id+':'+f.tx_hash;
   if(f.message==='Bench transaction attempt started')seen.add(key);
   if(f.message==='Bench transaction attempt finished'&&!seen.has(key)){
    if(Date.parse(x.timestamp)>=from)throw new Error('Missing measured attempt start');
    ++prefixCompletions;return false;
   }return true;
  });
  r.latency=summarize(eventsFromLogs(logs),from,to);
  r.latency.capture={...capture,ignored_prefix_completions:prefixCompletions,source:path.join(__dirname,'events-a.jsonl')};
  fs.writeFileSync(path.join(dir,'declared-latency.json'),JSON.stringify(r.latency,null,2)+'\n');
  const observerFiles=[path.join(dir,'state-path-observer-feature-1.jsonl')];
  if(r.scenario==='declared_write')observerFiles.push(path.join(__dirname,'write-postload-observer.jsonl'));
  const observations=observerFiles.flatMap(file=>fs.readFileSync(file,'utf8').trim().split('\n').map(JSON.parse)).concat(r.correctness.drain||[]).sort((a,b)=>a.unix_ms-b.unix_ms);
  r.postload_durability={workload_end_block:r.correctness.workload_end_block,quiet_target_block:r.correctness.quiet_target_block,nodes:{}};
  for(const node of ['a','b']){
   const completed=observations.map(row=>row.nodes[node]).find(x=>x?.persisted?.state>=r.correctness.workload_end_block&&x.unix_ms>=to);
   if(!completed)throw new Error('Missing durable workload completion observation');
   r.postload_durability.nodes[node]={first_observed_unix_ms:completed.unix_ms,first_observed_state:completed.persisted.state,seconds_after_load_end:(completed.unix_ms-to)/1000};
  }
  r.postload_durability.source='First observer/checkpoint sample after load end whose durable state frontier covers the last reported block. Sampling delay is included; this is not a throughput denominator.';

 }
 experiment.status='complete';experiment.finished_at=new Date().toISOString();experiment.results=runs.map(r=>({scenario:r.scenario,directory:r.directory}));
 fs.writeFileSync(path.join(__dirname,'results.json'),JSON.stringify({experiment,runs},null,2)+'\n');
 const f=n=>n==null?'n/a':n.toLocaleString('en-US',{maximumFractionDigits:2});
 const lines=['# Declared read/write storage results','',
 'Both cases: 128 declared slots per native Tempo transaction, 1,000 offered TPS, 1,000 signers, 1,200 seconds of load with the first 600 seconds excluded. Uniform random 128-slot ranges over 1,638,395,904 populated storage slots. Fresh fixture restore per case; AMD EPYC 4585PX with eight physical cores and 20 GiB total memory/node, no swap, verified scratch-file cache eviction, separate builder/follower CPU sets and NVMe devices. Same instrumented node binary as the previous latency runs; prewarming remains enabled.','',
 '| Case | Canonical transactions/s | Useful slots/s | Whole-wall ns/slot | Builder durable slots/s | Follower durable slots/s | Follower backlog slots first → last |',
 '| --- | ---: | ---: | ---: | ---: | ---: | --- |'];
 for(const r of runs)lines.push(`| ${r.scenario} | ${f(r.canonical.transactions/r.canonical.duration_seconds)} | ${f(r.slots.slots_per_second)} | ${f(r.slots.amortized_wall_ns_per_slot)} | ${f(r.durability.a.slots.slots_per_second)} | ${f(r.durability.b.slots.slots_per_second)} | ${f(r.durability.b.backlog_slots.first)} → ${f(r.durability.b.backlog_slots.last)} |`);
 lines.push('','| Case | Builder transaction EVM p50 / p95 ms | Completed nonempty build p50 / p95 ms | Cancelled created payload jobs / jobs | Builder / follower backpressure active | Builder / follower read MB/s | Builder / follower write MB/s |','| --- | --- | --- | --- | --- | --- | --- |');
 for(const r of runs){const l=r.latency,io=(n,key='rbytes')=>r.observer[n].io[key]/((r.observer[n].to_unix_ms-r.observer[n].from_unix_ms)/1000)/1e6;
  lines.push(`| ${r.scenario} | ${f(l.valid_attempt_execution.p50_ms)} / ${f(l.valid_attempt_execution.p95_ms)} | ${f(l.completed_nonempty_build_elapsed.p50_ms)} / ${f(l.completed_nonempty_build_elapsed.p95_ms)} | ${l.cancelled_jobs} / ${l.proposal_jobs} | ${f(100*r.builder.backpressure.active_fraction)}% / ${f(100*r.follower.backpressure.active_fraction)}% | ${f(io('a'))} / ${f(io('b'))} | ${f(io('a','wbytes'))} / ${f(io('b','wbytes'))} |`);}
 lines.push('','| Case | Load minutes | Canonical slots/s |','| --- | --- | ---: |');
 for(const r of runs)for(const s of r.trend)lines.push(`| ${r.scenario} | ${s.from_seconds/60}–${s.to_seconds/60} | ${f(s.slots.slots_per_second)} |`);
 lines.push('','| Case | Builder / follower first observed durable through final reported block, seconds after load end |','| --- | --- |');
 for(const r of runs)lines.push(`| ${r.scenario} | ${f(r.postload_durability.nodes.a.seconds_after_load_end)} / ${f(r.postload_durability.nodes.b.seconds_after_load_end)} |`);
 lines.push('','Completion delays include observer sampling delay. The throughput tables above retain their original measurement windows.');
 lines.push('','At the 1 Ggas/s target, one nanosecond is numerically one gas. Whole-wall ns/slot is an observed pipeline budget including transaction overhead and cadence; it is not an isolated opcode cost or a recommended price. Write slots each include a read and a changed nonzero-to-nonzero write. New-slot creation, deletion/refunds, and multi-owner workloads are outside this experiment.','',
 'A growing durable backlog prevents interpreting canonical production as sustainable capacity. Endpoints also reflect commit batching, so inspect the five time slices and frontier series in results.json. One pass per case is not a worst-case bound or a confidence interval. The existing gas charges have not been repriced; their Mgas/s must not be confused with throughput under a future schedule.','',
 'The write follower entered pipeline catch-up. Its aggregate execution totals include that path; payload-thread fault counts and engine-cache counters do not cover all catch-up work and must not be normalized as if they did. Whole-node physical I/O and durable frontiers retain that work.','',
 'Cancellation counts cover created payload jobs. Consensus proposals may time out while waiting on a backpressured engine before a job is created; the backpressure gauge and whole-wall throughput capture that delay. EVM timing is per transaction; completed-build timing omits intervals in which no build can start.', '',
 'Correctness checks use included receipts, actual signed access lists and actual prestate/write diffs. The native AA opcode tracer emits empty logs; warmth is verified by replay using each transaction’s actual prestate and signed list, with matching returned output. EIP-2930 warmth is not proof of disk prefetch.','',
 `Node SHA256: ${experiment.tools.tempo}. Raw suite: ${experiment.suite_dir}. Exact binaries, sources, fixture metadata, command, and tool hashes are archived alongside this report.`, '');
 fs.writeFileSync(path.join(__dirname,'README.md'),lines.join('\n'));
 fs.writeFileSync(path.join(__dirname,'experiment.json'),JSON.stringify(experiment,null,2)+'\n');
 console.log(lines.slice(0,9).join('\n'));
}
main().catch(e=>{console.error(e);process.exitCode=1;});
