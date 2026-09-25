'use strict';
const fs=require('node:fs'),path=require('node:path');
const {readLogs,eventsFromLogs,summarize}=require('../../contrib/bench/analyze-state-access-latency.cjs');
(async()=>{
 const r=JSON.parse(fs.readFileSync(path.join(__dirname,'write-interim.json'))),seen=new Set();let skipped=0;
 const logs=(await readLogs(path.join(__dirname,'events-a.jsonl'))).filter(x=>Date.parse(x.timestamp)>=r.origin-15000&&Date.parse(x.timestamp)<=r.canonical.to_unix_ms+90000).filter(x=>{
  const f=x.fields||{},id=x.spans?.find(s=>s.name==='build_payload')?.id??x.span?.id,key=id+':'+f.tx_hash;
  if(f.message==='Bench transaction attempt started')seen.add(key);
  if(f.message==='Bench transaction attempt finished'&&!seen.has(key)){if(Date.parse(x.timestamp)>=r.canonical.from_unix_ms)throw Error('missing measured attempt start');++skipped;return false;}return true;
 });
 const out=summarize(eventsFromLogs(logs),r.canonical.from_unix_ms,r.canonical.to_unix_ms);out.skipped_pre_measurement_prefix_completions=skipped;
 fs.writeFileSync(path.join(__dirname,'write-latency.json'),JSON.stringify(out,null,2)+'\n');
 console.log(JSON.stringify({attempts:out.attempts_started,unfinished:out.attempts_unfinished,tx_evm:out.valid_attempt_execution,build:out.completed_nonempty_build_elapsed,cancelled:out.cancelled_jobs,jobs:out.proposal_jobs,skipped},null,2));
})().catch(e=>{console.error(e);process.exitCode=1;});
