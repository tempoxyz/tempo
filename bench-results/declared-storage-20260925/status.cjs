'use strict';
const fs=require('node:fs'),path=require('node:path');
const archive=__dirname,root=path.resolve(archive,'../..'),stateFile=path.join(archive,'status-state.json');
function tail(file,size=400000){try{const fd=fs.openSync(file,'r'),length=fs.fstatSync(fd).size,buffer=Buffer.alloc(Math.min(size,length));fs.readSync(fd,buffer,0,buffer.length,length-buffer.length);fs.closeSync(fd);return buffer.toString();}catch{return '';}}
let state={offset:0,partial:'',log_tail:[]};try{state=JSON.parse(fs.readFileSync(stateFile));}catch{}
const fd=fs.openSync(path.join(archive,'run.log'),'r'),end=fs.fstatSync(fd).size;
while(state.offset<end){const buffer=Buffer.alloc(Math.min(1024*1024,end-state.offset));fs.readSync(fd,buffer,0,buffer.length,state.offset);state.offset+=buffer.length;
 const lines=(state.partial+buffer.toString()).split('\n');state.partial=lines.pop();
 for(const line of lines){if(!line.trim()||line.startsWith('[e2e-'))continue;const c=/=== State-access case: (\w+) ===/.exec(line),r=/BENCH_RESULTS_DIR=(\S+)/.exec(line);
  if(c){state.case=c[1];delete state.results;}if(r)state.results=r[1];state.log_tail.push(line);state.log_tail=state.log_tail.slice(-3);}}
fs.closeSync(fd);fs.writeFileSync(stateFile,JSON.stringify(state));
const experiment=JSON.parse(fs.readFileSync(path.join(archive,'experiment.json')));
const result={time:new Date().toISOString(),case:state.case,results:state.results,suite_status:JSON.parse(fs.readFileSync(path.join(experiment.suite_dir,'manifest.json'))).status,log_tail:state.log_tail};
if(state.results){const dir=path.resolve(root,state.results);let rows=tail(path.join(dir,'state-path-observer-feature-1.jsonl')).trim().split('\n').flatMap(line=>{try{return[JSON.parse(line)];}catch{return[];}});
 const post=tail(path.join(archive,'write-postload-observer.jsonl')).trim().split('\n').flatMap(line=>{try{return[JSON.parse(line)];}catch{return[];}});
 if(state.case==='writes'&&post.at(-1)?.unix_ms>(rows.at(-1)?.unix_ms||0))rows=post;
 if(rows.length){const row=rows.at(-1);result.observer={time:new Date(row.unix_ms).toISOString()};for(const node of ['a','b']){const x=row.nodes[node],persisted=rows.findLast(r=>r.nodes[node]?.persisted)?.nodes[node].persisted;
  result.observer[node]={head:x.head,state:persisted?.state,mem_gib:Number(x.memory_limits?.['memory.current'])/2**30,swap:x.memory_limits?.['memory.swap.current'],oom:x.memory_events?.oom,io:x.io?.[x.database_device],pending:x.metrics?.reth_transaction_pool_aa_2d_pending_transactions,error:x.error,checkpoint_error:x.checkpoint_error};}}
 const file=path.join(dir,'correctness-feature-1.json');if(fs.existsSync(file)){const c=JSON.parse(fs.readFileSync(file));result.correctness={ok:c.ok,traces:c.traces?.length,persisted:c.persisted_through_workload};}}
if(process.argv.includes('--brief')){const progress=/elapsed=([0-9.]+)s/.exec(state.log_tail.at(-1)||'');
 console.log(JSON.stringify({time:result.time,case:result.case,status:result.suite_status,load_seconds:progress?Math.round(Number(progress[1])):null,
 nodes:result.observer?Object.fromEntries(['a','b'].map(n=>{const x=result.observer[n];return[n,{head:x.head,persisted:x.state,memory_gib:Number(x.mem_gib.toFixed(2)),swap:x.swap,oom:x.oom,pending:x.pending}]})):null,
 last:progress?undefined:state.log_tail.at(-1),correctness:result.correctness}));
}else console.log(JSON.stringify(result,null,2));
