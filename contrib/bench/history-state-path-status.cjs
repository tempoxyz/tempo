'use strict';
const fs=require('node:fs'),path=require('node:path');
const suite=path.resolve(process.argv[2]);
const manifest=JSON.parse(fs.readFileSync(path.join(suite,'manifest.json')));
const now=Date.now(),status={suite,elapsed_seconds:(now-Date.parse(manifest.started_at))/1000,finished_cases:manifest.cases};
const candidates=fs.readdirSync('bench-results').filter(name=>/^20\d{6}-/.test(name)).sort().reverse();
for(const name of candidates) {
  const directory=path.join('bench-results',name);
  let config;
  try {config=JSON.parse(fs.readFileSync(path.join(directory,'summary-config.json')));}catch{continue;}
  if(!config.benchmark_id?.startsWith(path.basename(suite)+'-')) continue;
  status.current={directory,scenario:config.preset};
  const file=path.join(directory,'state-path-observer-feature-1.jsonl');
  if(fs.existsSync(file)) {
    const rows=fs.readFileSync(file,'utf8').split('\n').filter(Boolean).flatMap(line=>{try{return [JSON.parse(line)];}catch{return [];}});
    status.current.observer_elapsed_seconds=(rows.at(-1)?.unix_ms-rows[0]?.unix_ms)/1000;
    status.current.nodes={};
    for(const node of ['a','b']) {
      const points=rows.map(row=>row.nodes[node]).filter(row=>row?.metrics);
      const last=points.at(-1),first=points.find(row=>row.unix_ms>=last.unix_ms-60000);
      if(!last||!first) continue;
      const key=node==='a'?'reth_tempo_payload_builder_gas_used_sum':'reth_sync_execution_gas_processed_total';
      const gas=last.metrics[key]-first.metrics[key],seconds=(last.unix_ms-first.unix_ms)/1000;
      const checkpoint=points.filter(row=>row.persisted).at(-1);
      const device=last.database_device;
      const io=last.io?.[device]&&first.io?.[device]?Object.fromEntries(['rbytes','wbytes','rios','wios'].map(key=>[key,last.io[device][key]-first.io[device][key]])):null;
      status.current.nodes[node]={head:last.head,persisted:checkpoint?.persisted,sample_age_seconds:(now-last.unix_ms)/1000,
        checkpoint_error:last.checkpoint_error,provisional_last_minute_mgas_s:seconds>0?gas/seconds/1e6:null,
        provisional_io_per_mgas:gas>0&&io?Object.fromEntries(Object.entries(io).map(([key,value])=>[key,value/gas*1e6])):null};
    }
  }
  const audit=path.join(directory,'correctness-feature-1.json');
  if(fs.existsSync(audit)) {const result=JSON.parse(fs.readFileSync(audit));status.current.audit={ok:result.ok,persisted:result.persisted_through_workload,traces:result.traces};}
  break;
}
const exit=path.join(suite,'exit-code');if(fs.existsSync(exit)) status.exit_code=Number(fs.readFileSync(exit,'utf8'));
console.log(JSON.stringify(status,null,2));
