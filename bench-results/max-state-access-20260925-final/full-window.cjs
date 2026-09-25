'use strict';
const fs=require('node:fs'),path=require('node:path'),readline=require('node:readline'),assert=require('node:assert/strict');
function seconds(value) {
  const m=/^(\d+(?:\.\d+)?)(ns|\u00b5s|ms|s)$/.exec(value||'');assert.ok(m,`bad duration ${value}`);
  return Number(m[1])*{ns:1e-9,'\u00b5s':1e-6,ms:1e-3,s:1}[m[2]];
}
function total(events,from,to) {
  const e=events.filter(e=>e.unix_ms>from && e.unix_ms<=to);
  const gas=e.reduce((s,e)=>s+e.gas,0),duration=e.reduce((s,e)=>s+e.execution_seconds,0);
  return {completed_events:e.length,gas,execution_seconds:duration,aggregate_execution_mgas_per_second:duration>0?gas/duration/1e6:null};
}
function canonical(blocks,from,to) {
  const selected=blocks.filter(b=>b.timestamp_ms>from && b.timestamp_ms<=to),gas=selected.reduce((s,b)=>s+Number(b.gas_used),0);
  return {from_unix_ms:from,to_unix_ms:to,duration_seconds:(to-from)/1000,gas:String(gas),blocks:selected.length,
    transactions:selected.reduce((s,b)=>s+b.tx_count,0),mgas_per_second:gas/((to-from)/1000)/1e6};
}
async function fullWindow(directory,run) {
  const report=JSON.parse(fs.readFileSync(path.join(directory,'report-feature-1.json')));
  const first=run.builder.gas_counter.first,origin=first.unix_ms-first.offset_ms;
  const from=origin+600000,to=origin+1200000;
  const events={builder:[],follower:[]},crossCheck={};
  for(const [side,role]of [['a','builder'],['b','follower']]) {
    for await(const line of readline.createInterface({input:fs.createReadStream(path.join(directory,`logs-feature-1-${side}/dev/reth.log`))})) {
      let x;try{x=JSON.parse(line);}catch{continue;}
      const message=x.fields?.message;
      if(role==='builder' && message==='Built payload')events[role].push({unix_ms:Date.parse(x.timestamp),number:x.fields.number,
        gas:x.fields.gas_used,execution_seconds:seconds(x.fields.total_transaction_execution_elapsed)});
      if(role==='follower' && message==='Executed block') {
        const unix_ms=Date.parse(x.timestamp);if(unix_ms<=from || unix_ms>to)continue;
        const number=Number(x.spans?.find(s=>s.block_num)?.block_num);
        const block=report.blocks.find(b=>b.number===number);
        assert.ok(block,`missing canonical gas for execution ${number}`);
        events[role].push({unix_ms,number,gas:Number(block.gas_used),execution_seconds:seconds(x.fields.elapsed)});
      }
    }
    const original=run[role],reconstructed=total(events[role],original.gas_counter.first.unix_ms,original.gas_counter.last.unix_ms);
    assert.equal(reconstructed.gas,original.gas,'logs do not match retained metric gas');
    assert.ok(Math.abs(reconstructed.execution_seconds-original.execution_seconds)<1e-5,'logs do not match retained metric duration');
    crossCheck[role]={original_gas:original.gas,original_execution_seconds:original.execution_seconds,reconstructed};
  }
  return {from_unix_ms:from,to_unix_ms:to,duration_seconds:600,origin_unix_ms:origin,
    builder:total(events.builder,from,to),follower:total(events.follower,from,to),canonical:canonical(report.blocks,from,to),
    trend:Array.from({length:5},(_,i)=>({from_seconds:600+i*120,to_seconds:720+i*120,
      builder:total(events.builder,from+i*120000,from+(i+1)*120000),follower:total(events.follower,from+i*120000,from+(i+1)*120000),
      canonical:canonical(report.blocks,from+i*120000,from+(i+1)*120000)})),
    cross_check_against_retained_scrapes:crossCheck,
    source:'Exact [load+600s, load+1200s] wall window. The bench scraper archive was trimmed before the final block; complete node logs restore execution timing and reported blocks restore canonical gas. Log durations equal the recorded metrics, verified over the retained interval. Canceled work is still excluded from completed-execution rates.'};
}
module.exports={fullWindow,canonical};
