'use strict';
const assert=require('node:assert/strict');
const COUNTERS=['pgfault','pgmajfault','workingset_refault_file'];
const GAUGES=['file','file_mapped','file_dirty','file_writeback'];
function parseMemory(text) {
  const result={};
  for(const line of text.trim().split('\n')) {
    const [key,value]=line.trim().split(/\s+/);
    if(![...COUNTERS,...GAUGES].includes(key)) continue;
    const number=Number(value);
    assert.ok(Number.isSafeInteger(number)&&number>=0,`invalid memory.stat ${key}`);
    assert.ok(!Object.hasOwn(result,key),`duplicate memory.stat ${key}`);
    result[key]=number;
  }
  for(const key of [...COUNTERS,...GAUGES]) assert.ok(Object.hasOwn(result,key),`missing memory.stat ${key}`);
  return result;
}
function summarizeMemory(points,gas) {
  if(points.every(point=>!point.memory)) return null;
  assert.ok(points.length>=2 && gas>=0,'insufficient memory/gas samples');
  for(let i=0;i<points.length;i++) for(const key of [...COUNTERS,...GAUGES]) {
    const value=points[i].memory?.[key];
    assert.ok(Number.isSafeInteger(value)&&value>=0,`missing/invalid memory coverage for ${key}`);
    if(i&&COUNTERS.includes(key)) assert.ok(value>=points[i-1].memory[key],`${key} reset`);
  }
  const first=points[0].memory,last=points.at(-1).memory;
  const deltas=Object.fromEntries(COUNTERS.map(key=>[key,last[key]-first[key]]));
  return {counters:deltas,per_mgas:Object.fromEntries(COUNTERS.map(key=>[key,gas>0?deltas[key]/gas*1e6:null])),
    gauges:Object.fromEntries(GAUGES.map(key=>[key,{first:first[key],last:last[key],max:Math.max(...points.map(point=>point.memory[key]))}])),
    scope:'Whole node cgroup memory.stat, including all execution paths, prewarming, trie and persistence threads. pgmajfault is not a count of unique pages, and pgfault includes anonymous/minor faults. File refaults are separate counters, not a cache-miss percentage.'};
}
module.exports={parseMemory,summarizeMemory};
