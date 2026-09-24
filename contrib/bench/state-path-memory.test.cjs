'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {parseMemory,summarizeMemory}=require('./state-path-memory.cjs');
const text='anon 4096\nfile 8192\nfile_mapped 4096\nfile_dirty 0\nfile_writeback 0\npgfault 100\npgmajfault 10\nworkingset_refault_file 20\n';
test('memory parser distinguishes fault counters from cache-size gauges',()=>{
  const parsed=parseMemory(text);
  assert.equal(parsed.pgmajfault,10);assert.equal(parsed.file,8192);assert.equal(parsed.anon,undefined);
  for(const broken of [text.replace('pgmajfault 10\n',''),text.replace('pgmajfault 10','pgmajfault NaN'),text+'pgfault 101\n']) assert.throws(()=>parseMemory(broken));
});
test('whole-node faults use aligned gas and allow cache gauges to shrink',()=>{
  const first=parseMemory(text),last={...first,file:4096,pgfault:150,pgmajfault:20,workingset_refault_file:50};
  const result=summarizeMemory([{memory:first},{memory:last}],2e6);
  assert.equal(result.per_mgas.pgmajfault,5);assert.equal(result.per_mgas.workingset_refault_file,15);
  assert.equal(result.gauges.file.last,4096);
  const idle=summarizeMemory([{memory:first},{memory:last}],0);
  assert.equal(idle.counters.pgmajfault,10);
  assert.equal(idle.per_mgas.pgmajfault,null);
});
test('memory summary rejects resets and partial coverage, but identifies older uninstrumented runs',()=>{
  const memory=parseMemory(text);
  assert.equal(summarizeMemory([{},{}],1e6),null);
  assert.throws(()=>summarizeMemory([{memory},{}],1e6));
  assert.throws(()=>summarizeMemory([{memory},{memory:{...memory,pgmajfault:0}}],1e6));
});
