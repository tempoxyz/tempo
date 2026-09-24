'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const {gasBetween, summarizeDurability} = require('./state-path-durability.cjs');
const blocks = Array.from({length: 31}, (_, number) => ({number, gas_used: 1000000}));
function fixture() {
  return [5,10,12].map((state,i)=>({nodes:{a:{head:10+i*10},b:{unix_ms:i*10000,persisted:{state}}}}));
}
test('durable gas and backlog use canonical included gas, not follower head lag alone',()=>{
  const s = summarizeDurability(fixture(),'b',blocks,0,20000);
  assert.equal(s.persisted_mgas_per_second,0.35);
  assert.equal(s.produced_mgas_per_second,1);
  assert.deepEqual(s.producer_backlog_blocks,{first:5,last:18,max:18});
  assert.equal(s.producer_backlog_gas.last,18e6);
});
test('flat durable progress is zero throughput, while regressions and coverage holes fail',()=>{
  const rows=fixture();for(const row of rows) row.nodes.b.persisted.state=5;
  assert.equal(summarizeDurability(rows,'b',blocks,0,20000).persisted_mgas_per_second,0);
  rows[1].nodes.b.persisted.state=4;
  assert.throws(()=>summarizeDurability(rows,'b',blocks,0,20000),/regressed/);
  assert.throws(()=>gasBetween(blocks.slice(10),5,20),/cover/);
  assert.throws(()=>gasBetween([blocks[6],blocks[6]],5,7),/contiguous/);
  assert.equal(gasBetween(blocks,5,5),0);
});
