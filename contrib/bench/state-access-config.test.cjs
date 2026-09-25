'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {resolveConfig,verifyCaseConfiguration}=require('./state-access-config.cjs');

test('registry resolves all three workloads with shared comparable defaults',()=>{
  const c=resolveConfig(undefined,[],{});
  assert.deepEqual(c.cases.map(x=>x.id),['sload','bytecode','writes']);
  assert.deepEqual([c.duration,c.warmup,c.tps,c.accounts],[1200,600,1000,1000]);
  assert.equal(c.transaction_cap,null);
  assert.equal(c.fixture_requirements.code_count,4266667);
  assert.equal(c.cases[0].scenario,'history_read');
  assert.equal(c.cases[0].operations_per_transaction,128);
  assert.equal(c.cases[0].minimum_history_advanced_fraction,0.9);
});
test('case selection preserves requested order and rejects unknown or duplicate cases',()=>{
  assert.deepEqual(resolveConfig(undefined,['writes','sload'],{}).cases.map(x=>x.id),['writes','sload']);
  for(const selected of [['typo'],['sload','sload']]) assert.throws(()=>resolveConfig(undefined,selected,{}));
});
test('common overrides cannot create invalid or too-short measurement windows',()=>{
  assert.equal(resolveConfig(undefined,[],{HISTORY_TPS:'2500'}).tps,2500);
  for(const env of [{HISTORY_DURATION:'60'},{HISTORY_WARMUP:'1200'},{HISTORY_TPS:'0'},{HISTORY_TPS:'1;false'}])
    assert.throws(()=>resolveConfig(undefined,[],env));
});
test('comparison rejects drift in run settings, actual sender metadata, or fixture',()=>{
  const configuration=resolveConfig(undefined,[],{}),entry={scenario:'history_read'};
  const fixture={state_root:'root',router_code_hash:'router',code_count:4266667,code_bytes:24576,hashed_storage_entries:1638400975};
  const manifest={configuration,build:{revision:'revision'},fixture};
  const summary={preset:entry.scenario,tps:1000,duration:1200,summary_warmup_seconds:600,summary_warmup_blocks:0,bloat_mib:100000,run_side:'feature',benchmark_id:'id'};
  const metadata={scenario:entry.scenario,target_tps:'1000',run_duration_secs:'1200',accounts:'1000',bloat_mib:'100000',node_commit_sha:'revision',benchmark_id:'id'};
  assert.equal(verifyCaseConfiguration(manifest,entry,summary,metadata,fixture),true);
  for(const key of ['tps','duration','summary_warmup_seconds','bloat_mib'])
    assert.throws(()=>verifyCaseConfiguration(manifest,entry,{...summary,[key]:0},metadata,fixture),/configuration drift/);
  for(const key of ['target_tps','accounts','node_commit_sha'])
    assert.throws(()=>verifyCaseConfiguration(manifest,entry,summary,{...metadata,[key]:'different'},fixture),/configuration drift/);
  for(const key of Object.keys(fixture))
    assert.throws(()=>verifyCaseConfiguration(manifest,entry,summary,metadata,{...fixture,[key]:'different'}),/fixture drift/);
});
