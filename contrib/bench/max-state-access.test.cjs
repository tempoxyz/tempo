'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {execFileSync}=require('node:child_process');
const {resolveConfig}=require('./state-access-config.cjs');
const {makePlan}=require('./run-sload-size-isolation.cjs');
const {selectTraceCandidates,validateHistorySamples}=require('./state-path-observer.cjs');
const {inspectOpcodes,CURSOR,ROUTER,replayStateOverrides}=require('./history-state-path-validation.cjs');
const file=path.join(__dirname,'configs/state-access-max-tx.json');
test('near-cap legacy replay neutralizes sender creation without changing router state',()=>{
  const sender='0x'+'1'.repeat(40);
  for(const scenario of ['history_read_max','history_code_max']) {
    assert.deepEqual(replayStateOverrides(scenario,sender),{[sender]:{nonce:'0x1'}});
    const actual=replayStateOverrides(scenario,sender,123n);
    assert.equal(BigInt(actual[ROUTER].stateDiff[CURSOR]),123n);
    assert.deepEqual(actual[sender],{nonce:'0x1'});
    assert.throws(()=>replayStateOverrides(scenario,ROUTER));
  }
  assert.deepEqual(replayStateOverrides('history_read',sender),{});
});
test('max-size suite is explicit and preserves the ordinary suite',()=>{
  const config=resolveConfig(file,[],{});
  assert.deepEqual(config.cases.map(c=>c.operations_per_transaction),[13800,10800]);
  assert.deepEqual(config.cases.map(c=>c.scenario),['history_read_max','history_code_max']);
  assert.throws(()=>resolveConfig(file,['writes'],{}));
  assert.equal(resolveConfig(undefined,[],{}).cases[0].operations_per_transaction,128);
  for(const c of config.cases) {
    const plan=makePlan({configuration:config,options:{}},{...c,reads:c.operations_per_transaction,prewarming:true},'max-test');
    assert.deepEqual(plan.configuration.cases,[c]);
    assert.equal(plan.options.feature_args,'');
    assert.equal(plan.options.feature_env,'RETH_BYTECODE_PREFETCH=1');
    assert.equal(plan.options.node_memory,'20G');
    assert.equal(plan.options.node_swap_limit,'0');
    assert.equal(plan.options.allow_first_sload_samples,false);
    const preset=fs.readFileSync(path.join(__dirname,`txgen/presets/${c.scenario}.yml`),'utf8');
    assert.match(preset,/gas_limit: 30000000/);
    assert.match(preset,/valid_for_secs: 25/);
    assert.match(preset,/fee_token: "0x20c0000000000000000000000000000000000000"/);
    for(const address of preset.matchAll(/(?:fee_token|to): "([^"]+)"/g))
      assert.match(address[1],/^0x[0-9a-fA-F]{40}$/);
  }
});
test('native max-size flag resolves both saved cases and resource controls',()=>{
  const p=JSON.parse(execFileSync('/usr/local/bin/nu',['--no-config-file','bench-e2e.nu','state-access-bloat-worst-case','--max-transaction-size','--dry-run'],{encoding:'utf8'}));
  assert.equal(p.configuration.id,'state-access-max-tx');
  assert.equal(p.configuration.cases.length,2);
  assert.equal(p.options.node_memory,'20G');
  assert.equal(p.options.node_swap_limit,'0');
  assert.equal(p.options.feature_env,'RETH_BYTECODE_PREFETCH=1');
});
test('near-cap first-tx sampling is explicitly labeled and does not relax small workloads',()=>{
  const blocks=Array.from({length:8},(_,number)=>({number,tx_count:1}));
  for(const scenario of ['history_read_max','history_code_max']) {
    const selected=selectTraceCandidates(blocks,true,scenario);
    assert.equal(selected.policy,'max-size-first-allowed');
    validateHistorySamples([{history_advanced:false}],selected.policy);
    assert.throws(()=>validateHistorySamples([{history_advanced:true,parent_state_mismatch_fraction:0}],selected.policy));
  }
  for(const scenario of ['history_read','history_code']) assert.throws(()=>selectTraceCandidates(blocks,true,scenario));
});
test('near-cap opcode audit rejects warm SLOADs and repeated bytecode targets',()=>{
  const cursor={op:'SSTORE',stack:[CURSOR]};
  const reads={failed:false,structLogs:[cursor,...Array.from({length:13800},(_,i)=>({op:'SLOAD',stack:[i.toString(16)],gasCost:2100}))]};
  assert.equal(inspectOpcodes(reads,false,true,13800).targets.size,13800);
  reads.structLogs[1].gasCost=100;
  assert.throws(()=>inspectOpcodes(reads,false,true,13800));
  const code={failed:false,structLogs:[cursor,...Array.from({length:10800},(_,i)=>({op:'EXTCODECOPY',stack:[(0x100000+i).toString(16)],gasCost:2603}))]};
  assert.equal(inspectOpcodes(code,false,false,0,10800).targets.size,10800);
  for(let i=1;i<=200;i++) {code.structLogs[i].stack=['100000'];code.structLogs[i].gasCost=103;}
  assert.throws(()=>inspectOpcodes(code,false,false,0,10800));
});
