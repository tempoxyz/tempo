'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {execFileSync,spawnSync}=require('node:child_process');
const {ROUTER,CURSOR,targetSet,overlap,checkWriteDiff,inspectOpcodes}=require('./history-state-path-validation.cjs');
const root=path.resolve(__dirname,'../..'),runner=path.join(__dirname,'run-history-state-paths.sh');
const word=n=>'0x'+BigInt(n).toString(16).padStart(64,'0');

test('history presets share the valid public test signer pool',()=>{
  const fs=require('node:fs');
  for(const name of ['history_code','history_write']) {
    const preset=fs.readFileSync(path.join(__dirname,'txgen/presets',name+'.yml'),'utf8');
    assert.equal(/mnemonic: "([^"]+)"/.exec(preset)?.[1],Array(11).fill('test').concat('junk').join(' '));
  }
});

test('history runner uses isolated populated fixtures and leaves prewarming/caps unchanged',()=>{
  const output=execFileSync('bash',[runner,'--dry-run'],{cwd:root,encoding:'utf8'});
  assert.match(output,/BENCH_DISABLE_SCHELK=1/);
  assert.match(output,/--snapshot-suffix history_paths/);
  assert.match(output,/--single-restore/);
  assert.match(output,/--state-access-bloat/);
  assert.match(output,/--preset history_code/);
  assert.match(output,/--preset history_write/);
  assert.match(output,/--preset state_access_dependent/);
  assert.doesNotMatch(output,/--builder\.max-transactions|--force-bloat|--disable.*prewarm/);
});
test('named configurations are discoverable and support a single-case dry run',()=>{
  const list=execFileSync('bash',[runner,'--list'],{cwd:root,encoding:'utf8'});
  for(const id of ['sload','bytecode','writes']) assert.match(list,new RegExp('^'+id+'\\t','m'));
  const output=execFileSync('bash',[runner,'--case','sload','--dry-run'],{cwd:root,encoding:'utf8'});
  assert.match(output,/--preset state_access_dependent/);
  assert.doesNotMatch(output,/--preset history_(code|write)/);
  assert.match(output,/--tps 1000 --duration 1200 --accounts 1000/);
});
test('single-restore rejects repeated/unobserved/shared snapshot phases before touching storage',()=>{
  const base=['--no-config-file','bench-e2e.nu','e2e','--baseline','HEAD','--feature','HEAD',
    '--feature-binary','/usr/bin/true','--single-restore'];
  for(const extra of [[],['--run-side','feature','--run-pairs','2','--observe-state-paths','--snapshot-suffix','history_paths'],
    ['--run-side','feature','--run-pairs','1','--observe-state-paths']]) {
    const result=spawnSync('nu',[...base,...extra],{cwd:root,encoding:'utf8'});
    assert.notEqual(result.status,0);
    assert.match(result.stderr,/single-restore requires one observed/);
  }
});
test('invalid timings and offered load fail before nodes are started',()=>{
  for(const env of [{HISTORY_DURATION:'60'},{HISTORY_WARMUP:'1200'},{HISTORY_TPS:'0'},{HISTORY_TPS:'1;false'}]) {
    const result=spawnSync('bash',[runner,'--dry-run'],{cwd:root,encoding:'utf8',env:{...process.env,...env}});
    assert.equal(result.status,2);
  }
});
test('access comparison counts overlap instead of assuming every target differs',()=>{
  assert.deepEqual(overlap(new Set(['a','b']),new Set(['b','c'])),{
    actual_unique:2,parent_state_unique:2,overlap:1,parent_state_mismatch_fraction:0.5});
  assert.throws(()=>overlap(new Set(),new Set(['a'])));
  const prestate={[ROUTER]:{storage:{[CURSOR]:'0x5',[word(9)]:'0xa'}},
    '0x6000000000000000000000000000000000000001':{},
    '0x6000000000000000000000000000000000000100':{}};
  assert.deepEqual([...targetSet(prestate,true,32)],[word(9)]);
  assert.deepEqual([...targetSet(prestate,false,32)],['0x6000000000000000000000000000000000000001']);
});
test('write audit rejects allocation, deletion, no-op writes and unpopulated values',()=>{
  const pre={[CURSOR]:word(3)},post={[CURSOR]:word(4)};
  for(let i=0;i<1024;i++){pre[word(i)]=word(i+1);post[word(i)]=word(BigInt(i+1)^(1n<<255n));}
  const diff={pre:{[ROUTER]:{storage:pre}},post:{[ROUTER]:{storage:post}}};
  assert.equal(checkWriteDiff(diff),1024);
  for(const value of [word(0),word(1),word(2)]){
    const broken=structuredClone(diff);broken.post[ROUTER].storage[word(0)]=value;
    assert.throws(()=>checkWriteDiff(broken));
  }
});
test('opcode audit distinguishes real cold reads and code fetches from hash-only reads',()=>{
  const logs=[{op:'SSTORE',stack:['1',CURSOR.slice(2)]}];
  for(let i=0;i<128;i++) logs.push({op:'EXTCODECOPY',gasCost:2603,stack:[(BigInt('0x6000000000000000000000000000000000000000')+BigInt(i)).toString(16)]});
  assert.equal(inspectOpcodes({failed:false,structLogs:logs},false).targets.size,128);
  assert.throws(()=>inspectOpcodes({failed:true,structLogs:logs},false));
  assert.throws(()=>inspectOpcodes({failed:false,structLogs:logs.map(log=>log.op==='EXTCODECOPY'?{...log,op:'EXTCODEHASH'}:log)},false));
});
test('SLOAD audit requires all 4096 reads cold and only the cursor written',()=>{
  const logs=[{op:'SSTORE',stack:['1',CURSOR.slice(2)]}];
  for(let i=0;i<4096;i++) logs.push({op:'SLOAD',gasCost:2100,stack:[i.toString(16)]});
  assert.equal(inspectOpcodes({failed:false,structLogs:logs},false,true).targets.size,4096);
  assert.throws(()=>inspectOpcodes({failed:false,structLogs:logs.slice(1)},false,true));
  const warm=structuredClone(logs); warm[1].gasCost=100;
  assert.throws(()=>inspectOpcodes({failed:false,structLogs:warm},false,true),/not cold/);
  assert.throws(()=>inspectOpcodes({failed:false,structLogs:[...logs,{op:'SSTORE',stack:['1','0']}]},false,true));
});
