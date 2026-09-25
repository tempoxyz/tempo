'use strict';
const fs=require('fs'),path=require('path'),assert=require('assert/strict'),crypto=require('crypto');
const {analyze}=require('../../contrib/bench/analyze-max-state-access.cjs');
const root=__dirname, v2=path.resolve('bench-results/max-state-access-20260925-v2'),v4=path.resolve('bench-results/max-state-access-20260925-v4');
const read=p=>JSON.parse(fs.readFileSync(p));
const write=(p,v)=>fs.writeFileSync(p,JSON.stringify(v,null,2)+'\n');
async function main(){
  const s=read(v2+'/experiment.json'),b=read(v4+'/experiment.json');
  assert.equal(s.sha256,b.sha256);assert.deepEqual(s.fixture,b.fixture);assert.deepEqual(s.tools,b.tools);
  for(const file of ['bench-e2e.nu','contrib/bench/state-path-observer.cjs','contrib/bench/max-state-access-preflight.cjs',
    'contrib/bench/configs/state-access-max-tx.json','contrib/bench/txgen/HistoryStatePaths.sol','contrib/bench/txgen/history-state-paths.json',
    'contrib/bench/txgen/presets/history_read_max.yml'])
    assert.equal(s.sources[file],b.sources[file],`measured input changed: ${file}`);
  const bytecodePresetCorrection={
    explanation:'The bytecode-only preset fee-token address was malformed in the archived SLOAD sources. It was never used by SLOAD. The first bytecode attempt sent zero transactions and is excluded; v4 uses the corrected address with a fresh cold restore.',
    excluded_attempt:path.resolve('bench-results/max-state-access-20260925-v3'),
    old_sha256:s.sources['contrib/bench/txgen/presets/history_code_max.yml'],
    measured_sha256:b.sources['contrib/bench/txgen/presets/history_code_max.yml']
  };
  const result='bench-results/20260925-133021-514';
  const audit=read(result+'/correctness-feature-1.json');assert.ok(audit.ok && audit.persisted_through_workload);
  const diagnosis=read(v2+'/replay-diagnosis.json');
  assert.equal(diagnosis.before.error,'out of gas');assert.ok(!diagnosis.after.error);
  assert.equal(BigInt(diagnosis.receipt.status),1n);
  assert.ok(audit.traces.every(t=>t.replay_sender_nonce_override));
  const plan=read(s.runs[0].directory+'/configuration.json');
  const directory=path.join(root,'1-sload-reaudited');fs.mkdirSync(directory,{recursive:true});
  const recovery={original_experiment:v2,original_status:s.status,original_exit_code:s.runs[0].exit_code,
    explanation:'Timed SLOAD load completed without reverted/invalid transactions. Original post-load legacy RPC replay spuriously charged sender creation. Same preserved database re-audited with sender nonce=1 simulation override; no measured-window data regenerated or changed.',
    audit_only_restart:true,diagnosis:v2+'/replay-diagnosis.json',reaudit_script:v2+'/reaudit.cjs',audited_at:audit.audited_at};
  const source='contrib/bench/history-state-path-validation.cjs';
  recovery.audit_source_sha256=crypto.createHash('sha256').update(fs.readFileSync(source)).digest('hex');
  recovery.original_audit_source_sha256=s.sources[source];
  fs.copyFileSync(source,path.join(directory,'history-state-path-validation.cjs'));
  write(path.join(directory,'manifest.json'),{status:'complete',configuration:plan.configuration,options:plan.options,
    fixture:s.fixture,builds:{feature:read(result+'/node-binary-feature.json')},cases:[{id:'sload',scenario:'history_read_max',results_dir:result}],recovery});
  const first={...s.runs[0],status:'complete',directory,results_dir:result,label:'sload-13800',recovery};
  const runs=[first,...b.runs.filter(e=>e.status==='complete' && e.results_dir)];
  const experiment={...s,status:runs.length===2 && b.status==='complete'?'complete':'running',runs,
    order:[{id:'sload',reads:13800,prewarming:true},{id:'bytecode',reads:10800,prewarming:true}],
    finished_at:runs.length===2?b.finished_at:null,source_experiments:[v2,v4],recovery,bytecode_preset_correction:bytecodePresetCorrection,
    limits:s.limits+' The completed first load was re-audited after an RPC-only simulation fix. Original failed manifests remain unchanged. Shared timed inputs match; per-case preset correction and audit source versions are explicit.'};
  write(root+'/experiment.json',experiment);
  await analyze(root);
}
main().catch(e=>{console.error(e);process.exitCode=1;});
