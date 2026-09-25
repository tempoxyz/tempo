'use strict';
const fs=require('fs'),path=require('path'),assert=require('assert/strict');
const {spawn,execFileSync}=require('child_process');
const root=__dirname, experiment=JSON.parse(fs.readFileSync(root+'/experiment.json'));
const result='bench-results/20260925-133021-514';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
async function rpc(node,method,params=[]) {
  const r=await fetch(`http://127.0.0.1:${node==='a'?8545:8645}`,{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(120000)});
  const j=await r.json();assert.ok(!j.error,JSON.stringify(j.error));return j.result;
}
async function main() {
  const children=[];
  try {
    for(const side of ['a','b']) {
      const evidence=experiment.runs[0].live_evidence.nodes[side];
      const archive=`${result}/logs-feature-1-${side}`;
      if(!fs.existsSync(archive))fs.cpSync(`localnet/logs-e2e-local-feature-1-${side}`,archive,{recursive:true});
      const args=[...evidence.args];
      args[args.indexOf('--log.file.directory')+1]=`${root}/reaudit-logs-${side}`;
      const script='RETH_BYTECODE_PREFETCH=1 '+args.map((a,i)=>args[i-1]==='--consensus.secret'
        ? "<(printf '%s\\n' 'tempo-localnet-signing-key-secret')" : quote(a)).join(' ');
      const log=fs.openSync(`${root}/reaudit-node-${side}.log`,'a');
      const child=spawn('sudo',['-n','systemd-run','--scope',`--unit=tempo-e2e-${side}-reaudit`,
        '--property=MemoryMax=20G','--property=MemorySwapMax=0',`--property=AllowedCPUs=${evidence.cpus}`,
        'taskset','-c',evidence.cpus,'bash','-c',script],{stdio:['ignore',log,log]});
      children.push({side,child,log});
    }
    for(const side of ['a','b']) {
      let ok=false;
      for(let i=0;i<120;i++){try {await rpc(side,'eth_blockNumber');ok=true;break;}catch{await sleep(1000);}}
      assert.ok(ok,`node ${side} unavailable`);
    }
    const report=JSON.parse(fs.readFileSync(result+'/report-feature-1.json'));
    const block=report.blocks.find(b=>b.tx_count>0 && b.timestamp_ms>=report.blocks[0].timestamp_ms+600000);
    const number='0x'+block.number.toString(16);
    const receipts=await rpc('b','eth_getBlockReceipts',[number]);
    const tx=await rpc('b','eth_getTransactionByHash',[receipts.at(-1).transactionHash]);
    const trace=await rpc('b','debug_traceTransaction',[tx.hash,{tracer:'callTracer'}]);
    const call=trace.calls.find(c=>c.to.toLowerCase()==='0x535441544541434345535342454e434800000000');
    const parent='0x'+(block.number-1).toString(16);
    const request={from:call.from,to:call.to,data:call.input,gas:'0x1c9c380'};
    const before=await rpc('b','debug_traceCall',[request,parent,{tracer:'callTracer'}]);
    const after=await rpc('b','debug_traceCall',[request,parent,{tracer:'callTracer',stateOverrides:{[call.from]:{nonce:'0x1'}}}]);
    const proof={transaction:tx.hash,receipt:receipts.at(-1),sender:call.from,parent_nonce:await rpc('b','eth_getTransactionCount',[call.from,parent]),before,after};
    fs.writeFileSync(root+'/replay-diagnosis.json',JSON.stringify(proof,null,2)+'\n');
    console.log(JSON.stringify({sender:call.from,nonce:proof.parent_nonce,before_error:before.error,before_gas:Number(BigInt(before.gasUsed)),after_error:after.error,after_gas:Number(BigInt(after.gasUsed))}));
    if(process.argv.includes('--audit')) {
      const code=await new Promise((resolve,reject)=>{
        const child=spawn(process.execPath,['contrib/bench/state-path-observer.cjs','audit','--tempo',experiment.binary,
          '--a-datadir','/reth-bench-a/tempo_e2e_100000mb_state_access_isolated_roles_history_paths',
          '--b-datadir','/reth-bench-b/tempo_e2e_100000mb_state_access_isolated_roles_history_paths','--phase','feature-1',
          '--warmup-seconds','600','--report',result+'/report-feature-1.json','--output',result+'/correctness-feature-1.json'],
          {stdio:'inherit',env:{...process.env,STATE_PATH_CHECKPOINT_TOOL:'/home/ubuntu/repos/tempo-payments-bloat-pr/bench-results/build-payload-cancel-20260923-v3/read_finish_checkpoint'}});
        child.once('error',reject);child.once('close',resolve);
      });assert.equal(code,0);
    }
  } finally {
    for(const {side}of children) {
      const p=`/sys/fs/cgroup/system.slice/tempo-e2e-${side}-reaudit.scope/cgroup.procs`;
      if(fs.existsSync(p))for(const pid of fs.readFileSync(p,'utf8').trim().split(/\s+/))try{
        const args=fs.readFileSync(`/proc/${pid}/cmdline`,'utf8').split('\0');
        if(args[0]===experiment.binary)execFileSync('sudo',['-n','kill','-INT',pid]);
      }catch{}
    }
    for(const {child,log}of children){if(child.exitCode===null)await new Promise(r=>child.once('close',r));fs.closeSync(log);}
  }
}
main().catch(e=>{console.error(e);process.exitCode=1;});
