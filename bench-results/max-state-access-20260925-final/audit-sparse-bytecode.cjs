'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {spawn,execFileSync}=require('node:child_process');
const {auditTransaction,ROUTER,CURSOR}=require('../../contrib/bench/history-state-path-validation.cjs');
const {checkCursorAdvance}=require('../../contrib/bench/state-access-validation.cjs');
const {frontier}=require('../../contrib/bench/state-path-observer.cjs');
const {analyzeRun}=require('../../contrib/bench/analyze-state-access.cjs');
const root=__dirname, result='bench-results/20260925-141345-022';
const experimentFile='bench-results/max-state-access-20260925-v4/experiment.json';
const read=p=>JSON.parse(fs.readFileSync(p));
const write=(p,v)=>fs.writeFileSync(p,JSON.stringify(v,null,2)+'\n');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
const hex=n=>'0x'+n.toString(16);
async function rpc(side,method,params=[]) {
  const response=await fetch(`http://127.0.0.1:${side==='a'?8545:8645}`,{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),signal:AbortSignal.timeout(120000)});
  assert.ok(response.ok);const v=await response.json();assert.ok(!v.error,JSON.stringify(v.error));return v.result;
}
async function main() {
  const experiment=read(experimentFile);
  assert.notEqual(experiment.status,'running','never restart nodes during measured load');
  const report=read(result+'/report-feature-1.json');
  assert.equal(report.metadata.scenario,'history_code_max');
  const blocks=report.blocks, txCount=blocks.reduce((sum,b)=>sum+b.tx_count,0);
  assert.ok(txCount>0 && txCount<=16,'this exhaustive recovery is for sparse results only');
  const measured=await analyzeRun(result,'bytecode-10800-sparse');
  const from=measured.builder.gas_counter.first.unix_ms,to=measured.builder.gas_counter.last.unix_ms;
  for(const side of ['a','b']) {
    let online=false;try{await rpc(side,'eth_blockNumber');online=true;}catch{}
    assert.ok(!online,'benchmark nodes must have stopped before audit restart');
    const archive=`${result}/logs-feature-1-${side}`;
    if(!fs.existsSync(archive))fs.cpSync(`localnet/logs-e2e-local-feature-1-${side}`,archive,{recursive:true});
  }
  const children=[];
  try {
    for(const side of ['a','b']) {
      const evidence=experiment.runs[0].live_evidence.nodes[side],args=[...evidence.args];
      args[args.indexOf('--log.file.directory')+1]=`${root}/sparse-audit-logs-${side}`;
      args.push('--rpc.max-response-size','512');
      const command='RETH_BYTECODE_PREFETCH=1 '+args.map((a,i)=>args[i-1]==='--consensus.secret'
        ? "<(printf '%s\\n' 'tempo-localnet-signing-key-secret')" : quote(a)).join(' ');
      const log=fs.openSync(`${root}/sparse-audit-node-${side}.log`,'a');
      const child=spawn('sudo',['-n','systemd-run','--scope',`--unit=tempo-e2e-${side}-sparse-audit`,
        '--property=MemoryMax=20G','--property=MemorySwapMax=0',`--property=AllowedCPUs=${evidence.cpus}`,
        'taskset','-c',evidence.cpus,'bash','-c',command],{stdio:['ignore',log,log]});
      children.push({side,child,log});
    }
    for(const side of ['a','b']) {
      let ok=false;for(let i=0;i<120;i++){try{await rpc(side,'eth_blockNumber');ok=true;break;}catch{await sleep(1000);}}
      assert.ok(ok,`node ${side} unavailable`);
      assert.equal(BigInt(await rpc(side,'eth_chainId')),1337n);
    }
    const end=blocks.at(-1).number;
    const deadline=Date.now()+600000;
    while(Number(BigInt(await rpc('b','eth_blockNumber')))<end){assert.ok(Date.now()<deadline);await sleep(1000);}
    const before=await rpc('b','eth_getStorageAt',[ROUTER,CURSOR,hex(blocks[0].number-1)]);
    const after=await rpc('b','eth_getStorageAt',[ROUTER,CURSOR,hex(end)]);
    const cursor=checkCursorAdvance(before,after,blocks);
    const fixture={...experiment.fixture,page_count:Number(report.metadata.bloat_mib)*4-1};
    const artifact=read('contrib/bench/txgen/history-state-paths.json');
    assert.equal((await rpc('b','eth_getCode',[ROUTER,'latest'])).toLowerCase(),artifact.deployedBytecode.object.toLowerCase());
    const receipts=[],traces=[];
    for(const block of blocks) {
      const live=await rpc('b','eth_getBlockByNumber',[hex(block.number),false]);
      const list=await rpc('b','eth_getBlockReceipts',[hex(block.number)]);
      assert.equal(list.length,block.tx_count);
      let gas=0n;
      for(const receipt of list) {
        assert.equal(BigInt(receipt.status),1n);assert.equal(receipt.blockHash,live.hash);
        const used=BigInt(receipt.gasUsed);assert.ok(used>=29700000n && used<=30000000n);gas+=used;
        const trace=await auditTransaction(rpc,receipt.transactionHash,block.number,'history_code_max',fixture,root);
        trace.block=block.number;trace.measured_window=block.timestamp_ms>from && block.timestamp_ms<=to;
        traces.push(trace);receipts.push(receipt);
        console.log(JSON.stringify({audited:receipt.transactionHash,block:block.number,gas:Number(used),cold:trace.gas_cost_histogram[2603],measured:trace.measured_window}));
      }
      assert.equal(gas,BigInt(block.gas_used));assert.equal(gas,BigInt(live.gasUsed));
    }
    const observer=fs.readFileSync(result+'/state-path-observer-feature-1.jsonl','utf8').trim().split('\n').map(JSON.parse);
    const minState=Math.min(...observer.flatMap(row=>['a','b'].map(side=>row.nodes[side].persisted?.state).filter(Number.isFinite)));
    const canonical=[];
    for(let number=minState+1;number<=end;number++) {
      const b=await rpc('b','eth_getBlockByNumber',[hex(number),false]);
      canonical.push({number,timestamp_ms:Number(BigInt(b.timestamp))*1000,gas_used:BigInt(b.gasUsed).toString(),tx_count:b.transactions.length});
    }
    // Retain the reporter's millisecond timestamps for all measured blocks.
    for(const b of blocks)Object.assign(canonical.find(c=>c.number===b.number),b);
    write(root+'/bytecode-canonical-backlog.json',canonical);
    const tool=Object.keys(experiment.tools).find(p=>p.endsWith('/read_finish_checkpoint'));
    let persisted;
    while(Date.now()<deadline) {
      persisted={};
      for(const side of ['a','b']) {
        const args=experiment.runs[0].live_evidence.nodes[side].args;
        persisted[side]=frontier(JSON.parse(execFileSync(tool,[path.join(args[args.indexOf('--datadir')+1],'db')],{encoding:'utf8',timeout:15000})));
      }
      if(['a','b'].every(side=>persisted[side].state>=end))break;
      await sleep(5000);
    }
    assert.ok(['a','b'].every(side=>persisted[side].state>=end),'included work did not persist');
    write(root+'/bytecode-sparse-audit.json',{ok:true,exhaustive:true,transactions:txCount,receipts,traces,cursor_check:cursor,
      from_unix_ms:from,to_unix_ms:to,measured_transactions:traces.filter(t=>t.measured_window).length,
      persisted_through_workload:true,persisted,audited_at:new Date().toISOString(),
      original_experiment_status:experiment.status,scope:'Post-load exhaustive audit of every included transaction in the original report, including warmup. Original performance data and failed standard-audit result are unchanged. RPC response limit raised only for this audit restart. Very few completed transactions: not a steady-state execution capacity estimate.'});
  } finally {
    for(const {side}of children) {
      const p=`/sys/fs/cgroup/system.slice/tempo-e2e-${side}-sparse-audit.scope/cgroup.procs`;
      if(fs.existsSync(p))for(const pid of fs.readFileSync(p,'utf8').trim().split(/\s+/))try{
        const args=fs.readFileSync(`/proc/${pid}/cmdline`,'utf8').split('\0');
        if(args[0]===experiment.binary)execFileSync('sudo',['-n','kill','-INT',pid]);
      }catch{}
    }
    for(const {child,log}of children){if(child.exitCode===null)await new Promise(r=>child.once('close',r));fs.closeSync(log);}
  }
}
main().catch(e=>{console.error(e);process.exitCode=1;});
