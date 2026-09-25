#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {ROUTER,CURSOR} = require('./history-state-path-validation.cjs');
async function main() {
  const [scenario, datadir, output] = process.argv.slice(2);
  assert.ok(['history_read_max', 'history_code_max', 'history_read_sized', 'history_code_sized'].includes(scenario));
  const sized = scenario.endsWith('_sized');
  const accesses = Number(process.env.TXGEN_STATE_ACCESSES);
  if (sized) assert.ok(Number.isSafeInteger(accesses) && accesses > 0 && accesses <= (scenario === 'history_read_sized' ? 13800 : 10800));
  const rpc = async (method, params) => {
    const response = await fetch('http://127.0.0.1:8545', {method: 'POST', headers: {'content-type':'application/json'},
      body: JSON.stringify({jsonrpc:'2.0',id:1,method,params}), signal: AbortSignal.timeout(180000)});
    assert.ok(response.ok, `HTTP ${response.status}`);
    const body = await response.json(); assert.ok(!body.error, JSON.stringify(body.error)); return body.result;
  };
  assert.equal(BigInt(await rpc('eth_chainId', [])), 1337n);
  const fixture = JSON.parse(fs.readFileSync(path.join(datadir, '.bench-meta/history-state-paths.json')));
  assert.equal(BigInt(await rpc('eth_getStorageAt',[ROUTER,CURSOR,'latest'])),0n,'fresh cursor required');
  // Pay the one-time 250k storage-creation cost outside steady-state timing.
  // This is the public local-only faucet key, never a production credential.
  const initialization = JSON.parse(execFileSync(process.env.CAST_BIN || path.join(process.env.HOME,'.foundry/bin/cast'),
    ['send',ROUTER,'touchReads(bytes32,uint256,bool)','0x'+'0'.repeat(64),'399999','true',
      '--rpc-url','http://127.0.0.1:8545','--private-key','0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
      '--gas-limit','3000000','--gas-price','100000000000','--legacy','--json'],
    {encoding:'utf8',timeout:180000}));
  assert.equal(BigInt(initialization.status),1n,'cursor initialization reverted');
  assert.equal(BigInt(await rpc('eth_getStorageAt',[ROUTER,CURSOR,'latest'])),1n);
  const reading = scenario.startsWith('history_read_');
  const signature = sized ? `${reading ? 'touchSizedReads' : 'touchSizedCode'}(bytes32,uint256,bool,uint256)` :
    `${reading ? 'touchMaxReads' : 'touchMaxCode'}(bytes32,uint256,bool)`;
  const selector = (await rpc('web3_sha3', ['0x'+Buffer.from(signature).toString('hex')])).slice(0,10);
  const word = n => BigInt(n).toString(16).padStart(64,'0');
  const probes = [];
  for (const salt of [19, 1337, 20260925]) {
    const data = selector + word(salt) + word(reading ? 399999 : fixture.code_count) + word(1) + (sized ? word(accesses) : '');
    const trace = await rpc('debug_traceCall', [{from:initialization.from,to:ROUTER, data, gas:'0x1c9c380'}, 'latest', {tracer:'callTracer',timeout:'180s'}]);
    assert.ok(!trace.error, JSON.stringify(trace));
    const gas = Number(BigInt(trace.gasUsed));
    assert.ok(sized ? gas >= accesses * (reading ? 2100 : 2500) && gas < 30000000 :
      gas >= 29700000 && gas < 29965000, `unexpected call gas: ${gas}`);
    probes.push({salt,gas_used:gas,output:trace.output});
    console.log(`State-access ${scenario} salt=${salt} call gas=${gas}`);
  }
  fs.writeFileSync(output, JSON.stringify({ok:true,scenario,accesses:sized ? accesses : undefined,fixture,initialization,probes,
    caveat:'One small excluded transaction initializes the cursor before steady-state load. Direct eth_call calibration is not a full fee-paying transaction. Receipt gas, opcode coldness and populated targets are audited after timed load.'},null,2)+'\n');
}
if (require.main === module) main().catch(error => {console.error(error); process.exitCode=1;});
