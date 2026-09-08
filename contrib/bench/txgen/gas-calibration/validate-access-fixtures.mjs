// Semantic checks on a private, disposable Cancun Anvil; not Tempo pricing evidence.
// Usage: node validate-access-fixtures.mjs /path/to/anvil
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import net from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

const binary = process.argv[2];
assert(binary, 'Pass the Anvil binary path');
const artifact = JSON.parse(await readFile(new URL('./AccessCalibration.json', import.meta.url)));
assert.equal(artifact.settings.optimizer.enabled, false);
const listener = net.createServer();
await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
const port = listener.address().port;
await new Promise(resolve => listener.close(resolve));
const child = spawn(binary, ['--host', '127.0.0.1', '--port', String(port),
  '--hardfork', 'cancun', '--chain-id', '31337', '--silent'], { stdio: 'ignore' });
let spawnError;
child.on('error', error => { spawnError = error; });
let id = 0;
async function rpc(method, params = []) {
  const response = await fetch(`http://127.0.0.1:${port}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
    signal: AbortSignal.timeout(5000),
  });
  assert(response.ok, `RPC HTTP ${response.status}`);
  const result = await response.json();
  assert(!result.error, JSON.stringify(result.error));
  return result.result;
}
try {
  let ready = false;
  for (let attempt = 0; attempt < 50; attempt++) {
    if (spawnError) throw spawnError;
    if (child.exitCode !== null) throw Error(`Anvil exited: ${child.exitCode}`);
    try { ready = await rpc('eth_chainId') === '0x7a69'; } catch {}
    if (ready) break;
    await delay(100);
  }
  assert(ready, 'Private Anvil did not start with chain ID 31337');
  const [from] = await rpc('eth_accounts');
  const hash = await rpc('eth_sendTransaction', [{ from, data: artifact.bytecode.object, gas: '0x989680' }]);
  let receipt;
  for (let attempt = 0; attempt < 50; attempt++) {
    receipt = await rpc('eth_getTransactionReceipt', [hash]);
    if (receipt) break;
    await delay(100);
  }
  assert.equal(receipt?.status, '0x1', 'Deployment must succeed');
  const cases = [
    ['control', 2, [], 0],
    ['slotOnce', 1, [2100], 0],
    ['slotTwiceWarm', 2, [2100, 100], 0],
    ['slotTwiceCold', 2, [2100, 2100], 0],
    ['callOnce', 1, [2100], 1],
    ['callTwiceWarm', 2, [2100, 100], 2],
    ['callTwiceCold', 2, [2100, 2100], 2],
  ];
  const results = [];
  for (const [method, expected, sloadCosts, staticCalls] of cases) {
    const data = '0x' + artifact.methodIdentifiers[`${method}()`];
    const call = { from, to: receipt.contractAddress, data, gas: '0x493e0' };
    assert.equal(BigInt(await rpc('eth_call', [call, 'latest'])), BigInt(expected), method);
    const trace = await rpc('debug_traceCall', [call, 'latest', { disableMemory: true, disableStorage: true, disableStack: true }]);
    assert.equal(trace.failed, false, method);
    const actualCosts = trace.structLogs.filter(row => row.op === 'SLOAD').map(row => Number(row.gasCost));
    assert.deepEqual(actualCosts, sloadCosts, `${method}: SLOAD count and warmth`);
    assert.equal(trace.structLogs.filter(row => row.op === 'STATICCALL').length, staticCalls, method);
    results.push({ method, returnValue: expected, sloadCosts: actualCosts, staticCalls });
  }
  console.log(JSON.stringify({ chain: 'isolated Anvil Cancun', pricingEvidence: false,
    deploymentGas: Number(BigInt(receipt.gasUsed)), results }, null, 2));
} finally {
  if (child.exitCode === null && child.pid) {
    const exited = new Promise(resolve => child.once('exit', resolve));
    child.kill('SIGTERM');
    const timeout = setTimeout(() => child.kill('SIGKILL'), 3000);
    await exited;
    clearTimeout(timeout);
  }
}
