// End-to-end cutover on a local dev chain. Uses real v1/v2 nodes and copied state.
// Usage: node contrib/multiplex/smoke.mjs /path/to/v1 /path/to/v2 /path/to/mux
// The validated multiplexer remains running for the box's lifetime.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { openSync, closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const [v1Binary, v2Binary, muxBinary] = process.argv.slice(2).map(p => path.resolve(p));
const root = await mkdtemp(path.join(tmpdir(), 'tempo-multiplex-smoke-'));
const v1Rpc = 'http://127.0.0.1:18546';
const v2Rpc = 'http://127.0.0.1:18547';
const muxRpc = 'http://127.0.0.1:18545';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const hex = n => `0x${n.toString(16)}`;
const genesisPath = path.join(root, 'genesis.json');
const v1Dir = path.join(root, 'v1');
const v2Dir = path.join(root, 'v2');
await mkdir(v1Dir);

async function response(url, method, params = [], id = 1) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    signal: AbortSignal.timeout(30000),
  });
  assert.equal(res.status, 200);
  return res.json();
}
async function rpc(url, method, params = []) {
  const res = await response(url, method, params);
  assert.ok(!res.error, JSON.stringify(res.error));
  return res.result;
}
async function ready(url, child) {
  for (let i = 0; i < 120; i++) {
    if (child.exitCode !== null) throw new Error(`child exited: ${child.exitCode}; logs in ${root}`);
    try { await rpc(url, 'eth_chainId'); return; } catch {}
    await delay(500);
  }
  throw new Error(`RPC startup timed out at ${url}; logs in ${root}`);
}
function start(binary, args, name) {
  const fd = openSync(path.join(root, `${name}.log`), 'a');
  const child = spawn(binary, args, { stdio: ['ignore', fd, fd], detached: true });
  closeSync(fd);
  return child;
}
async function stop(child) {
  child.kill('SIGINT');
  await Promise.race([
    new Promise((resolve, reject) => child.once('exit', (code, signal) => {
      if (code !== 0 && signal !== 'SIGINT') reject(new Error(`unclean checkpoint shutdown: ${code}/${signal}`));
      else resolve();
    })),
    delay(30000).then(() => { throw new Error('node did not shut down cleanly'); }),
  ]);
}
function args(datadir, port, networkPort, timed) {
  return ['node', '--chain', genesisPath, '--datadir', datadir, '--dev',
    ...(timed ? ['--dev.block-time', '1s'] : []),
    '--http', '--http.addr', '127.0.0.1', '--http.port', String(port),
    '--http.api', 'eth,net,web3,debug,trace,tempo',
    '--port', String(networkPort), '--authrpc.port', String(port + 10),
    '--ipcdisable', '--disable-discovery', '--tempo.bootnodes-endpoint', 'none'];
}

let seed;
let mux;
let success = false;
try {
  // This file is extracted from the pinned v1 release's source before running the script.
  const genesis = JSON.parse(await readFile(process.env.MULTIPLEX_GENESIS, 'utf8'));
  delete genesis.config.t12Time;
  delete genesis.config.t13Time;
  const activation = Math.floor(Date.now() / 1000) + 12;
  genesis.config.t11Time = activation;
  await writeFile(genesisPath, JSON.stringify(genesis));
  seed = start(v1Binary, args(v1Dir, 18546, 30316, true), 'seed');
  await ready(v1Rpc, seed);
  let tip;
  for (let i = 0; i < 60; i++) {
    tip = await rpc(v1Rpc, 'eth_getBlockByNumber', ['latest', false]);
    if (Number(BigInt(tip.timestamp)) >= activation + 3) break;
    await delay(1000);
  }
  assert.ok(Number(BigInt(tip.timestamp)) >= activation + 3, 'seed did not cross T11');
  let cutover;
  let parent;
  for (let n = 1; n <= Number(BigInt(tip.number)); n++) {
    const block = await rpc(v1Rpc, 'eth_getBlockByNumber', [hex(n), false]);
    if (Number(BigInt(block.timestamp)) >= activation) {
      cutover = n;
      parent = await rpc(v1Rpc, 'eth_getBlockByNumber', [hex(n - 1), false]);
      break;
    }
  }
  assert.ok(cutover > 1, 'need non-genesis history before T11');
  await stop(seed);
  seed = undefined;
  await cp(v1Dir, v2Dir, { recursive: true });
  const config = {
    listen: '0.0.0.0:18545', cutover_block: cutover, parent_hash: parent.hash,
    v1: { rpc: v1Rpc, binary: v1Binary, args: args(v1Dir, 18546, 30316, false) },
    v2: { rpc: v2Rpc, binary: v2Binary, args: args(v2Dir, 18547, 30317, true) },
  };
  const configPath = path.join(root, 'multiplex.json');
  await writeFile(configPath, JSON.stringify(config, null, 2));
  mux = start(muxBinary, ['--config', configPath], 'multiplex');
  await ready(muxRpc, mux);
  assert.equal(await rpc(muxRpc, 'eth_chainId'), await rpc(v1Rpc, 'eth_chainId'));
  const old = hex(cutover - 1);
  const current = hex(cutover);
  for (const [block, backend] of [[old, v1Rpc], [current, v2Rpc]]) {
    for (const [method, params] of [
      ['eth_getBlockByNumber', [block, false]],
      ['eth_getBalance', ['0x0000000000000000000000000000000000000001', block]],
      ['eth_getBlockReceipts', [block]],
      ['debug_traceBlockByNumber', [block, { tracer: 'callTracer' }]],
    ]) {
      assert.deepEqual(await response(muxRpc, method, params), await response(backend, method, params), `${method} at ${block}`);
    }
  }
  assert.deepEqual(await rpc(muxRpc, 'eth_getBlockByHash', [parent.hash, false]), await rpc(v1Rpc, 'eth_getBlockByHash', [parent.hash, false]));
  const token = Object.keys(genesis.alloc).find(address => /^0x?20c/i.test(address) || /^20c/i.test(address));
  assert.ok(token, 'genesis needs a TIP-20 token');
  const tokenAddress = token.startsWith('0x') ? token : `0x${token}`;
  const canonicalCall = { to: tokenAddress, data: '0x313ce567' };
  const refusedHistoricalExecution = await response(v2Rpc, 'eth_call', [canonicalCall, old]);
  assert.ok(refusedHistoricalExecution.error, 'v2 must refuse historical execution');
  for (const [block, backend] of [[old, v1Rpc], [current, v2Rpc]]) {
    const expected = await response(backend, 'eth_call', [canonicalCall, block]);
    assert.ok(!expected.error, JSON.stringify(expected));
    assert.deepEqual(await response(muxRpc, 'eth_call', [canonicalCall, block]), expected);
  }
  // Strict ABI decoding changes at T11: the same calldata succeeds before and fails after.
  const paddedCall = { ...canonicalCall, data: `0x313ce567${'00'.repeat(32)}` };
  const before = await response(muxRpc, 'eth_call', [paddedCall, old]);
  const after = await response(muxRpc, 'eth_call', [paddedCall, current]);
  assert.ok(!before.error, JSON.stringify(before));
  assert.ok(after.error, 'T11 must reject trailing ABI bytes');
  const logs = await rpc(muxRpc, 'eth_getLogs', [{ fromBlock: old, toBlock: current }]);
  assert.deepEqual(logs, [
    ...await rpc(v1Rpc, 'eth_getLogs', [{ fromBlock: old, toBlock: old }]),
    ...await rpc(v2Rpc, 'eth_getLogs', [{ fromBlock: current, toBlock: current }]),
  ]);
  const fees = await rpc(muxRpc, 'eth_feeHistory', ['0x2', current, [50]]);
  assert.equal(fees.baseFeePerGas.length, 3);
  assert.equal(fees.gasUsedRatio.length, 2);
  // Check clean supervision and restart against the same checkpointed databases.
  await stop(mux);
  mux = undefined;
  for (const url of [v1Rpc, v2Rpc]) {
    let alive = false;
    try { await rpc(url, 'eth_chainId'); alive = true; } catch {}
    assert.equal(alive, false, 'child RPC must stop when the supervisor stops');
  }
  mux = start(muxBinary, ['--config', configPath], 'multiplex');
  await ready(muxRpc, mux);
  const firstHeight = await rpc(muxRpc, 'eth_blockNumber');
  await delay(2200);
  const lastHeight = await rpc(muxRpc, 'eth_blockNumber');
  assert.ok(BigInt(lastHeight) > BigInt(firstHeight), 'v2 must continue producing blocks');
  const report = { root, rpc: muxRpc, pid: mux.pid, cutover, parentHash: parent.hash, activation, firstHeight, lastHeight, before, after, refusedHistoricalExecution, result: 'passed' };
  await writeFile(path.join(root, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
  success = true;
  mux.unref();
} finally {
  if (seed) await stop(seed);
  if (mux && !success) { mux.kill('SIGINT'); }
}
