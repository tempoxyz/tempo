// Start a mainnet demonstration from an archive downloaded into ROOT/v1.
// Usage: node mainnet.mjs /path/to/v1 /path/to/v2 /path/to/mux ROOT [--resume]
// No validator keys or transactions are used. Both children are certified followers.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { closeSync, openSync } from 'node:fs';
import { cp, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

assert.ok(process.argv.length === 6 || (process.argv.length === 7 && process.argv[6] === '--resume'),
  'expected v1, v2, mux, root paths, and optional --resume');
const resume = process.argv[6] === '--resume';
const [v1Binary, v2Binary, muxBinary, root] = process.argv.slice(2, 6).map(p => path.resolve(p));
const v1Dir = path.join(root, 'v1');
const v2Dir = path.join(root, 'v2');
await stat(path.join(v1Dir, 'db'));
if (resume) await stat(path.join(v2Dir, 'db'));
else {
  try { await stat(v2Dir); throw new Error('v2 already exists; pass --resume to use the saved checkpoint'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}

const v1Rpc = 'http://127.0.0.1:28546';
const v2Rpc = 'http://127.0.0.1:28547';
const muxRpc = 'http://127.0.0.1:28545';
const reference = 'https://rpc.presto.tempo.xyz';
const activation = 1789048800;
const hex = n => `0x${n.toString(16)}`;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const token = '0x20c0000000000000000000000000000000000000';

async function response(url, method, params = []) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(30000) });
  assert.equal(res.status, 200, `HTTP ${res.status} from ${url}`);
  return res.json();
}
async function rpc(url, method, params = []) {
  const res = await response(url, method, params);
  assert.ok(!res.error, JSON.stringify(res.error));
  return res.result;
}
async function ready(url, child) {
  for (let i = 0; i < 240; i++) {
    if (child.exitCode !== null) throw new Error(`process exited ${child.exitCode}; inspect ${root}`);
    try { assert.equal(await rpc(url, 'eth_chainId'), '0x1079'); return; } catch {}
    await delay(500);
  }
  throw new Error(`mainnet RPC startup timed out at ${url}`);
}
function start(binary, args, name) {
  const fd = openSync(path.join(root, `${name}.log`), 'a');
  const child = spawn(binary, args, { stdio: ['ignore', fd, fd], detached: true });
  closeSync(fd);
  return child;
}
async function stop(child) {
  if (child.exitCode !== null) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('unclean checkpoint shutdown')), 30000);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      if (code !== 0 && signal !== 'SIGINT') reject(new Error(`shutdown ${code}/${signal}`));
      else resolve();
    });
    child.kill('SIGINT');
  });
}
function args(datadir, port, networkPort, metricsPort) {
  return ['node', '--chain', 'mainnet', '--datadir', datadir, '--follow',
    '--follow.upstream-request-timeout', '10s',
    '--http', '--http.addr', '127.0.0.1', '--http.port', String(port),
    '--http.api', 'eth,net,web3,debug,trace,tempo',
    '--port', String(networkPort), '--discovery.port', String(networkPort),
    '--p2p-secret-key', path.join(root, `peer-${port}.key`),
    '--authrpc.port', String(port + 10), '--ipcdisable',
    '--log.file.directory', path.join(root, `logs-${port}`),
    '--consensus.metrics-address', `127.0.0.1:${metricsPort}`,
    '--color', 'never'];
}

let seed;
let mux;
let success = false;
try {
  assert.equal(await rpc(reference, 'eth_chainId'), '0x1079');
  const schedule = await rpc(reference, 'tempo_forkSchedule');
  assert.equal(schedule.active, 'T11', 'this fixed-rule binary only supports the active T11 protocol');
  assert.equal(schedule.schedule.find(f => f.name === 'T11').activationTime, activation);
  let cutover;
  let parent;
  let first;
  if (resume) {
    const saved = JSON.parse(await readFile(path.join(root, 'multiplex.json'), 'utf8'));
    cutover = saved.cutover_block;
    assert.ok(Number.isSafeInteger(cutover) && cutover > 0);
    parent = await rpc(reference, 'eth_getBlockByNumber', [hex(cutover - 1), false]);
    first = await rpc(reference, 'eth_getBlockByNumber', [hex(cutover), false]);
    assert.equal(parent.hash, saved.parent_hash);
  } else {
    seed = start(v1Binary, args(v1Dir, 28546, 30326, 28561), 'checkpoint');
    await ready(v1Rpc, seed);
    const genesis = await rpc(v1Rpc, 'eth_getBlockByNumber', ['0x0', false]);
    assert.equal(genesis.hash, (await rpc(reference, 'eth_getBlockByNumber', ['0x0', false])).hash);
    let low = 1;
    let high = Number(BigInt(await rpc(v1Rpc, 'eth_blockNumber')));
    assert.ok(Number(BigInt((await rpc(v1Rpc, 'eth_getBlockByNumber', [hex(high), false])).timestamp)) >= activation);
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      const block = await rpc(v1Rpc, 'eth_getBlockByNumber', [hex(middle), false]);
      if (Number(BigInt(block.timestamp)) >= activation) high = middle;
      else low = middle + 1;
    }
    cutover = low;
    parent = await rpc(v1Rpc, 'eth_getBlockByNumber', [hex(cutover - 1), false]);
    first = await rpc(v1Rpc, 'eth_getBlockByNumber', [hex(cutover), false]);
    for (const block of [parent, first]) {
      assert.equal(block.hash, (await rpc(reference, 'eth_getBlockByNumber', [block.number, false])).hash);
    }
    await stop(seed);
    seed = undefined;
    await cp(v1Dir, v2Dir, { recursive: true, errorOnExist: true, force: false });
  }
  assert.equal(first.parentHash, parent.hash);
  console.log(JSON.stringify({ phase: 'checkpoint', cutover, parentHash: parent.hash }));
  const config = { listen: '127.0.0.1:28545', cutover_block: cutover, parent_hash: parent.hash,
    v1: { rpc: v1Rpc, binary: v1Binary, args: args(v1Dir, 28546, 30326, 28561) },
    v2: { rpc: v2Rpc, binary: v2Binary, args: args(v2Dir, 28547, 30327, 28562) } };
  const configPath = path.join(root, 'multiplex.json');
  await writeFile(configPath, JSON.stringify(config, null, 2));
  mux = start(muxBinary, ['--config', configPath], 'multiplex');
  await ready(muxRpc, mux);
  assert.equal((await rpc(muxRpc, 'eth_getBlockByNumber', ['0x0', false])).hash,
    (await rpc(reference, 'eth_getBlockByNumber', ['0x0', false])).hash);
  const canonical = { to: token, data: '0x313ce567' };
  for (const [block, backend] of [[parent.number, v1Rpc], [first.number, v2Rpc]]) {
    for (const [method, params] of [
      ['eth_getBlockByNumber', [block, false]],
      ['eth_call', [canonical, block]],
      ['eth_getBlockReceipts', [block]],
      ['debug_traceCall', [canonical, block, { tracer: 'callTracer' }]],
    ]) assert.deepEqual(await response(muxRpc, method, params), await response(backend, method, params));
    assert.equal(await rpc(muxRpc, 'eth_call', [canonical, block]), await rpc(reference, 'eth_call', [canonical, block]));
  }
  const padded = { ...canonical, data: `${canonical.data}${'00'.repeat(32)}` };
  const before = await response(muxRpc, 'eth_call', [padded, parent.number]);
  const after = await response(muxRpc, 'eth_call', [padded, first.number]);
  assert.ok(!before.error, JSON.stringify(before));
  assert.equal(after.error?.code, 3, 'T11 must reject trailing ABI bytes');
  const rejected = await response(v2Rpc, 'eth_call', [canonical, parent.number]);
  assert.match(rejected.error?.message ?? '', /pre-T11/);
  const fees = await rpc(muxRpc, 'eth_feeHistory', ['0x2', first.number, [50]]);
  assert.equal(fees.gasUsedRatio.length, 2);
  assert.equal(fees.baseFeePerGas.length, 3);
  console.log(JSON.stringify({ phase: 'historical-checks-passed', cutover, before, after }));
  let tip;
  for (let i = 0; i < 180; i++) {
    tip = await rpc(muxRpc, 'eth_getBlockByNumber', ['latest', false]);
    const upstream = await rpc(reference, 'eth_getBlockByNumber', ['latest', false]);
    const lag = Number(BigInt(upstream.number) - BigInt(tip.number));
    if (i % 4 === 0) console.log(JSON.stringify({ phase: 'sync', local: tip.number, upstream: upstream.number, lag }));
    if (lag <= 8 && Date.now() / 1000 - Number(BigInt(tip.timestamp)) < 15) break;
    if (i === 179) throw new Error('mainnet catch-up did not complete within 15 minutes');
    await delay(5000);
  }
  assert.equal(tip.hash, (await rpc(reference, 'eth_getBlockByNumber', [tip.number, false])).hash);
  const firstHeight = tip.number;
  await delay(4000);
  const lastHeight = await rpc(muxRpc, 'eth_blockNumber');
  assert.ok(BigInt(lastHeight) > BigInt(firstHeight), 'mainnet follower must advance');
  const report = { chainId: 4217, root, rpc: muxRpc, pid: mux.pid, cutover, parentHash: parent.hash,
    activation, firstHeight, lastHeight, before, after, rejected, reference,
    verifiedAt: new Date().toISOString(), result: 'passed' };
  await writeFile(path.join(root, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report));
  success = true;
  mux.unref();
} finally {
  if (seed) await stop(seed);
  if (mux && !success) await stop(mux);
}
