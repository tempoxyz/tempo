#!/usr/bin/env node
'use strict';
// Small native-Tempo correctness smoke. This does not measure storage capacity.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const {spawn, execFileSync} = require('node:child_process');
const {ROUTER, word, auditTransaction} = require('./declared-state-path-validation.cjs');
const {preflight} = require('./declared-state-path-preflight.cjs');
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function port() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {server.once('error', reject); server.listen(0, '127.0.0.1', resolve);});
  const value = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return value;
}
async function smoke(tempo, generator) {
  assert.ok(tempo && generator, 'usage: smoke-declared-state-paths.cjs /path/to/tempo /path/to/txgen-tempo');
  tempo = path.resolve(tempo); generator = path.resolve(generator);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'tempo-declared-smoke-'));
  console.log(`SMOKE_DIR=${directory}`);
  const root = path.resolve(__dirname, '../..');
  const genesis = JSON.parse(fs.readFileSync(path.join(root, 'crates/chainspec/src/genesis/dev.json')));
  const artifact = JSON.parse(fs.readFileSync(path.join(__dirname, 'txgen/history-state-paths.json')));
  genesis.alloc[ROUTER] = {nonce: '0x1', balance: '0x0', code: artifact.deployedBytecode.object,
    storage: Object.fromEntries(Array.from({length: 4096}, (_, i) => [word(i), word(i + 1)]))};
  const genesisPath = path.join(directory, 'genesis.json');
  fs.writeFileSync(genesisPath, JSON.stringify(genesis));
  const http = await port(), auth = await port(), p2p = await port();
  const log = fs.openSync(path.join(directory, 'node.log'), 'w');
  const child = spawn(tempo, ['node', '--dev', '--chain', genesisPath, '--datadir', path.join(directory, 'node'),
    '--http', '--http.addr', '127.0.0.1', '--http.port', String(http), '--http.api', 'eth,debug,web3,net,txpool',
    '--authrpc.port', String(auth), '--port', String(p2p), '--disable-discovery', '--ipcdisable', '--dev.block-time', '200ms'],
    {stdio: ['ignore', log, log]});
  fs.closeSync(log);
  let spawnError;
  child.once('error', error => {spawnError = error;});
  const exited = new Promise(resolve => child.once('close', resolve));
  const rpc = async (_node, method, params = []) => {
    const response = await fetch(`http://127.0.0.1:${http}`, {method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({jsonrpc: '2.0', id: 1, method, params}), signal: AbortSignal.timeout(20000)});
    const data = await response.json(); assert.ok(!data.error, `${method}: ${JSON.stringify(data.error)}`); return data.result;
  };
  try {
    const deadline = Date.now() + 45000;
    for (;;) {
      assert.ok(!spawnError && child.exitCode === null, `Tempo exited: ${spawnError || child.exitCode}; see ${directory}/node.log`);
      try { assert.equal(BigInt(await rpc('b', 'eth_chainId')), 1337n); break; }
      catch (error) { if (Date.now() >= deadline) throw error; await sleep(200); }
    }
    const results = [];
    for (const scenario of ['declared_read', 'declared_write']) for (const count of [1, 128, 256]) {
      const env = {...process.env, TXGEN_ACCOUNTS: '10', TXGEN_STATE_ACCESSES: String(count), TXGEN_DECLARED_MAX_START: String(4096 - count)};
      const preset = path.join(__dirname, `txgen/presets/${scenario}.yml`);
      preflight(generator, preset, path.join(directory, `${scenario}-${count}.preflight.json`), env);
      const rows = execFileSync(generator, ['generate', '-s', preset, '-n', '2', '--seed', '42'],
        {env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000}).trim().split('\n').map(JSON.parse);
      for (const row of rows) {
        assert.ok(row.raw.startsWith('0x76'), 'expected signed native Tempo envelope');
        const hash = await rpc('b', 'eth_sendRawTransaction', [row.raw]);
        const deadline = Date.now() + 30000;
        let receipt;
        while (!(receipt = await rpc('b', 'eth_getTransactionReceipt', [hash]))) {
          assert.ok(Date.now() < deadline, `receipt timeout ${hash}`); await sleep(100);
        }
        assert.equal(BigInt(receipt.status), 1n);
        const audit = await auditTransaction(rpc, hash, Number(BigInt(receipt.blockNumber)), scenario,
          {page_count: 1, declared_accesses: count}, directory);
        results.push({scenario, count, gas_used: Number(BigInt(receipt.gasUsed)), ...audit});
      }
      console.log(`${scenario}: ${count} slots, two signed transactions audited`);
    }
    fs.writeFileSync(path.join(directory, 'results.json'), JSON.stringify({ok: true, results}, null, 2) + '\n');
    return results;
  } finally {
    if (child.exitCode === null) {
      child.kill('SIGTERM');
      const force = setTimeout(() => child.kill('SIGKILL'), 5000);
      await exited;
      clearTimeout(force);
    }
    // Retain the small genesis, receipts/traces and log, not the scratch database.
    fs.rmSync(path.join(directory, 'node'), {recursive: true, force: true});
  }
}
module.exports = {smoke};
if (require.main === module) smoke(...process.argv.slice(2)).catch(error => {console.error(error); process.exitCode = 1;});
