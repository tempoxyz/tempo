// Offline signed-envelope checks only; Tempo inclusion/execution remains required.
// Usage: node validate-aa-access.mjs /path/to/txgen-tempo /path/to/cast
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const [txgen, cast] = process.argv.slice(2);
assert(txgen && cast, 'Pass txgen-tempo and cast binary paths');
const artifact = JSON.parse(readFileSync(new URL('./AccessCalibration.json', import.meta.url)));
const expected = { control: 'control', slot_once: 'slotOnce', call_once: 'callOnce' };
const cases = Object.entries(expected).map(([name, method]) => [`gas-aa-access-${name.replaceAll('_', '-')}-2`, { aa_access: method }]);
cases.push(['gas-aa-access-smoke', expected]);
for (const [preset, methods] of cases) {
  const spec = fileURLToPath(new URL(`../presets/${preset}.yml`, import.meta.url));
  const output = execFileSync(txgen, ['generate', '--spec', spec, '--count', '100', '--seed', '42'], {
    encoding: 'utf8', env: { ...process.env, TXGEN_ACCOUNTS: '16' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const rows = output.trim().split('\n').map(JSON.parse);
  assert.equal(rows.filter(row => row.phase === 'setup').length, 1);
  const workload = rows.filter(row => row.phase === 'workload');
  assert.equal(workload.length, 100);
  assert.equal(new Set(workload.map(row => row.raw)).size, 100, 'Signed payloads must be unique');
  const seen = new Set();
  for (const row of workload) {
    assert(methods[row.id], `Unexpected template ${row.id}`);
    seen.add(row.id);
    const decoded = JSON.parse(execFileSync(cast, ['decode-transaction', '--network', 'tempo', '--json', row.raw], { encoding: 'utf8' }));
    assert.equal(decoded.success, true);
    const tx = JSON.parse(decoded.data);
    assert.equal(tx.type, '0x76');
    assert.equal(tx.chainId, '0x539');
    assert.equal(tx.feeToken, '0x20c0000000000000000000000000000000000000');
    assert.equal(tx.gas, '0x493e0');
    assert.equal(tx.calls.length, 2);
    for (const call of tx.calls) {
      // CREATE address for the public test mnemonic's first account at nonce zero.
      assert.equal(call.to, '0x5fbdb2315678afecb367f032d93f642f64180aa3');
      assert.equal(call.value, '0x0');
      assert.equal(call.input, '0x' + artifact.methodIdentifiers[`${methods[row.id]}()`]);
    }
    assert.equal(tx.nonceKey, '0x' + 'ff'.repeat(32));
    assert.equal(tx.nonce, '0x0');
    assert(BigInt(tx.validBefore) > 0n);
    assert.equal(tx.signature.type, 'secp256k1');
    assert(/^0x[0-9a-f]{40}$/.test(tx.signer));
  }
  assert.deepEqual([...seen].sort(), Object.keys(methods).sort());
  console.log(`${preset}: 100 unique signed transactions, exactly two intended calls each; runtime pending`);
}
