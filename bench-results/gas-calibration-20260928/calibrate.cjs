const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const root = path.resolve(__dirname, '../..');
const sources = {};
function load(file) {
  const bytes = fs.readFileSync(path.join(root, file));
  sources[file] = crypto.createHash('sha256').update(bytes).digest('hex');
  return JSON.parse(bytes);
}
function observation(id, mgas, operations, seconds, scope, notes) {
  assert(mgas > 0 && operations > 0 && seconds > 0);
  const ops = operations / seconds;
  const gasPerOp = mgas * 1e6 / ops;
  const target = 1e9 / ops;
  assert(Math.abs(target - gasPerOp * 1000 / mgas) < 1e-6);
  return { id, kind: 'measured', mgas_per_second: mgas,
    useful_operations_per_second: ops, existing_workload_gas_per_operation: gasPerOp,
    target_gas_per_operation: target, scope, notes };
}

const declared = load('bench-results/declared-storage-20260925/results.json').runs;
const read = declared.find(r => r.scenario === 'declared_read').durability.a;
const write = declared.find(r => r.scenario === 'declared_write').durability.b;
const rd = observation('RD', read.persisted_mgas_per_second, read.slots.slots,
  read.duration_seconds, 'Builder durable frontier (slightly slower than follower)',
  'Existing EIP-2930 lists plus speculative prewarming, not a dedicated declared-key fetcher.');
const wd = observation('WD', write.persisted_mgas_per_second, write.slots.slots,
  write.duration_seconds, 'Follower durable frontier',
  'Backlog grew; provisional service rate from overload, not demonstrated sustainable capacity.');

const controls = load('bench-results/builder-prewarm-control-20260925/experiment.json');
const sload = controls.runs.find(r => r.label === 'sload-off-retry-1').analyses[0];
assert.equal(sload.accesses_per_transaction, 7200);
const rs = observation('RS', sload.chain.mgas_per_second,
  sload.chain.transactions * sload.accesses_per_transaction, sload.duration_seconds,
  'Canonical production / full wall time; builder prewarming disabled',
  'Engine prewarming remains enabled. Large transactions do not establish within-block prewarming bypass.');

const history = load('bench-results/history-state-paths-sustained-20260924-v2/throughput.json');
const serialWrite = history.runs.find(r => r.scenario === 'history_write');
const frontier = serialWrite.durability.b;
const blocks = load(serialWrite.directory + '/report-feature-1.json').blocks
  .filter(b => b.number > frontier.first_state && b.number <= frontier.last_state);
assert.equal(blocks.length, frontier.last_state - frontier.first_state);
assert.equal(blocks.reduce((n, b) => n + b.gas_used, 0), frontier.persisted_gas);
const ws = observation('WS', frontier.persisted_mgas_per_second,
  blocks.reduce((n, b) => n + b.tx_count, 0) * 1024, frontier.duration_seconds,
  'Follower durable frontier; history-dependent writes with speculative prewarming enabled',
  'Older run with different memory controls; backlog grew. One SLOAD plus changed nonzero-to-nonzero SSTORE per unit.');

const bytecode = load('bench-results/bytecode-oom-fix-20260926/results.json');
const b = bytecode.latency;
assert.equal(b.accesses_per_transaction, 2250);
const codeGasPerOp = b.chain.gas_per_transaction / b.accesses_per_transaction;
const codeMgas = bytecode.follower_wall.executed_mgas_per_wall_second;
const bs = observation('BS', codeMgas, codeMgas * 1e6 / codeGasPerOp, 1,
  'Follower executed gas / wall time, including pipeline work; operations inferred from canonical gas mix',
  'Read-only bytecode, OOM-fixed node; warmup catch-up intervention. Not a durable-frontier count. Account record is not independently cold.');
bs.operation_count_kind = 'inferred from measured gas and workload gas per access';

const gain = rd.useful_operations_per_second / rs.useful_operations_per_second;
const bd = { ...bs, id: 'BD', kind: 'estimated',
  mgas_per_second: bs.mgas_per_second * gain,
  useful_operations_per_second: bs.useful_operations_per_second * gain,
  target_gas_per_operation: bs.target_gas_per_operation / gain,
  scope: 'Hypothetical known-target bytecode prefetch; no direct benchmark',
  notes: 'Apply the observed declared/serial storage-read operation-rate ratio to serial code. Mgas/s is equivalent at the serial bytecode workload gas/access, NOT measured access-list gas throughput. May overstate gains if bytes, CPU, staging, or cache capacity limit code prefetch.',
  model_gain: gain, source_ids: ['RD', 'RS', 'BS'] };

const anchors = [rd, rs, wd, ws, bs, bd];
const proxyRows = [
  ['Account metadata read', 'access_list', rd],
  ['Account metadata read', 'serial', rs],
  ['Existing account metadata update', 'access_list', wd],
  ['Existing account metadata update', 'serial', ws],
].map(([operation, mode, anchor]) => ({ operation, mode, kind: 'estimated',
  source_id: anchor.id, proxy_mgas_per_second: anchor.mgas_per_second,
  useful_operations_per_second: anchor.useful_operations_per_second,
  target_gas_per_operation: anchor.target_gas_per_operation,
  note: 'Transfer per-operation service time from the corresponding storage benchmark. Mgas/s is the proxy benchmark rate, not an account-op measurement. Account-table/trie behavior is not isolated.' }));

process.stdout.write(JSON.stringify({ target_gas_per_second: 1e9, anchors, proxy_rows: proxyRows,
  read_prefetch_model_gain: gain, sources_sha256: sources,
  gas_meaning: 'Amortized whole-workload budget per useful resource operation, not an isolated opcode price or additive surcharge. No safety margin.',
  not_calibrated: ['new storage slots', 'account creation', 'deletion/refunds', 'code deployment or replacement', 'sustained mixed workloads', 'account-only cold fixtures', 'dedicated declared-code prefetch'] }, null, 2) + '\n');
