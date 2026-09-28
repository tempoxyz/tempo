const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const root = __dirname;
const base = 'https://lab.ethpandaops.io/api/v1/mainnet/';
const month = '2026-08';
const sampleDate = '2026-08-30';
const manifest = [];

async function get(table, filters, label) {
  const rows = [];
  let token;
  const seenTokens = new Set();
  for (let page = 0; ; page++) {
    const url = new URL(table, base);
    for (const [key, value] of Object.entries(filters)) url.searchParams.set(key, value);
    url.searchParams.set('page_size', '10000');
    if (token) url.searchParams.set('page_token', token);
    const file = path.join(root, `${label}-${page}.json`);
    let body;
    if (fs.existsSync(file)) {
      body = JSON.parse(fs.readFileSync(file, 'utf8'));
    } else {
      console.error(`Fetching ${url}`);
      const response = await fetch(url, { signal: AbortSignal.timeout(120000) });
      if (!response.ok) throw new Error(`${response.status}: ${await response.text()}`);
      body = await response.json();
      fs.writeFileSync(file, JSON.stringify(body, null, 2) + '\n');
    }
    manifest.push({ url: String(url), file: path.basename(file), rows: body[table]?.length ?? 0 });
    if (body.code || body.error) throw new Error(JSON.stringify(body));
    rows.push(...(body[table] ?? []));
    token = body.next_page_token;
    if (!token) break;
    assert(!seenTokens.has(token), 'Repeated pagination token');
    seenTokens.add(token);
  }
  return rows;
}

const sum = (rows, key) => rows.reduce((n, r) => n + r[key], 0);
const pct = (n, d) => 100 * n / d;

async function main() {
  const filter = { day_start_date_starts_with: month };
  const opcodes = await get('fct_opcode_gas_by_opcode_daily', filter, 'opcode-daily');
  const transactions = await get('fct_execution_transactions_daily', filter, 'transactions-daily');
  const gas = await get('fct_execution_gas_used_daily', filter, 'gas-daily');
  const ops = await get('fct_opcode_ops_daily', filter, 'ops-daily');
  for (const rows of [transactions, gas, ops]) {
    assert.equal(rows.length, 31);
    assert.equal(new Set(rows.map(r => r.day_start_date)).size, 31);
  }
  assert.equal(new Set(opcodes.map(r => `${r.day_start_date}:${r.opcode}`)).size, opcodes.length);
  assert.equal(new Set(opcodes.map(r => r.day_start_date)).size, 31);

  const totals = {
    days: 31,
    blocks: sum(transactions, 'block_count'),
    transactions: sum(transactions, 'total_transactions'),
    gas_used: sum(gas, 'total_gas_used'),
    opcode_executions: sum(opcodes, 'total_count'),
    opcode_gas: sum(opcodes, 'total_gas'),
  };
  const names = ['EXTCODECOPY', 'EXTCODESIZE', 'EXTCODEHASH', 'CALL', 'STATICCALL',
    'DELEGATECALL', 'CALLCODE', 'CODESIZE', 'CODECOPY', 'CREATE', 'CREATE2', 'SLOAD'];
  const statistics = names.map(opcode => {
    const rows = opcodes.filter(r => r.opcode === opcode);
    const count = sum(rows, 'total_count');
    const gas = sum(rows, 'total_gas');
    return {
      opcode, count, per_day: count / 31,
      per_block: count / totals.blocks,
      opcode_share_pct: pct(count, totals.opcode_executions),
      executions_per_transaction: count / totals.transactions,
      transaction_share_upper_bound_pct: Math.min(100, pct(count, totals.transactions)),
      gas, gas_per_execution: gas / count,
      gas_vs_block_gas_pct: pct(gas, totals.gas_used),
      blocks_containing_pct: pct(sum(rows, 'block_count'), totals.blocks),
      error_count: sum(rows, 'total_error_count'),
      plus_1000_gas_each_vs_block_gas_pct: pct(count * 1000, totals.gas_used),
      plus_10000_gas_each_vs_block_gas_pct: pct(count * 10000, totals.gas_used),
    };
  });

  const start = Date.parse(`${sampleDate}T00:00:00Z`) / 1000;
  const blocks = await get('int_execution_block_by_date', {
    // This DateTime64 field is exposed as microseconds, unlike daily-table dates.
    block_date_time_gte: start * 1000000, block_date_time_lt: (start + 86400) * 1000000,
    order_by: 'block_date_time',
  }, 'sample-blocks-us');
  const first = Math.min(...blocks.map(r => r.block_number));
  const last = Math.max(...blocks.map(r => r.block_number));
  const sampleTx = transactions.find(r => r.day_start_date === sampleDate);
  assert.equal(blocks.length, sampleTx.block_count);
  assert.equal(last - first + 1, blocks.length);
  const txRows = await get('int_transaction_opcode_gas', {
    block_number_gte: first, block_number_lte: last, opcode_eq: 'EXTCODECOPY',
    meta_network_name_eq: 'mainnet',
  }, 'extcodecopy-sample-transactions');
  const keys = txRows.map(r => `${r.block_number}:${r.transaction_hash}:${r.opcode}`);
  assert.equal(new Set(keys).size, keys.length);
  const daily = opcodes.find(r => r.day_start_date === sampleDate && r.opcode === 'EXTCODECOPY');
  assert.equal(sum(txRows, 'count'), daily.total_count);
  assert.equal(sum(txRows, 'gas'), daily.total_gas);
  const incidence = {
    date: sampleDate, first_block: first, last_block: last,
    all_transactions: sampleTx.total_transactions,
    transactions_using_extcodecopy: txRows.length,
    transaction_share_pct: pct(txRows.length, sampleTx.total_transactions),
    extcodecopy_executions: sum(txRows, 'count'),
    executions_per_using_transaction: sum(txRows, 'count') / txRows.length,
    max_executions_in_one_transaction: Math.max(...txRows.map(r => r.count)),
  };
  const summary = { retrieved_at: new Date().toISOString(), month, totals, statistics, incidence,
    caveats: [
      'Counts are executions, not distinct users or contracts; they include reverted execution.',
      'No inference of physical disk misses from EVM cold/warm counts.',
      'Transaction incidence is exact only for the sampled day; monthly per-opcode counts provide upper bounds only.',
      'Gas ratios compare gross attributed opcode gas to actual block gas used; not a repricing replay.',
      'The ops/sec daily table drops the first block each day; use sums of per-opcode daily rows for the opcode denominator.',
      'Public data coverage is August, not live September activity; coverage is based on published aggregates.',
    ] };
  fs.writeFileSync(path.join(root, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  console.log(JSON.stringify(summary, null, 2));
}
main().catch(error => { console.error(error); process.exitCode = 1; });
