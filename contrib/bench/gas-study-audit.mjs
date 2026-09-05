/** Read-only report consistency gate; a pass is never a pricing verdict. */
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const count = value => Number.isSafeInteger(value) && value >= 0;
const read = path => JSON.parse(readFileSync(path, 'utf8'));
const limitations = 'Consistency only. Requires separate output validation, workload inclusion attribution, saturation checks, matched hardware/state/forks, repeated runs, and gas attribution before pricing inference.';

export function audit(directory) {
  const summary = read(join(directory, 'summary.json'));
  const issues = [];
  const runs = [];
  let pairs = summary.config?.run_pairs;
  if (!count(pairs) || pairs === 0) {
    issues.push('comparison requires a positive integer run_pairs');
    pairs = 0;
  }
  const expected = ['baseline', 'feature'].flatMap(side =>
    Array.from({ length: pairs }, (_, index) => `${side}-${index + 1}`));
  const rows = Array.isArray(summary.per_run) ? summary.per_run : [];
  const labels = rows.map(row => row?.label);
  if (new Set(labels).size !== labels.length) issues.push('duplicate summary run labels');
  if (new Set(labels).size !== expected.length || expected.some(label => !labels.includes(label))) {
    issues.push('summary run set does not match requested comparison pairs');
  }
  for (const label of expected.sort()) {
    let raw;
    try {
      raw = read(join(directory, `report-${label}.json`));
    } catch (error) {
      runs.push({ label, issues: [error.code === 'ENOENT' ? 'missing raw report' : 'unreadable raw report'] });
      continue;
    }
    const problems = [];
    const blocks = Array.isArray(raw.blocks) ? raw.blocks : [];
    const numbers = blocks.map(block => block.number);
    const validNumbers = numbers.every(count);
    if (!validNumbers || numbers.some((value, index) => index > 0 && value <= numbers[index - 1])) {
      problems.push('block numbers are invalid, duplicated, or out of order');
    } else if (numbers.some((value, index) => index > 0 && value !== numbers[index - 1] + 1)) {
      problems.push('block range has gaps');
    }
    const keys = ['tx_count', 'ok_count', 'err_count', 'gas_used'];
    const complete = blocks.every(block => keys.every(key => count(block[key])) &&
      block.ok_count + block.err_count === block.tx_count);
    if (!complete) problems.push('raw receipt outcomes are absent or inconsistent');
    const totals = Object.fromEntries(keys.map(key => [key,
      complete ? blocks.reduce((total, block) => total + block[key], 0) : null]));
    if (complete && !Object.values(totals).every(count)) problems.push('raw totals exceed safe integer precision');
    if (!blocks.length || totals.ok_count === 0) problems.push('no successful included transactions');
    if (totals.err_count) problems.push('reverted transactions in ordinary successful-workload run');
    if (!count(raw.failed) || raw.failed !== 0) problems.push('submission failures are present or unknown');
    const row = rows.find(row => row?.label === label);
    if (!row) {
      problems.push('missing retained summary row');
    } else if (complete) {
      const warmup = row.summary_warmup_blocks;
      if (!count(warmup) || warmup > blocks.length) {
        problems.push('invalid summary warmup window');
      } else {
        const retained = blocks.slice(warmup);
        const mappings = { total_tx: 'tx_count', ok: 'ok_count', err: 'err_count', total_gas: 'gas_used' };
        if (row.blocks !== retained.length || Object.entries(mappings).some(([target, source]) =>
          row[target] !== retained.reduce((total, block) => total + block[source], 0))) {
          problems.push('retained summary does not reconcile with raw blocks');
        }
        if (!retained.length || retained.reduce((total, block) => total + block.ok_count, 0) === 0) {
          problems.push('no successful transactions after warmup');
        }
        if (row.receipt_outcomes_complete !== true) problems.push('summary receipt outcomes are not complete');
      }
    }
    runs.push({ label, raw_totals: totals, submission_failed: raw.failed ?? null, issues: problems });
  }
  return {
    benchmark_id: summary.benchmark_id ?? null,
    ordinary_workload_data_valid: !issues.length && runs.every(run => !run.issues.length),
    pricing_ready: false,
    limitations,
    issues,
    runs,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let result;
  try {
    if (process.argv.length !== 3) throw new Error('Usage: node gas-study-audit.mjs RESULTS_DIRECTORY');
    result = audit(process.argv[2]);
  } catch (error) {
    result = {
      ordinary_workload_data_valid: false, pricing_ready: false, limitations,
      issues: [`Unable to audit reports: ${error.message}`], runs: [],
    };
  }
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.ordinary_workload_data_valid ? 0 : 1;
}
