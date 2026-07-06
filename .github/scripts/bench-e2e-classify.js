#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const BOOTSTRAP_ITERATIONS = 10000;
const SIG_EMOJI = { good: '✅', bad: '❌', neutral: '⚪' };

const AXES = {
  builder_latency_p50: { floor: 0.45, lower: true },
  builder_latency_p90: { floor: 0.90, lower: true },
  builder_latency_p99: { floor: 1.25, lower: true },
  builder_gas_s: { floor: 0.95, lower: false },
  tps: { floor: 0.55, lower: false },
  mgas_s: { floor: 0.50, lower: false },
  block_time_mean: { floor: 0.40, lower: true },
  block_time_p50: { floor: 0.70, lower: true },
  block_time_p90: { floor: 0.70, lower: true },
  block_time_p99: { floor: 1.60, lower: true },
  validation_latency_p50: { floor: 1.55, lower: true },
  validation_latency_p90: { floor: 1.55, lower: true },
  validation_latency_p99: { floor: 2.05, lower: true },
  validation_gas_s: { floor: 0.65, lower: false },
};

const SECTIONS = [
  {
    title: 'Tempo Metrics',
    rows: [
      ['TPS Mean', 'tps', v => fmtVal(v, 0)],
      ['Gas Throughput [Mgas/s]', 'mgas_s', v => fmtVal(v, 1)],
      ['Block Time Mean [ms]', 'block_time_mean', v => fmtVal(v, 1)],
      ['Block Time P50 [ms]', 'block_time_p50', v => fmtVal(v, 1)],
      ['Block Time P90 [ms]', 'block_time_p90', v => fmtVal(v, 1)],
      ['Block Time P99 [ms]', 'block_time_p99', v => fmtVal(v, 1)],
    ],
  },
  {
    title: 'Builder',
    rows: [
      ['Gas Throughput [Mgas/s]', 'builder_gas_s', v => fmtVal(v / 1_000_000, 1)],
      ['P50 [ms]', 'builder_latency_p50', v => fmtVal(v, 1)],
      ['P90 [ms]', 'builder_latency_p90', v => fmtVal(v, 1)],
      ['P99 [ms]', 'builder_latency_p99', v => fmtVal(v, 1)],
    ],
  },
  {
    title: 'Validator',
    rows: [
      ['Gas Throughput [Mgas/s]', 'validation_gas_s', v => fmtVal(v / 1_000_000, 1)],
      ['P50 [ms]', 'validation_latency_p50', v => fmtVal(v, 1)],
      ['P90 [ms]', 'validation_latency_p90', v => fmtVal(v, 1)],
      ['P99 [ms]', 'validation_latency_p99', v => fmtVal(v, 1)],
    ],
  },
];

const BUILDER_DETAIL_ROWS = [
  ['Finish P50 [ms]', 'builder_finish_p50', v => fmtVal(v, 1)],
  ['Finish P90 [ms]', 'builder_finish_p90', v => fmtVal(v, 1)],
  ['Finish P99 [ms]', 'builder_finish_p99', v => fmtVal(v, 1)],
  ['Pool Fetch P50 [ms]', 'builder_pool_fetch_p50', v => fmtVal(v, 1)],
  ['Pool Fetch P90 [ms]', 'builder_pool_fetch_p90', v => fmtVal(v, 1)],
  ['Pool Fetch P99 [ms]', 'builder_pool_fetch_p99', v => fmtVal(v, 1)],
  ['Included Tx Exec P50 [ms]', 'builder_included_tx_execution_p50', v => fmtVal(v, 1)],
  ['Included Tx Exec P90 [ms]', 'builder_included_tx_execution_p90', v => fmtVal(v, 1)],
  ['Included Tx Exec P99 [ms]', 'builder_included_tx_execution_p99', v => fmtVal(v, 1)],
  ['Invalid Tx Exec P50 [ms]', 'builder_invalid_tx_execution_p50', v => fmtVal(v, 1)],
  ['Invalid Tx Exec P90 [ms]', 'builder_invalid_tx_execution_p90', v => fmtVal(v, 1)],
  ['Invalid Tx Exec P99 [ms]', 'builder_invalid_tx_execution_p99', v => fmtVal(v, 1)],
  ['Invalid Tx Attempts P50', 'builder_invalid_tx_execution_attempts_p50', v => fmtVal(v, 1)],
  ['Invalid Tx Attempts P90', 'builder_invalid_tx_execution_attempts_p90', v => fmtVal(v, 1)],
  ['Invalid Tx Attempts P99', 'builder_invalid_tx_execution_attempts_p99', v => fmtVal(v, 1)],
  ['Reverted Txs', 'builder_reverted_txs', v => fmtVal(v, 0)],
  ['Invalid Tx Skips', 'builder_invalid_tx_skips', v => fmtVal(v, 0)],
  ['Nonce Too Low Skips', 'builder_nonce_too_low_skips', v => fmtVal(v, 0)],
  ['Serialized Block Size P50 [KiB]', 'serialized_block_size_p50', fmtKiB],
  ['Serialized Block Size P90 [KiB]', 'serialized_block_size_p90', fmtKiB],
  ['Serialized Block Size P99 [KiB]', 'serialized_block_size_p99', fmtKiB],
  ['Serialized Block Size / Tx P50 [B/tx]', 'serialized_block_size_per_tx_p50', v => fmtVal(v, 1)],
  ['Serialized Block Size / Tx P90 [B/tx]', 'serialized_block_size_per_tx_p90', v => fmtVal(v, 1)],
  ['Serialized Block Size / Tx P99 [B/tx]', 'serialized_block_size_per_tx_p99', v => fmtVal(v, 1)],
  ['Fill Overhead P50 [ms]', 'builder_fill_overhead_p50', v => fmtVal(v, 1)],
  ['Fill Overhead P90 [ms]', 'builder_fill_overhead_p90', v => fmtVal(v, 1)],
  ['Fill Overhead P99 [ms]', 'builder_fill_overhead_p99', v => fmtVal(v, 1)],
  ['Fill Idle P50 [ms]', 'builder_fill_idle_p50', v => fmtVal(v, 1)],
  ['Fill Idle P90 [ms]', 'builder_fill_idle_p90', v => fmtVal(v, 1)],
  ['Fill Idle P99 [ms]', 'builder_fill_idle_p99', v => fmtVal(v, 1)],
];

function rng(seed) {
  let state = seed >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pct(base, feature) {
  return base > 0 ? ((feature - base) / base) * 100 : 0;
}

function mean(values) {
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0;
}

function quantile(sorted, q) {
  if (sorted.length === 0) return 0;
  const idx = Math.min(Math.floor(sorted.length * q), sorted.length - 1);
  return sorted[idx];
}

function bootstrapCiPct(baseline, feature, base, rand) {
  if (baseline.length < 2 || feature.length < 2 || base <= 0) return null;

  const diffs = [];
  for (let i = 0; i < BOOTSTRAP_ITERATIONS; i += 1) {
    let b = 0;
    let f = 0;
    for (let j = 0; j < baseline.length; j += 1) {
      b += baseline[Math.floor(rand() * baseline.length)];
    }
    for (let j = 0; j < feature.length; j += 1) {
      f += feature[Math.floor(rand() * feature.length)];
    }
    diffs.push((f / feature.length) - (b / baseline.length));
  }
  diffs.sort((a, b) => a - b);
  return ((quantile(diffs, 0.975) - quantile(diffs, 0.025)) / 2) / base * 100;
}

function axisChange(axis, summary, baselineRuns, featureRuns, rand) {
  const meta = AXES[axis];
  const runSide = summary.config?.run_side || 'comparison';
  const base = summary.results.baseline[axis];
  const feature = summary.results.feature[axis];
  const changePct = pct(base, feature);
  const baseline = baselineRuns.map(r => r[axis]).filter(Number.isFinite);
  const featureValues = featureRuns.map(r => r[axis]).filter(Number.isFinite);
  const ciPct = bootstrapCiPct(baseline, featureValues, base, rand);
  const change = {
    pct: Number(changePct.toFixed(4)),
    ci_pct: ciPct == null ? null : Number(ciPct.toFixed(4)),
    floor_pct: meta.floor,
    sig: 'neutral',
  };

  if (runSide !== 'comparison') {
    change.informational = true;
    change.informational_reason = `${runSide}-only run`;
    return change;
  }

  if (base <= 0 || ciPct == null) {
    change.informational = true;
    change.informational_reason = base <= 0 ? 'zero baseline' : 'insufficient runs';
    return change;
  }

  const improvement = meta.lower ? -changePct : changePct;
  if (improvement - ciPct > meta.floor) {
    change.sig = 'good';
  } else if (improvement + ciPct < -meta.floor) {
    change.sig = 'bad';
  }
  return change;
}

function verdict(changes) {
  const values = Object.values(changes).filter(v => !v.informational);
  const hasBad = values.some(v => v.sig === 'bad');
  const hasGood = values.some(v => v.sig === 'good');
  if (hasBad && hasGood) return { emoji: '⚠️', slack_emoji: ':warning:', label: 'Mixed Results' };
  if (hasBad) return { emoji: '❌', slack_emoji: ':x:', label: 'Regression' };
  if (hasGood) return { emoji: '✅', slack_emoji: ':white_check_mark:', label: 'Improvement' };
  return { emoji: '⚪', slack_emoji: ':white_circle:', label: 'No Difference' };
}

function fmtVal(value, precision) {
  return Number.isFinite(value) ? value.toFixed(precision) : '-';
}

function fmtKiB(value) {
  return Number.isFinite(value) ? (value / 1024).toFixed(1) : '-';
}

function fmtChange(change) {
  if (!change || change.pct == null) return '';
  const sign = change.pct >= 0 ? '+' : '';
  const ci = change.ci_pct == null ? '' : ` (+/-${change.ci_pct.toFixed(2)}/floor ${change.floor_pct.toFixed(2)})`;
  return `${sign}${change.pct.toFixed(2)}% ${SIG_EMOJI[change.sig] || ''}${ci}`.trim();
}

function fmtInfoChange(base, feature) {
  if (!Number.isFinite(base) || !Number.isFinite(feature)) return '';
  if (base === 0) return feature === 0 ? '0.00%' : 'n/a';
  const change = pct(base, feature);
  const sign = change >= 0 ? '+' : '';
  return `${sign}${change.toFixed(2)}%`;
}

function appendBuilderDetails(lines, summary) {
  lines.push('');
  lines.push('<details><summary>Builder details</summary>');
  lines.push('');
  lines.push('| Metric | Baseline | Feature | Delta |');
  lines.push('|--------|----------|---------|-------|');
  for (const [label, axis, formatter] of BUILDER_DETAIL_ROWS) {
    const base = summary.results.baseline[axis];
    const feature = summary.results.feature[axis];
    lines.push(`| ${label} | ${formatter(base)} | ${formatter(feature)} | ${fmtInfoChange(base, feature)} |`);
  }
  lines.push('');
  lines.push('</details>');
}

function buildMarkdown(summary) {
  const c = summary.classification;
  const derekCommand = summary.config?.derek_command || '';
  const baselineRemovedArgs = summary.config?.baseline_removed_args || '';
  const featureRemovedArgs = summary.config?.feature_removed_args || '';
  const runSide = summary.config?.run_side || 'comparison';
  const featureOnly = runSide === 'feature';
  const baselineOnly = runSide === 'baseline';
  const lines = [
    featureOnly ? `# ${c.emoji} Feature Bench: ${c.label}` : baselineOnly ? `# ${c.emoji} Baseline Bench: ${c.label}` : `# ${c.emoji} Bench Comparison: ${c.label}`,
    '',
    `**Refs:** ${summary.baseline_ref} vs ${summary.feature_ref}`,
    featureOnly ? `**Criteria:** Feature-only run; baseline columns are intentionally empty.` : baselineOnly ? `**Criteria:** Baseline-only run; feature columns are intentionally empty.` : `**Criteria:** 95% run-bootstrap CI must clear floor; cells show delta (+/-CI/floor).`,
    '',
    '## Configuration',
    ...(derekCommand ? [`- Derek command: \`${derekCommand}\``] : []),
    `- Bloat: ${summary.config.bloat} MiB`,
    `- Token count: ${summary.config.token_count ?? 4}`,
    `- Preset: ${summary.config.preset}`,
    `- Target TPS: ${summary.config.tps}`,
    `- Duration: ${summary.config.duration}s`,
    `- Run pairs: ${summary.config.run_pairs}`,
    ...(runSide !== 'comparison' ? [`- Run side: ${runSide}`] : []),
    ...(baselineRemovedArgs ? [`- Baseline removed args: \`${baselineRemovedArgs}\``] : []),
    ...(featureRemovedArgs ? [`- Feature removed args: \`${featureRemovedArgs}\``] : []),
    `- Baseline blocks: ${summary.results.baseline.blocks}`,
    `- Feature blocks: ${summary.results.feature.blocks}`,
    '',
  ];

  for (const section of SECTIONS) {
    lines.push(`## ${section.title}`, '');
    lines.push('| Metric | Baseline | Feature | Delta |');
    lines.push('|--------|----------|---------|-------|');
    for (const [label, axis, formatter] of section.rows) {
      const b = formatter(summary.results.baseline[axis]);
      const f = formatter(summary.results.feature[axis]);
      lines.push(`| ${label} | ${b} | ${f} | ${fmtChange(summary.results.changes[axis])} |`);
    }
    if (section.title === 'Builder') appendBuilderDetails(lines, summary);
    lines.push('');
  }
  return lines.join('\n');
}

function main(resultsDir = process.argv[2]) {
  if (!resultsDir) {
    console.error('usage: bench-e2e-classify.js <results-dir>');
    process.exit(2);
  }

  const summaryPath = path.join(resultsDir, 'summary.json');
  const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
  const runs = summary.per_run || [];
  const baselineRuns = runs.filter(r => /^baseline/.test(r.label));
  const featureRuns = runs.filter(r => /^feature/.test(r.label));
  const rand = rng(42);

  const changes = {};
  for (const axis of Object.keys(AXES)) {
    changes[axis] = axisChange(axis, summary, baselineRuns, featureRuns, rand);
  }

  summary.results.changes = changes;
  summary.classification = {
    ...verdict(changes),
    method: 'run-cluster-bootstrap',
    confidence: 0.95,
    bootstrap_iterations: BOOTSTRAP_ITERATIONS,
  };

  fs.writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  fs.writeFileSync(path.join(resultsDir, 'summary.md'), `${buildMarkdown(summary)}\n`);
  console.log(`${summary.classification.emoji} ${summary.classification.label}`);
}

if (require.main === module) {
  main();
}

module.exports = { main };
