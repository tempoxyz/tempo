#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const BOOTSTRAP_ITERATIONS = 10000;
const SIG_EMOJI = { good: '✅', bad: '❌', neutral: '⚪' };

const AXES = {
  latency_mean: { floor: 0.70, lower: true },
  latency_p50: { floor: 0.70, lower: true },
  latency_p90: { floor: 1.35, lower: true },
  latency_p99: { floor: 5.0, lower: true },
  builder_latency_p50: { floor: 0.70, lower: true },
  builder_latency_p90: { floor: 1.35, lower: true },
  builder_latency_p99: { floor: 5.0, lower: true },
  builder_gas_s: { floor: 0.45, lower: false },
  tps: { floor: 0.45, lower: false },
  tps_p50: { floor: 0.70, lower: false },
  tps_p90: { floor: 1.35, lower: false },
  tps_p99: { floor: 5.0, lower: false },
  mgas_s: { floor: 0.45, lower: false },
  block_time_p50: { floor: 0.70, lower: true },
  block_time_p90: { floor: 1.35, lower: true },
  block_time_p99: { floor: 5.0, lower: true },
  validation_latency_p50: { floor: 0.70, lower: true },
  validation_latency_p90: { floor: 1.35, lower: true },
  validation_latency_p99: { floor: 5.0, lower: true },
  validation_gas_s: { floor: 0.45, lower: false },
};

const SECTIONS = [
  {
    title: 'Tempo Metrics',
    rows: [
      ['Latency Mean [ms]', 'latency_mean', v => fmtVal(v, 1)],
      ['Latency P50 [ms]', 'latency_p50', v => fmtVal(v, 1)],
      ['Latency P90 [ms]', 'latency_p90', v => fmtVal(v, 1)],
      ['Latency P99 [ms]', 'latency_p99', v => fmtVal(v, 1)],
      ['Avg TPS', 'tps', v => fmtVal(v, 0)],
      ['TPS P50', 'tps_p50', v => fmtVal(v, 1)],
      ['TPS P90', 'tps_p90', v => fmtVal(v, 1)],
      ['TPS P99', 'tps_p99', v => fmtVal(v, 1)],
      ['Gas Throughput [Mgas/s]', 'mgas_s', v => fmtVal(v, 1)],
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

function fmtChange(change) {
  if (!change || change.pct == null) return '';
  const sign = change.pct >= 0 ? '+' : '';
  const ci = change.ci_pct == null ? '' : ` (+/-${change.ci_pct.toFixed(2)}/floor ${change.floor_pct.toFixed(2)})`;
  return `${sign}${change.pct.toFixed(2)}% ${SIG_EMOJI[change.sig] || ''}${ci}`.trim();
}

function buildMarkdown(summary) {
  const c = summary.classification;
  const lines = [
    `# ${c.emoji} Bench Comparison: ${c.label}`,
    '',
    `**Refs:** ${summary.baseline_ref} vs ${summary.feature_ref}`,
    `**Criteria:** 95% run-bootstrap CI must clear floor; cells show delta (+/-CI/floor).`,
    '',
    '## Configuration',
    `- Bloat: ${summary.config.bloat} MiB`,
    `- Preset: ${summary.config.preset}`,
    `- Target TPS: ${summary.config.tps}`,
    `- Duration: ${summary.config.duration}s`,
    `- Run pairs: ${summary.config.run_pairs}`,
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
    lines.push('');
  }
  return lines.join('\n');
}

function main() {
  const resultsDir = process.argv[2];
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

main();
