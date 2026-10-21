#!/usr/bin/env node
// Significance for Zones benchmark latency rows.
//
// Zones journeys cluster around block-timing values, so a raw percentile can jump
// between clusters with no code change. Rows are classified on their p95 with a
// bootstrap confidence interval instead, like bench-e2e-classify.js: a change counts
// only when it clears CI + FLOOR_PCT. The floor covers correlation the journey-level
// bootstrap ignores (journeys share blocks and withdrawal batches). The bootstrap is
// smoothed (Gaussian jitter, Silverman bandwidth): resampling a percentile of a few
// discrete clusters otherwise understates its noise (~3-4% same-commit false positives
// per row in simulation, ~0% smoothed, with the same power on a 20% change).

const fs = require('fs');
const path = require('path');

const BOOTSTRAP_ITERATIONS = 10000;
const FLOOR_PCT = 2;
// Below this a nearest-rank p95 is one of the slowest few journeys, and bootstrapping
// it understates its noise (simulated same-commit false positives: ~5% per row at 20
// journeys, ~1% at 100).
const MIN_JOURNEYS = 100;

// Same edges as the controller's LATENCY_ROWS (tempo-multi-region-benchmark
// scripts/zones_prover/summary.py); null is the client-observed journey latency.
const ROW_EDGES = {
  withdrawal: ['offramp', 'offramp_processed'],
  withdrawal_to_zone: ['offramp', 'offramp_result'],
  withdrawal_zone_to_l1: ['offramp_result', 'offramp_processed'],
  deposit: ['onramp.zone_before', 'onramp.zone_deposit.processed'],
  deposit_to_l1: ['onramp.submission', 'onramp.enqueued'],
  deposit_l1_to_zone: ['onramp.enqueued', 'onramp.zone_deposit.processed'],
  journey: null,
};

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

// txgen's nearest-rank percentile (bench-core metrics::percentile), so the tested change
// matches the report's p95.
function p95(sorted) {
  return sorted[Math.min(Math.floor(sorted.length * 95 / 100), sorted.length - 1)];
}

function sortedCopy(values) {
  return Float64Array.from(values).sort();
}

// txgen's primary milestone: a step's last protocol milestone, else its command finish.
function primaryOffset(step) {
  const milestones = step.milestones || [];
  return milestones.length ? milestones[milestones.length - 1].run_offset_ms : step.finished_offset_ms;
}

// Per-journey samples for each row, rebuilt from txgen's sampled lifecycle traces
// the same way txgen aggregates its "dependency" causal edges. Returns null for a row
// unless every completed journey was traced: a partial sample is the earliest
// journeys, not a random subset.
function journeySamples(report) {
  const instances = (report.sampled_instances || []).filter(i => i.outcome === 'completed');
  const complete = report.completed > 0 && instances.length === report.completed;
  const samples = {};
  for (const [key, edge] of Object.entries(ROW_EDGES)) {
    if (!complete) {
      samples[key] = null;
      continue;
    }
    const values = [];
    for (const instance of instances) {
      if (!edge) {
        values.push(instance.client_observed_e2e_latency_ms);
        continue;
      }
      const steps = Object.fromEntries((instance.steps || []).map(step => [step.id, step]));
      const [source, destination] = edge.map(id => steps[id]);
      if (!source || !destination || !(destination.depends_on || []).includes(source.id)) break;
      values.push(primaryOffset(destination) - primaryOffset(source));
    }
    samples[key] = values.length === instances.length && values.every(Number.isFinite) ? values : null;
  }
  return samples;
}

function gaussian(rand) {
  return Math.sqrt(-2 * Math.log(1 - rand())) * Math.cos(2 * Math.PI * rand());
}

function bandwidth(values) {
  const m = values.reduce((a, b) => a + b, 0) / values.length;
  const sd = Math.sqrt(values.reduce((a, v) => a + (v - m) ** 2, 0) / (values.length - 1));
  return 1.06 * sd * values.length ** -0.2;
}

function bootstrapCiPct(baseline, feature, base, rand) {
  const resampledP95 = (values, h) => {
    const sample = new Float64Array(values.length);
    for (let j = 0; j < values.length; j += 1) {
      sample[j] = values[Math.floor(rand() * values.length)] + h * gaussian(rand);
    }
    return p95(sample.sort());
  };
  const [hBaseline, hFeature] = [bandwidth(baseline), bandwidth(feature)];
  const diffs = new Float64Array(BOOTSTRAP_ITERATIONS);
  for (let i = 0; i < BOOTSTRAP_ITERATIONS; i += 1) {
    diffs[i] = resampledP95(feature, hFeature) - resampledP95(baseline, hBaseline);
  }
  diffs.sort();
  const at = q => diffs[Math.min(Math.floor(diffs.length * q), diffs.length - 1)];
  return ((at(0.975) - at(0.025)) / 2) / base * 100;
}

// Lower latency is better. Rows that do not gate (sub-legs, missing samples, or a
// zero baseline) are informational and never decide the verdict.
function classifyRow(baseline, feature, { endToEnd, rand }) {
  if (!baseline || !feature) {
    return { pct: null, sig: 'neutral', informational: true, informational_reason: 'per-journey samples unavailable' };
  }
  if (baseline.length < MIN_JOURNEYS || feature.length < MIN_JOURNEYS) {
    return { pct: null, sig: 'neutral', informational: true, informational_reason: `needs ${MIN_JOURNEYS} journeys` };
  }
  const base = p95(sortedCopy(baseline));
  if (!(base > 0)) {
    return { pct: null, sig: 'neutral', informational: true, informational_reason: 'zero baseline' };
  }
  const pct = (p95(sortedCopy(feature)) / base - 1) * 100;
  const ciPct = bootstrapCiPct(baseline, feature, base, rand);
  const change = { pct, ci_pct: ciPct, floor_pct: FLOOR_PCT, sig: 'neutral' };
  if (-pct - ciPct > FLOOR_PCT) change.sig = 'good';
  else if (-pct + ciPct < -FLOOR_PCT) change.sig = 'bad';
  if (!endToEnd) {
    change.informational = true;
    change.informational_reason = 'sub-leg';
  }
  return change;
}

function classify(comparison, reports) {
  const rand = rng(42);
  const samples = { baseline: journeySamples(reports.baseline), feature: journeySamples(reports.feature) };
  const changes = {};
  for (const { key, end_to_end: endToEnd } of comparison.rows) {
    changes[key] = classifyRow(samples.baseline[key], samples.feature[key], { endToEnd, rand });
  }
  return changes;
}

function readReports(workDir) {
  const reports = {};
  for (const phase of ['baseline', 'feature']) {
    reports[phase] = JSON.parse(fs.readFileSync(path.join(workDir, phase, 'report.json'), 'utf8'));
  }
  return reports;
}

module.exports = { FLOOR_PCT, MIN_JOURNEYS, ROW_EDGES, journeySamples, classifyRow, classify, readReports };
