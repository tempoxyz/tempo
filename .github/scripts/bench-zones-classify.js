#!/usr/bin/env node
// Significance for Zones benchmark latency rows.
//
// Zones journeys cluster around block-timing values, so a 20-journey p50 can jump
// between clusters with no code change. Rows are classified on the per-journey mean
// with a bootstrap confidence interval instead, like bench-e2e-classify.js: a change
// counts only when it clears CI + FLOOR_PCT. The floor covers correlation the
// journey-level bootstrap ignores (journeys share blocks and withdrawal batches).

const fs = require('fs');
const path = require('path');

const BOOTSTRAP_ITERATIONS = 10000;
const FLOOR_PCT = 2;

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

function mean(values) {
  return values.reduce((a, b) => a + b, 0) / values.length;
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

function bootstrapCiPct(baseline, feature, base, rand) {
  const diffs = new Float64Array(BOOTSTRAP_ITERATIONS);
  for (let i = 0; i < BOOTSTRAP_ITERATIONS; i += 1) {
    let b = 0;
    let f = 0;
    for (let j = 0; j < baseline.length; j += 1) b += baseline[Math.floor(rand() * baseline.length)];
    for (let j = 0; j < feature.length; j += 1) f += feature[Math.floor(rand() * feature.length)];
    diffs[i] = f / feature.length - b / baseline.length;
  }
  diffs.sort();
  const at = q => diffs[Math.min(Math.floor(diffs.length * q), diffs.length - 1)];
  return ((at(0.975) - at(0.025)) / 2) / base * 100;
}

// Lower latency is better. Rows that do not gate (sub-legs, missing samples, or a
// zero baseline) are informational and never decide the verdict.
function classifyRow(baseline, feature, { endToEnd, rand }) {
  if (!baseline || !feature || baseline.length < 2 || feature.length < 2) {
    return { pct: null, sig: 'neutral', informational: true, informational_reason: 'per-journey samples unavailable' };
  }
  const base = mean(baseline);
  if (!(base > 0)) {
    return { pct: null, sig: 'neutral', informational: true, informational_reason: 'zero baseline' };
  }
  const pct = (mean(feature) / base - 1) * 100;
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

module.exports = { FLOOR_PCT, ROW_EDGES, journeySamples, classifyRow, classify, readReports };
