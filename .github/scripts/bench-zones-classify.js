// Zones latency significance. Journeys cluster on block timing, so raw percentiles jump
// with no code change; an end-to-end row counts only when its p95 change clears a 95%
// bootstrap CI plus FLOOR_PCT, like bench-e2e-classify.js. The bootstrap is smoothed
// (Silverman bandwidth) because resampling a few discrete clusters understates noise;
// below MIN_JOURNEYS the p95 is one of the slowest few journeys, so there is no verdict.
const fs = require('fs');
const path = require('path');
const { rng } = require('./bench-e2e-classify');

const FLOOR_PCT = 2;
const MIN_JOURNEYS = 100;
// End-to-end rows of the controller's LATENCY_ROWS; null is the whole client-observed journey.
const EDGES = {
  withdrawal: ['offramp', 'offramp_processed'],
  deposit: ['onramp.zone_before', 'onramp.zone_deposit.processed'],
  journey: null,
};

// txgen's nearest-rank percentile, so the tested p95 is the report's.
const p95 = sorted => sorted[Math.min(Math.floor(sorted.length * 0.95), sorted.length - 1)];
// txgen's primary milestone: a step's last protocol milestone, else its command finish.
const offset = step => step.milestones?.at(-1)?.run_offset_ms ?? step.finished_offset_ms;

// Per-journey latencies rebuilt from txgen's lifecycle traces the way it aggregates
// "dependency" edges; null unless every journey was traced (a partial trace is the earliest).
function samples(report, edge) {
  const instances = (report.sampled_instances || []).filter(i => i.outcome === 'completed');
  if (instances.length < MIN_JOURNEYS || instances.length !== report.completed) return null;
  const values = instances.map(instance => {
    if (!edge) return instance.client_observed_e2e_latency_ms;
    const [source, destination] = edge.map(id => instance.steps.find(step => step.id === id));
    return source && destination ? offset(destination) - offset(source) : NaN;
  });
  return values.every(Number.isFinite) ? values : null;
}

function resampler(values, rand) {
  const mean = values.reduce((a, b) => a + b) / values.length;
  const sd = Math.sqrt(values.reduce((a, v) => a + (v - mean) ** 2, 0) / (values.length - 1));
  const h = 1.06 * sd * values.length ** -0.2;
  const sample = new Float64Array(values.length);
  return () => {
    for (let j = 0; j < values.length; j += 1) {
      const noise = Math.sqrt(-2 * Math.log(1 - rand())) * Math.cos(2 * Math.PI * rand());
      sample[j] = values[Math.floor(rand() * values.length)] + h * noise;
    }
    return p95(sample.sort());
  };
}

// Lower is better: 'good' when the p95 drops by more than CI + floor, 'bad' when it rises.
function sig(baseline, feature, rand) {
  const base = p95(Float64Array.from(baseline).sort());
  if (!(base > 0)) return 'neutral';
  const pct = (p95(Float64Array.from(feature).sort()) / base - 1) * 100;
  const [b, f] = [resampler(baseline, rand), resampler(feature, rand)];
  const diffs = Float64Array.from({ length: 10000 }, () => f() - b()).sort();
  const ciPct = (diffs[9750] - diffs[250]) / 2 / base * 100;
  return Math.abs(pct) - ciPct > FLOOR_PCT ? (pct < 0 ? 'good' : 'bad') : 'neutral';
}

function classify(rows, workDir) {
  const [baseline, feature] = ['baseline', 'feature'].map(phase =>
    JSON.parse(fs.readFileSync(path.join(workDir, phase, 'report.json'), 'utf8')));
  const rand = rng(42);
  const changes = {};
  for (const { key, end_to_end: endToEnd } of rows) {
    const [b, f] = [baseline, feature].map(report => endToEnd && key in EDGES && samples(report, EDGES[key]));
    if (b && f) changes[key] = { sig: sig(b, f, rand) };
  }
  return changes;
}

module.exports = { classify };
