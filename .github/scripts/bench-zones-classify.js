// Zones latency significance: resample measured journeys without synthetic jitter.
// An end-to-end row counts when its p95 change clears the bootstrap uncertainty, with no extra floor.
// This estimates within-run sampling uncertainty, not run-to-run environment variation.
// Below MIN_JOURNEYS there are too few tail observations for a verdict.
const fs = require('fs');
const path = require('path');
const { rng } = require('./bench-e2e-classify');

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
// "dependency" edges; null if a latency is missing or invalid.
function samples(instances, edge) {
  const values = instances.map(instance => {
    if (!edge) return instance.client_observed_e2e_latency_ms;
    const [source, destination] = edge.map(id => instance.steps.find(step => step.id === id));
    return source && destination ? offset(destination) - offset(source) : NaN;
  });
  return values.every(Number.isFinite) ? values : null;
}

function resampler(values, rand) {
  const sample = new Float64Array(values.length);
  return () => {
    for (let j = 0; j < values.length; j += 1) {
      sample[j] = values[Math.floor(rand() * values.length)];
    }
    return p95(sample.sort());
  };
}

// Lower is better: 'good' when the p95 drop exceeds bootstrap uncertainty, 'bad' for a rise.
function sig(baseline, feature, rand) {
  const base = p95(Float64Array.from(baseline).sort());
  if (!(base > 0)) return 'neutral';
  const pct = (p95(Float64Array.from(feature).sort()) / base - 1) * 100;
  const [b, f] = [resampler(baseline, rand), resampler(feature, rand)];
  const diffs = Float64Array.from({ length: 10000 }, () => f() - b()).sort();
  const ciPct = (diffs[9750] - diffs[250]) / 2 / base * 100;
  return Math.abs(pct) > ciPct ? (pct < 0 ? 'good' : 'bad') : 'neutral';
}

function classify(rows, workDir) {
  const changes = {};
  const traces = [];
  for (const phase of ['baseline', 'feature']) {
    const report = JSON.parse(fs.readFileSync(path.join(workDir, phase, 'report.json'), 'utf8'));
    if (!Number.isInteger(report.completed) || report.completed < 0) throw new Error(`${phase}: invalid completed count`);
    const instances = (report.sampled_instances || []).filter(i => i.outcome === 'completed');
    if (instances.length !== report.completed) {
      return { changes, reason: `${phase}: retained ${instances.length} of ${report.completed} completed journey traces; all are required.` };
    }
    if (instances.length < MIN_JOURNEYS) {
      return { changes, reason: `${phase}: only ${report.completed} completed journeys; at least ${MIN_JOURNEYS} are required.` };
    }
    traces.push(instances);
  }
  const rand = rng(42);
  for (const { key, end_to_end: endToEnd } of rows) {
    const [b, f] = traces.map(instances => endToEnd && key in EDGES && samples(instances, EDGES[key]));
    if (b && f) changes[key] = { sig: sig(b, f, rand) };
  }
  return { changes, reason: Object.keys(changes).length ? '' : 'No valid end-to-end latency samples.' };
}

module.exports = { classify };
