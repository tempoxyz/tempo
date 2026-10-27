// Zones latency significance: resample measured journeys without synthetic jitter.
// Score only non-degenerate 95% bootstrap intervals excluding zero; no extra floor.
// This estimates within-run sampling uncertainty, not run-to-run environment variation.
// Below MIN_JOURNEYS there are too few tail observations for a verdict.
const fs = require('fs');
const path = require('path');
const { rng } = require('./bench-e2e-classify');

const MIN_JOURNEYS = 100;
const MIN_GROUPS = 20;
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

// Keep contemporaneous journeys together. One median journey duration per window
// captures local shared-load/block-timing effects without another benchmark setup.
// This is a temporal-cluster approximation, not a guarantee of independence.
function temporalGroups(instances) {
  if (!instances.every(i => Number.isFinite(i.started_at_unix_ms) &&
      Number.isFinite(i.finished_at_unix_ms) && i.finished_at_unix_ms > i.started_at_unix_ms)) return null;
  const durations = instances.map(i => i.finished_at_unix_ms - i.started_at_unix_ms).sort((a, b) => a - b);
  const width = durations[Math.floor(durations.length / 2)];
  const start = Math.min(...instances.map(i => i.started_at_unix_ms));
  const groups = new Map();
  instances.forEach((i, index) => {
    const key = Math.floor((i.started_at_unix_ms - start) / width);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(index);
  });
  return [...groups.values()];
}

function resampler(values, groups, rand) {
  return () => {
    const sample = [];
    for (let j = 0; j < groups.length; j += 1) {
      for (const index of groups[Math.floor(rand() * groups.length)]) sample.push(values[index]);
    }
    return p95(sample.sort((a, b) => a - b));
  };
}

// Use interval endpoints: discrete/asymmetric bootstrap intervals need not be
// centred on the observed change. A collapsed interval cannot establish certainty.
function sig(baseline, feature, groups, rand) {
  const [b, f] = [baseline, feature].map((values, i) => resampler(values, groups[i], rand));
  const diffs = Float64Array.from({ length: 10000 }, () => f() - b()).sort();
  const [low, high] = [diffs[250], diffs[9750]];
  if (low === high) return null;
  return high < 0 ? 'good' : low > 0 ? 'bad' : 'neutral';
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
  const groups = traces.map(temporalGroups);
  if (groups.some(g => !g)) return { changes, reason: 'Missing or invalid journey timing for temporal grouping.' };
  if (groups.some(g => g.length < MIN_GROUPS)) {
    return { changes, reason: `At least ${MIN_GROUPS} temporal groups per phase are required.` };
  }
  const reasons = [];
  const rand = rng(42);
  for (const { key, end_to_end: endToEnd } of rows) {
    const [b, f] = traces.map(instances => endToEnd && key in EDGES && samples(instances, EDGES[key]));
    if (b && f) {
      const verdict = sig(b, f, groups, rand);
      if (verdict) changes[key] = { sig: verdict };
      else reasons.push(`${key}: insufficient tail variation to estimate uncertainty.`);
    }
  }
  return { changes, reason: reasons.join(' ') || (Object.keys(changes).length ? '' : 'No valid end-to-end latency samples.') };
}

module.exports = { classify };
