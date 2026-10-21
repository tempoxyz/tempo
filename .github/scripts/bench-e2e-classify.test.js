const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { main } = require('./bench-e2e-classify.js');

function report(t, axis, baseline, feature, config = {}) {
  const metrics = Object.fromEntries([
    'tps', 'mgas_s', 'block_time_mean', 'block_time_p50', 'block_time_p90',
    'block_time_p99', 'builder_gas_s', 'builder_latency_p50',
    'builder_latency_p90', 'builder_latency_p99', 'validation_gas_s',
    'validation_latency_p50', 'validation_latency_p90', 'validation_latency_p99',
  ].map(key => [key, 100]));
  const mean = values => values.reduce((sum, value) => sum + value, 0) / values.length;
  const summary = {
    baseline_ref: 'baseline', feature_ref: 'feature',
    config: { run_side: 'comparison', run_pairs: 3, ...config },
    results: {
      baseline: { ...metrics, [axis]: mean(baseline) },
      feature: { ...metrics, [axis]: mean(feature) },
    },
    per_run: [
      ...baseline.map((value, i) => ({ ...metrics, [axis]: value, label: `baseline-${i}` })),
      ...feature.map((value, i) => ({ ...metrics, [axis]: value, label: `feature-${i}` })),
    ],
  };
  const resultsDir = path.join(__dirname, 'in-memory-results');
  const summaryPath = path.join(resultsDir, 'summary.json');
  const markdownPath = path.join(resultsDir, 'summary.md');
  const output = new Map();
  t.mock.method(fs, 'readFileSync', file => {
    assert.equal(file, summaryPath);
    return JSON.stringify(summary);
  });
  t.mock.method(fs, 'writeFileSync', (file, contents) => {
    assert.ok(file === summaryPath || file === markdownPath);
    output.set(file, contents);
  });
  t.mock.method(console, 'log', () => {});
  main(resultsDir);
  return { summary: JSON.parse(output.get(summaryPath)), markdown: output.get(markdownPath) };
}

for (const axis of ['tps', 'block_time_mean']) {
  for (const feature of [[100, 200, 200], [0, 0, 100]]) {
    test(`${axis}: asymmetric interval touching zero is neutral (${feature})`, t => {
      const { summary, markdown } = report(t, axis, [100, 100, 100], feature);
      const change = summary.results.changes[axis];
      // Each extreme resample has probability 1/27 > 2.5%, fixing both endpoints.
      assert.equal(change.sig, 'neutral');
      assert.equal(summary.classification.label, 'No Difference');
      assert.match(markdown, /^# ⚪ Bench Comparison: No Difference\n/);
      const bounds = feature[0] === 100 ? [0, 100] : [-100, 0];
      assert.deepEqual([change.ci_lower_pct, change.ci_upper_pct], bounds);
      assert.equal(change.ci_pct, 50);
    });
  }
  for (const feature of [[110, 210, 210], [0, 0, 90]]) {
    test(`${axis}: asymmetric interval clearing the floor remains significant (${feature})`, t => {
      const { summary } = report(t, axis, [100, 100, 100], feature);
      const increase = feature[0] === 110;
      const good = increase === (axis === 'tps');
      const change = summary.results.changes[axis];
      assert.equal(change.sig, good ? 'good' : 'bad');
      assert.equal(summary.classification.label, good ? 'Improvement' : 'Regression');
      assert.deepEqual([change.ci_lower_pct, change.ci_upper_pct],
        increase ? [10, 110] : [-100, -10]);
    });
  }
  for (const sign of [-1, 1]) {
    test(`${axis}: interval exactly at the floor is neutral (direction ${sign})`, t => {
      const floorDelta = axis === 'tps' ? 55 : 40;
      const value = 10000 + sign * floorDelta;
      const { summary } = report(t, axis, [10000, 10000, 10000], [value, value, value]);
      assert.equal(summary.results.changes[axis].sig, 'neutral');
      assert.equal(summary.classification.label, 'No Difference');
    });
  }
}

for (const [baseline, feature, reason, config] of [
  [[100], [200], 'insufficient runs', {}],
  [[0, 0, 0], [100, 100, 100], 'zero baseline', {}],
  [[100, 100, 100], [200, 200, 200], 'feature-only run', { run_side: 'feature' }],
  [[100, 100, 100], [200, 200, 200], 'baseline-only run', { run_side: 'baseline' }],
]) {
  test(`${reason} remains informational`, t => {
    const { summary } = report(t, 'tps', baseline, feature, config);
    const change = summary.results.changes.tps;
    assert.equal(change.sig, 'neutral');
    assert.equal(change.informational, true);
    assert.equal(change.informational_reason, reason);
    assert.equal(summary.classification.label, 'No Difference');
    if (reason === 'insufficient runs' || reason === 'zero baseline') {
      assert.equal(change.ci_pct, null);
      assert.equal(change.ci_lower_pct, null);
      assert.equal(change.ci_upper_pct, null);
    }
  });
}
