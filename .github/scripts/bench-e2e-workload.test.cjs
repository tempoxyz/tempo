const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { main } = require('./bench-e2e-classify.js');

test('different workloads cannot receive a code-improvement verdict', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-workload-'));
  try {
    const summary = {
      baseline_ref: 'same-node', feature_ref: 'same-node',
      config: { comparison_kind: 'workload', preset: 'gas-compare:gas-echo,gas-branch',
        baseline_preset: 'gas-echo', feature_preset: 'gas-branch', run_pairs: 3 },
      results: { baseline: { tps: 100, blocks: 30 }, feature: { tps: 200, blocks: 30 } },
      per_run: [1, 2, 3].flatMap(i => [{label: `baseline-${i}`, tps: 100}, {label: `feature-${i}`, tps: 200}]),
    };
    fs.writeFileSync(path.join(directory, 'summary.json'), JSON.stringify(summary));
    main(directory);
    const result = JSON.parse(fs.readFileSync(path.join(directory, 'summary.json')));
    assert.equal(result.classification.label, 'Workload Comparison - Unpriced');
    assert.equal(result.classification.pricing_ready, false);
    assert.equal(result.results.changes.tps.pct, 100);
    assert.equal(result.results.changes.tps.ci_pct, null);
    assert.equal(result.results.changes.validation_gas_s.pct, null);
    assert.ok(Object.values(result.results.changes).every(c => c.informational && c.sig === 'neutral'));
    const markdown = fs.readFileSync(path.join(directory, 'summary.md'), 'utf8');
    assert.match(markdown, /Baseline workload: gas-echo/);
    assert.match(markdown, /Feature workload: gas-branch/);
    assert.match(markdown, /not code improvements or pricing verdicts/);
    assert.doesNotMatch(markdown, /95% run-bootstrap CI|Bench Comparison: Improvement/);
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});

test('ordinary same-workload comparisons retain the existing classifier', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-control-'));
  try {
    const summary = {
      baseline_ref: 'same-node', feature_ref: 'same-node', config: {preset: 'gas-echo', run_pairs: 3},
      results: {baseline: {tps: 100, blocks: 30}, feature: {tps: 100, blocks: 30}},
      per_run: [1, 2, 3].flatMap(i => [{label: `baseline-${i}`, tps: 100}, {label: `feature-${i}`, tps: 100}]),
    };
    fs.writeFileSync(path.join(directory, 'summary.json'), JSON.stringify(summary));
    main(directory);
    const result = JSON.parse(fs.readFileSync(path.join(directory, 'summary.json')));
    assert.equal(result.classification.label, 'No Difference');
    assert.equal(result.classification.method, 'run-cluster-bootstrap');
    assert.equal(result.classification.confidence, 0.95);
    assert.equal(result.results.changes.tps.ci_pct, 0);
    assert.equal(result.results.changes.tps.floor_pct, 0.55);
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});
