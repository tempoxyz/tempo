#!/usr/bin/env node

const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const { main } = require('./bench-e2e-classify.js');

function metricValues(label, values) {
  return {
    label,
    tps: values.tps,
    mgas_s: values.mgas_s,
    block_time_mean: values.block_time_mean,
    block_time_p50: values.block_time_p50,
    block_time_p90: values.block_time_p90,
    block_time_p99: values.block_time_p99,
    builder_gas_s: 0,
    builder_latency_p50: 0,
    builder_latency_p90: 0,
    builder_latency_p99: 0,
    validation_gas_s: 0,
    validation_latency_p50: 0,
    validation_latency_p90: 0,
    validation_latency_p99: 0,
  };
}

test('single-run e2e comparisons classify large regressions by point estimate', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-e2e-classify-'));
  const baseline = {
    ...metricValues('baseline', {
      tps: 27808,
      mgas_s: 1224.8,
      block_time_mean: 608.8,
      block_time_p50: 605,
      block_time_p90: 714,
      block_time_p99: 793,
    }),
    blocks: 138,
  };
  const feature = {
    ...metricValues('feature', {
      tps: 2,
      mgas_s: 0.1,
      block_time_mean: 509.2,
      block_time_p50: 510,
      block_time_p90: 524,
      block_time_p99: 526,
    }),
    blocks: 167,
  };

  fs.writeFileSync(path.join(dir, 'summary.json'), `${JSON.stringify({
    baseline_ref: 'merge-base',
    feature_ref: 'feature',
    config: {
      preset: 'tip20_existing_recipients',
      bloat: 100000,
      token_count: 4,
      tps: 50000,
      duration: 90,
      run_pairs: 1,
    },
    results: { baseline, feature },
    per_run: [metricValues('baseline-1', baseline), metricValues('feature-1', feature)],
  }, null, 2)}\n`);

  main(dir);

  const summary = JSON.parse(fs.readFileSync(path.join(dir, 'summary.json'), 'utf8'));
  assert.equal(summary.results.changes.tps.sig, 'bad');
  assert.equal(summary.results.changes.tps.method, 'point-estimate');
  assert.equal(summary.results.changes.mgas_s.sig, 'bad');
  assert.notEqual(summary.classification.label, 'No Difference');
});
