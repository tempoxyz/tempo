#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const root = path.resolve(process.argv[2] || 'bench-results/bytecode-latency-breakdown-20260927');
const read = name => fs.readFileSync(path.join(root, name), 'utf8').trim().split('\n').map(JSON.parse);
const sum = (rows, fn) => rows.reduce((total, row) => total + fn(row), 0);
function summarize(rows) {
  const operations = sum(rows, row => row.records ?? row.operations);
  const mean = key => sum(rows, row => row[key] || 0) / operations;
  const trialMeans = rows.map(row => row.wall_us / (row.records ?? row.operations));
  const wall = mean('wall_us');
  const cpu = rows[0].kind === 'codec' ? mean('cpu_us') : mean('user_us') + mean('system_us');
  const sd = Math.sqrt(sum(trialMeans, value => (value - wall) ** 2) / (rows.length - 1));
  const result = {
    trials: rows.length, operations, wall_us: wall, cpu_us: cpu, off_cpu_us: wall - cpu,
    trial_wall_min_us: Math.min(...trialMeans), trial_wall_max_us: Math.max(...trialMeans),
    trial_wall_sd_us: sd,
    read_requests_per_operation: mean('read_ios'), read_bytes_per_operation: mean('read_bytes'),
    major_faults_per_operation: mean('major_faults'), minor_faults_per_operation: mean('minor_faults'),
  };
  if (rows[0].kind === 'codec') {
    result.decode_us = mean('decode_us');
    result.drop_us = mean('drop_us');
  } else {
    result.user_us = mean('user_us');
    result.system_us = mean('system_us');
    result.stages = Object.fromEntries(Object.keys(rows[0].stages).map(stage => [stage, {
      wall_us: sum(rows, row => row.stages[stage].wall_us) / operations,
      cpu_us: sum(rows, row => row.stages[stage].cpu_us) / operations,
    }]));
  }
  return result;
}
function group(rows, key) {
  return Object.fromEntries([...new Set(rows.map(key))].map(name => [name, summarize(rows.filter(row => key(row) === name))]));
}

const result = {generated_at: new Date().toISOString(), runs: {}};
for (const name of ['a', 'traced', 'builder']) {
  const rows = read(`latency-${name}.jsonl`);
  const residency = rows.filter(row => row.kind === 'residency');
  assert.equal(residency.length, 90);
  assert(residency.every(row => row.resident_pages === 0));
  const measurements = rows.filter(row => row.kind === 'latency');
  assert.equal(measurements.length, 198);
  const warm = measurements.filter(row => row.temperature === 'warm');
  assert(warm.every(row => row.read_ios === 0 && row.read_bytes === 0 && row.major_faults === 0));
  result.runs[name] = {
    metadata: rows.find(row => row.kind === 'latency_metadata'),
    calibration: rows.find(row => row.kind === 'timer_calibration'),
    residency_checks: residency.length,
    cold: group(measurements.filter(row => row.temperature === 'cold'), row => row.mode),
    warm: group(warm, row => row.mode),
  };
}
const wide = read('latency-wide.jsonl').filter(row => row.kind === 'latency' && row.temperature === 'warm');
assert.equal(wide.length, 10);
assert(wide.every(row => row.read_ios === 0 && row.read_bytes === 0 && row.major_faults === 0));
result.wide_source = group(wide, row => row.mode);
result.codecs = {};
for (const allocator of ['jemalloc', 'system']) {
  const rows = read(`codec-${allocator}.jsonl`);
  assert.equal(rows.length, 24);
  assert(rows.every(row => row.major_faults === 0));
  result.codecs[allocator] = group(rows.filter(row => row.trial > 0), row => `${row.corpus_records}_${row.retain_batch ? 'retain' : 'drop'}`);
}
const block = Object.assign({}, ...read('block-latency.jsonl').filter(row => row.type === 'map').map(row => row.data));
assert.equal(block['@errors'], 0);
assert.equal(block['@collisions'], 0);
assert.equal(block['@partial_completions'], 0);
assert.deepEqual(block['@issued'], block['@completed']);
assert(!block['@start'] || Object.keys(block['@start']).length === 0);
result.block = Object.fromEntries(Object.entries(block['@completed']).map(([key, count]) => [key, {
  requests: count, issue_to_completion_us: block['@total_ns'][key] / count / 1000,
}]));
const a = result.runs.a.cold;
const builder = result.runs.builder.cold;
result.decomposition = {
  follower_device_cold: {
    late_prefetch_minus_two_prefix_us: a.late_prefetch.wall_us - 2 * a.prefix.wall_us,
    off_cpu_excess_us: a.late_prefetch.off_cpu_us - 2 * a.prefix.off_cpu_us,
    cpu_excess_us: a.late_prefetch.cpu_us - 2 * a.prefix.cpu_us,
  },
  builder_device_cold: {
    late_prefetch_minus_two_prefix_us: builder.late_prefetch.wall_us - 2 * builder.prefix.wall_us,
    off_cpu_excess_us: builder.late_prefetch.off_cpu_us - 2 * builder.prefix.off_cpu_us,
    cpu_excess_us: builder.late_prefetch.cpu_us - 2 * builder.prefix.cpu_us,
  },
  second_request_minus_first_service_us:
    result.block['lat-late,24576'].issue_to_completion_us - result.block['lat-late,4096'].issue_to_completion_us,
};
fs.writeFileSync(path.join(root, 'summary.json'), `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify({decomposition: result.decomposition, block: result.block, wide_source: result.wide_source, codecs: result.codecs}, null, 2));
