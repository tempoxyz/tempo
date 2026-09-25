'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function measurementTiming(durationSeconds, warmupSeconds = 600) {
  const duration = Number(durationSeconds), warmup = Number(warmupSeconds);
  assert.ok(Number.isSafeInteger(duration) && duration > 0, 'invalid duration');
  assert.ok(Number.isSafeInteger(warmup) && warmup >= 0 && warmup < duration, 'invalid warmup');
  return {duration_seconds: duration, warmup_seconds: warmup,
    from_ms: warmup * 1000, to_ms: duration * 1000, slice_ms: (duration - warmup) * 1000 / 5};
}

function readTiming(directory, report) {
  const file = path.join(directory, 'summary-config.json');
  const config = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : {};
  return measurementTiming(report.metadata.run_duration_secs, config.summary_warmup_seconds ?? 600);
}

module.exports = {measurementTiming, readTiming};
