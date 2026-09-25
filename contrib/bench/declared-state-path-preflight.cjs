#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {ROUTER, declaredRange, checkAccessList} = require('./declared-state-path-validation.cjs');

function preflight(generator, preset, output, env = process.env) {
  const scenario = path.basename(preset, '.yml');
  const accesses = Number(env.TXGEN_STATE_ACCESSES), maxStart = Number(env.TXGEN_DECLARED_MAX_START);
  assert.ok(Number.isSafeInteger(accesses) && accesses >= 1 && accesses <= 256);
  assert.ok(Number.isSafeInteger(maxStart) && maxStart >= 0);
  const pages = (maxStart + accesses) / 4096;
  assert.ok(Number.isSafeInteger(pages) && pages > 0, 'generated range must cover the full populated domain');
  // Old txgen ignores unknown template fields. Inspect its emitted request before
  // starting a sustained load; a syntactically accepted preset is insufficient.
  const lines = execFileSync(generator, ['generate', '-s', preset, '-n', '8', '--seed', '42', '--defer-signing'],
    {encoding: 'utf8', env, maxBuffer: 2 ** 22, timeout: 30000, stdio: ['ignore', 'pipe', 'pipe']})
    .trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 8);
  const starts = [];
  for (const row of lines) {
    assert.equal(row.phase, 'workload');
    assert.equal(row.late_sign?.format, 'tempo_expiring_relative');
    const request = row.late_sign.payload.request;
    assert.equal(request.calls.length, 1);
    assert.equal(request.calls[0].to.toLowerCase(), ROUTER);
    const range = declaredRange(request.calls[0].input, scenario, pages, accesses);
    checkAccessList(request.accessList, range);
    starts.push(range.start.toString());
  }
  assert.ok(new Set(starts).size > 1, 'generator repeats the same range');
  const result = {ok: true, scenario, accesses, page_count: pages, max_start: maxStart,
    generator: path.resolve(generator), generator_sha256: crypto.createHash('sha256').update(fs.readFileSync(generator)).digest('hex'),
    preset_sha256: crypto.createHash('sha256').update(fs.readFileSync(preset)).digest('hex'), samples: starts,
    caveat: 'Generated deferred requests verified before load. The post-load audit verifies signed on-chain access lists and actual execution.'};
  fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
  return result;
}
module.exports = {preflight};
if (require.main === module) {
  try { console.log(JSON.stringify(preflight(...process.argv.slice(2)))); }
  catch (error) { console.error(error); process.exitCode = 1; }
}
