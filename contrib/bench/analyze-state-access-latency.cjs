#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const assert = require('node:assert/strict');
const {loadOrigin} = require('./state-access-load-clock.cjs');
const {checkMemory} = require('./run-sload-size-isolation.cjs');

function distribution(values) {
  values = [...values].sort((a,b) => a-b);
  assert.ok(values.every(Number.isFinite));
  const percentile = p => values.length ? values[Math.max(0, Math.ceil(values.length * p) - 1)] : null;
  return {count: values.length, p50_ms: percentile(.5), p90_ms: percentile(.9), p95_ms: percentile(.95),
    p99_ms: percentile(.99), max_ms: values.at(-1) ?? null,
    above_900ms: values.filter(v => v > 900).length, above_1200ms: values.filter(v => v > 1200).length};
}
function milliseconds(value) {
  const m = /^(\d+(?:\.\d+)?)(ns|\u00b5s|ms|s)$/.exec(value || '');
  assert.ok(m, `bad duration ${value}`);
  return Number(m[1]) * {ns: 1e-6, '\u00b5s': 1e-3, ms: 1, s: 1000}[m[2]];
}
function eventsFromLogs(logs) {
  const attempts = [], pending = new Map(), jobs = new Map(), built = [], cancelled = new Map();
  for (const x of logs) {
    const f = x.fields || {}, t = Date.parse(x.timestamp);
    const id = x.spans?.find(s => s.name === 'build_payload')?.id ?? x.span?.id;
    if (f.message === 'New payload job created') jobs.set(f.id, t);
    if (f.message === 'payload subscriber went away before the payload was resolved; killing the payload build')
      cancelled.set(x.span?.payload_id ?? x.spans?.find(s => s.payload_id)?.payload_id, t);
    if (f.message === 'Built payload') built.push({id, unix_ms:t, gas:f.gas_used,
      elapsed_ms:milliseconds(f.elapsed), execution_ms:milliseconds(f.total_transaction_execution_elapsed), transactions:f.pool_transactions_included});
    if (f.message === 'Bench transaction attempt started') {
      const key = `${id}:${f.tx_hash}`;
      assert.ok(!pending.has(key), 'duplicate unmatched attempt start');
      const attempt = {id, hash:f.tx_hash, started_ms:t, before_execution_ms:f.build_elapsed_us / 1000};
      pending.set(key, attempt); attempts.push(attempt);
    }
    if (f.message === 'Bench transaction attempt finished') {
      const key = `${id}:${f.tx_hash}`, attempt = pending.get(key);
      assert.ok(attempt, 'completion without an attempt start');
      Object.assign(attempt, {finished_ms:t, execution_ms:f.execution_us / 1000,
        build_elapsed_ms:f.build_elapsed_us / 1000, cancelled_at_finish:f.cancelled, valid:f.valid});
      pending.delete(key);
    }
  }
  return {attempts, jobs, built, cancelled};
}
function summarize(events, from, to) {
  const inWindow = t => t > from && t <= to;
  const cohort = events.attempts.filter(a => inWindow(a.started_ms));
  const finished = cohort.filter(a => a.finished_ms !== undefined), valid = finished.filter(a => a.valid);
  const jobs = [...events.jobs].filter(([,t]) => inWindow(t));
  const completed = new Set(events.built.map(b => b.id));
  const cancelled = jobs.filter(([id]) => events.cancelled.has(id));
  const built = events.built.filter(b => inWindow(b.unix_ms));
  const gas = built.reduce((s,b) => s+b.gas,0), execution = built.reduce((s,b) => s+b.execution_ms,0);
  return {from_unix_ms:from, to_unix_ms:to, duration_seconds:(to-from)/1000,
    attempts_started:cohort.length, attempts_unfinished:cohort.length-finished.length,
    valid_attempt_execution:distribution(valid.map(a => a.execution_ms)),
    invalid_attempt_execution:distribution(finished.filter(a => !a.valid).map(a => a.execution_ms)),
    valid_attempts_on_cancelled_jobs:valid.filter(a => events.cancelled.has(a.id)).length,
    cancelled_valid_execution:distribution(valid.filter(a => events.cancelled.has(a.id)).map(a => a.execution_ms)),
    valid_before_execution:distribution(valid.map(a => a.before_execution_ms)),
    valid_build_elapsed_at_tx_finish:distribution(valid.map(a => a.build_elapsed_ms)),
    proposal_jobs:jobs.length, cancelled_jobs:cancelled.length,
    completed_jobs:jobs.filter(([id]) => completed.has(id)).length,
    jobs_without_terminal_event:jobs.filter(([id]) => !completed.has(id) && !events.cancelled.has(id)).length,
    cancellation_after_job_creation:distribution(cancelled.map(([id,t]) => events.cancelled.get(id)-t)),
    completed_builds:built.length, completed_nonempty_build_elapsed:distribution(built.filter(b => b.gas > 0).map(b => b.elapsed_ms)),
    completed_build_execution_mgas_per_second:execution > 0 ? gas / execution / 1000 : null};
}
async function readLogs(file) {
  const logs = [];
  for await (const line of readline.createInterface({input:fs.createReadStream(file)})) {
    let row; try {row = JSON.parse(line);} catch {continue;}
    if (/Bench transaction attempt|New payload job created|Built payload|subscriber went away|^Executed block$/.test(row.fields?.message || '')) logs.push(row);
  }
  return logs;
}
async function analyze(directory, from, to) {
  const log = side => path.join(directory, `logs-feature-1-${side}/dev/reth.log`);
  const events = eventsFromLogs(await readLogs(log('a')));
  if (from !== undefined) return summarize(events, from, to);
  const report = JSON.parse(fs.readFileSync(path.join(directory,'report-feature-1.json')));
  const config = JSON.parse(fs.readFileSync(path.join(directory,'summary-config.json')));
  const origin = await loadOrigin(path.join(directory,'report-feature-1.samples.ndjson.gz'));
  from = origin + config.summary_warmup_seconds * 1000;
  to = origin + config.duration * 1000;
  const result = summarize(events, from, to);
  result.warmup = summarize(events, origin, from);
  result.trend = Array.from({length:5}, (_,i) => summarize(events,
    from + (to-from)*i/5, from + (to-from)*(i+1)/5));
  const blocks = report.blocks.filter(b => b.timestamp_ms > from && b.timestamp_ms <= to);
  const gas = blocks.reduce((s,b) => s+Number(b.gas_used),0), txs = blocks.reduce((s,b) => s+b.tx_count,0);
  result.origin_unix_ms = origin;
  result.scenario = report.metadata.scenario;
  result.accesses_per_transaction = JSON.parse(fs.readFileSync(path.join(directory,'max-tx-preflight-feature-1.json'))).accesses;
  result.chain = {gas, transactions:txs, blocks:blocks.length, gas_per_transaction:txs ? gas/txs : null,
    mgas_per_second:gas/result.duration_seconds/1e6,
    history_advanced_fraction:txs ? blocks.reduce((s,b) => s+Math.max(0,b.tx_count-1),0)/txs : null};
  const follower = [];
  for (const x of await readLogs(log('b'))) {
    if (x.fields.message !== 'Executed block' || Date.parse(x.timestamp) <= from || Date.parse(x.timestamp) > to) continue;
    const number = Number(x.spans?.find(s => s.block_num)?.block_num);
    const block = report.blocks.find(b => b.number === number);
    assert.ok(block, `missing canonical gas for follower block ${number}`);
    follower.push({gas:Number(block.gas_used), ms:milliseconds(x.fields.elapsed)});
  }
  const followerMs = follower.reduce((s,b) => s+b.ms,0);
  result.follower = {blocks:follower.length, execution_mgas_per_second:followerMs ? follower.reduce((s,b) => s+b.gas,0)/followerMs/1000 : null,
    nonempty_block_execution:distribution(follower.filter(b => b.gas > 0).map(b => b.ms))};
  const observer = fs.readFileSync(path.join(directory,'state-path-observer-feature-1.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
  result.io = {};
  for (const side of ['a','b']) {
    const points = observer.map(r => r.nodes[side]).filter(r => r.memory);
    points.forEach(checkMemory);
    const first = points.find(p => p.unix_ms >= from), last = points.findLast(p => p.unix_ms <= to);
    assert.ok(first && last && first.unix_ms-from < 10000 && to-last.unix_ms < 10000, 'observer does not cover full measurement');
    assert.equal(first.database_device,last.database_device);
    const device = first.database_device, read = last.io[device].rbytes-first.io[device].rbytes;
    assert.ok(read >= 0);
    result.io[side] = {from_unix_ms:first.unix_ms,to_unix_ms:last.unix_ms,read_mb_per_second:read/(last.unix_ms-first.unix_ms)/1000,
      file_cache_start_gib:first.memory.file/2**30,file_cache_end_gib:last.memory.file/2**30};
  }
  result.caveats = [
    'Attempt cohort is selected by START time, including completions after the window and canceled payloads. Unfinished attempts are explicitly counted, not silently discarded.',
    'Transaction execution does not include all proposal overhead; the 1200ms deadline covers more than EVM execution. Completed-build throughput excludes canceled work.',
    'Exact submission-relative wall window, not a trimmed metric endpoint or first inclusion timestamp. A single calibration run is not a worst-case latency guarantee.'
  ];
  return result;
}
module.exports = {distribution, milliseconds, eventsFromLogs, summarize, readLogs, analyze};
if (require.main === module) {
  const [directory,from,to] = process.argv.slice(2);
  analyze(directory,from === undefined ? undefined : Date.parse(from),to === undefined ? undefined : Date.parse(to))
    .then(result => {if (from === undefined) fs.writeFileSync(path.join(directory,'latency-analysis.json'),JSON.stringify(result,null,2)+'\n'); console.log(JSON.stringify(result,null,2));})
    .catch(error => {console.error(error);process.exitCode=1;});
}
