'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const readline = require('node:readline');
const {select, selectCoverage, selectWrites, seriesKey, metricsWindow} = require('../../contrib/bench/analyze-state-access.cjs');
const {canonicalWindow, summarizeObserver} = require('../../contrib/bench/analyze-state-path-controls.cjs');
const {summarizeDurability} = require('../../contrib/bench/state-path-durability.cjs');
const {checkMemory} = require('../../contrib/bench/run-sload-size-isolation.cjs');
const read = file => JSON.parse(fs.readFileSync(file));

async function main() {
  const experiment = read(path.join(__dirname, 'experiment.json'));
  assert.equal(experiment.status, 'complete');
  const runs = [];
  for (const entry of experiment.runs) {
    assert.equal(entry.status, 'complete');
    const series = new Map();
    const input = fs.createReadStream(path.join(entry.results_dir, 'report-feature-1.samples.ndjson.gz')).pipe(zlib.createGunzip());
    for await (const line of readline.createInterface({input, crlfDelay:Infinity})) {
      const name = /^\{"name":"([^"]+)"/.exec(line)?.[1];
      if (!name || !(select(name) || selectCoverage(name) || selectWrites(name))) continue;
      const sample = JSON.parse(line);
      if (sample.offset_ms < 900000) continue;
      const key = seriesKey(name, sample.labels);
      if (!series.has(key)) series.set(key, {name, labels:sample.labels, points:[]});
      series.get(key).points.push({offset_ms:sample.offset_ms, unix_ms:sample.unix_ms, value:sample.value});
    }
    const report = read(path.join(entry.results_dir, 'report-feature-1.json'));
    const rows = fs.readFileSync(path.join(entry.results_dir, 'state-path-observer-feature-1.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    const r = {label:entry.label, reads:entry.reads, prewarming:entry.prewarming,
      builder:metricsWindow(series, 'a', 900000, 1200000), follower:metricsWindow(series, 'b', 900000, 1200000), nodes:{}};
    r.canonical = canonicalWindow(report.blocks, r.builder.gas_counter.first.unix_ms, r.builder.gas_counter.last.unix_ms);
    r.workload_reads_per_second = r.canonical.transactions * entry.reads / r.canonical.duration_seconds;
    for (const [node, role] of [['a','builder'], ['b','follower']]) {
      const o = summarizeObserver(rows, node, r[role]);
      const canonical = canonicalWindow(report.blocks, o.from_unix_ms, o.to_unix_ms);
      const samples = rows.map(row => row.nodes[node]).filter(s => s.unix_ms >= o.from_unix_ms && s.unix_ms <= o.to_unix_ms);
      assert.ok(samples.length >= 50);
      samples.forEach(checkMemory);
      r.nodes[node] = {observer:o, durability:summarizeDurability(rows, node, report.blocks, o.from_unix_ms, o.to_unix_ms),
        file_gib:{first:samples[0].memory.file/2**30,last:samples.at(-1).memory.file/2**30,
          min:Math.min(...samples.map(s=>s.memory.file))/2**30,max:Math.max(...samples.map(s=>s.memory.file))/2**30},
        read_requests_per_canonical_workload_sload:o.io.rios/(canonical.transactions*entry.reads)};
    }
    runs.push(r);
  }
  const f = n => n == null ? 'n/a' : n.toFixed(3);
  const lines = ['# Late-window sensitivity check', '',
    'Common load offsets 900-1200 seconds (last five minutes), selected before the size/prewarming comparison completed. This supplements, not replaces, the standard 600-1200 second window.', '',
    '| Reads/tx | Prewarming | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s | Canonical SLOAD/s | Builder whole-node read requests/canonical SLOAD |',
    '| ---: | --- | ---: | ---: | ---: | ---: | ---: |'];
  for (const r of runs) lines.push(`| ${r.reads} | ${r.prewarming?'on':'off'} | ${f(r.builder.aggregate_execution_mgas_per_second)} | ${f(r.follower.aggregate_execution_mgas_per_second)} | ${f(r.canonical.mgas_per_second)} | ${f(r.workload_reads_per_second)} | ${f(r.nodes.a.read_requests_per_canonical_workload_sload)} |`);
  lines.push('', '| Cell | Node | File-cache first/last GiB | File-cache min/max GiB | Durable Mgas/s | Backlog first/last Ggas |', '| --- | --- | --- | --- | ---: | --- |');
  for (const r of runs) for (const node of ['a','b']) {
    const n = r.nodes[node], c = n.file_gib, d = n.durability;
    lines.push(`| ${r.label} | ${node} | ${f(c.first)}/${f(c.last)} | ${f(c.min)}/${f(c.max)} | ${f(d.persisted_mgas_per_second)} | ${f(d.producer_backlog_gas.first/1e9)}/${f(d.producer_backlog_gas.last/1e9)} |`);
  }
  lines.push('', 'Read requests/canonical SLOAD includes speculative work, trie and persistence; it is not an opcode-attributed miss count. Follower execution may include pipeline replay. A growing backlog means chain production is not demonstrated sustainable throughput.', '');
  fs.writeFileSync(path.join(__dirname, 'late-window.json'), JSON.stringify({from_seconds:900,to_seconds:1200,runs},null,2)+'\n');
  fs.writeFileSync(path.join(__dirname, 'late-window.md'), lines.join('\n'));
  console.log(lines.join('\n'));
}
main().catch(error=>{console.error(error);process.exitCode=1;});
