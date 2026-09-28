'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {loadOrigin} = require('../../contrib/bench/state-access-load-clock.cjs');
(async () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'experiment.json')));
  const output = {now: new Date().toISOString(), status: manifest.status,
    elapsed_minutes: (Date.now() - Date.parse(manifest.started_at)) / 60000};
  const dirs = fs.readdirSync(path.join(__dirname, 'harness/bench-results')).filter(name => /^20\d{6}-/.test(name)).sort();
  if (dirs.length) {
    const raw = path.join(__dirname, 'harness/bench-results', dirs.at(-1));
    const sample = path.join(raw, 'report-feature-1.samples.ndjson.gz');
    if (fs.existsSync(sample)) {
      const origin = await loadOrigin(sample);
      output.load_elapsed_minutes = (Date.now() - origin) / 60000;
      output.load_remaining_minutes = Math.max(0, 20 - output.load_elapsed_minutes);
    }
    const observer = path.join(raw, 'state-path-observer-feature-1.jsonl');
    if (fs.existsSync(observer)) {
      const rows = fs.readFileSync(observer, 'utf8').trim().split('\n').map(JSON.parse);
      output.latest_observer = {time: new Date(rows.at(-1).unix_ms).toISOString(),
        heads: Object.fromEntries(Object.entries(rows.at(-1).nodes).map(([node, row]) => [node, row.head ?? row.error]))};
    }
  }
  const mem = path.join(__dirname, 'memory-controls.jsonl');
  if (fs.existsSync(mem)) {
    const rows = fs.readFileSync(mem, 'utf8').trim().split('\n').map(JSON.parse);
    output.memory = Object.fromEntries(['a', 'b'].map(node => [node, {
      anon_gib: rows.at(-1).nodes[node].anon / 2 ** 30,
      peak_sampled_anon_gib: Math.max(...rows.map(row => row.nodes[node].anon)) / 2 ** 30,
      current_gib: rows.at(-1).nodes[node]['memory.current'] / 2 ** 30,
      events: rows.at(-1).nodes[node].memory_events.trim().replaceAll('\n', ', ')}]));
  }
  const log = path.join(__dirname, 'harness/localnet/logs-e2e-local-feature-1-b/dev/reth.log');
  if (fs.existsSync(log)) output.follower_limit_commits =
    (fs.readFileSync(log, 'utf8').match(/Committing execution batch at bytecode cache limit/g) || []).length;
  console.log(JSON.stringify(output, null, 2));
})().catch(error => {console.error(error); process.exitCode = 1;});
