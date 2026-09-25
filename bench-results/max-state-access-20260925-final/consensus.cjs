'use strict';
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const root = __dirname;
function milliseconds(value) {
  const match = /^(\d+(?:\.\d+)?)(ns|\u00b5s|ms|s)$/.exec(value || '');
  return match ? Number(match[1]) * {ns: 1e-6, '\u00b5s': 1e-3, ms: 1, s: 1000}[match[2]] : null;
}
function distribution(values) {
  values = values.filter(x => x != null).sort((a,b) => a-b);
  const percentile = p => values.length ? values[Math.min(values.length-1, Math.floor(p*values.length))] : null;
  return {count: values.length, p50_ms: percentile(.5), p95_ms: percentile(.95), max_ms: values.at(-1) ?? null};
}
async function main() {
  const report = JSON.parse(fs.readFileSync(path.join(root,'throughput.json')));
  const results = [];
  for (const run of report.runs) {
    const entry = report.experiment.runs.find(e => e.id === run.workload);
    const log = path.resolve(entry.results_dir,'logs-feature-1-a/dev/reth.log');
    const from = run.full_window?.from_unix_ms ?? run.builder.gas_counter.first.unix_ms;
    const to = run.full_window?.to_unix_ms ?? run.builder.gas_counter.last.unix_ms;
    const rounds = new Set(), jobs = new Set(), builtJobs = new Set(), builds = [], outcomes = {};
    for await (const line of readline.createInterface({input: fs.createReadStream(log)})) {
      let x;
      try { x = JSON.parse(line); } catch { continue; }
      const t = Date.parse(x.timestamp);
      if (!(t > from && t <= to)) continue;
      const message = x.fields?.message;
      if (message === 'broadcasting nullification') rounds.add(x.fields.round ?? `${x.span?.epoch}:${x.span?.view}`);
      if (message === 'New payload job created') jobs.add(x.fields.id);
      if (message === 'Built payload') {
        builtJobs.add(x.span?.id);
        builds.push({id:x.span?.id, gas:x.fields.gas_used, elapsed:milliseconds(x.fields.elapsed),
          execution:milliseconds(x.fields.total_transaction_execution_elapsed)});
      }
      if (message === 'execution task finished') {
        const key = `${x.span?.task_type}:${x.span?.outcome}`;
        outcomes[key] = (outcomes[key] || 0) + 1;
      }
    }
    const admission={logged_failures:0,nonce_too_far_in_future:0,bursts:[]};
    const original=entry.recovery?.original_experiment;
    const originalDirectory=original?JSON.parse(fs.readFileSync(path.join(original,'experiment.json'))).runs[0].directory:null;
    const runLog=path.join(originalDirectory || entry.directory,'run.log');
    admission.log_source=runLog;admission.available=fs.existsSync(runLog);
    if(fs.existsSync(runLog))for await(const line of readline.createInterface({input:fs.createReadStream(runLog)})) {
      const t=Date.parse(line.slice(0,27));
      if(!(t>from && t<=to) || !line.includes('Failed to send transaction'))continue;
      admission.logged_failures++;
      if(line.includes('too far in the future'))admission.nonce_too_far_in_future++;
      const last=admission.bursts.at(-1);
      if(!last || t-last.last_ms>2000)admission.bursts.push({first_ms:t,last_ms:t,count:1});
      else {last.last_ms=t;last.count++;}
    }
    for(const burst of admission.bursts){burst.first=new Date(burst.first_ms).toISOString();burst.last=new Date(burst.last_ms).toISOString();}
    results.push({workload: run.workload, log, from: new Date(from).toISOString(), to:new Date(to).toISOString(),admission,
      duration_seconds:(to-from)/1000, unique_nullified_rounds:rounds.size, new_payload_jobs:jobs.size,
      completed_build_events:builds.length, unique_completed_jobs:builtJobs.size,
      jobs_without_completed_build_in_window:[...jobs].filter(id => !builtJobs.has(id)).length,
      completed_build_gas:builds.reduce((sum,b) => sum+b.gas,0),
      nonempty_builds:builds.filter(b => b.gas>0).length,
      nonempty_build_elapsed:distribution(builds.filter(b => b.gas>0).map(b => b.elapsed)),
      nonempty_build_execution:distribution(builds.filter(b => b.gas>0).map(b => b.execution)),
      execution_task_outcomes:outcomes, canonical:run.canonical});
  }
  const output = {results, caveats:[
    'Events use the exact full 600-second window when reconstructed; otherwise the retained builder gas-counter window.',
    'Nullified rounds are consensus observations, not a direct count of canceled EVM executions or proof of a particular timeout cause.',
    'A job without a completion in this window is not necessarily canceled: boundary-crossing jobs and payload-job reuse affect this statistic.',
    'Completed build duration distributions exclude incomplete/canceled work. Canonical gas divided by wall time is the chain metric.'
  ]};
  fs.writeFileSync(path.join(root,'consensus.json'),JSON.stringify(output,null,2)+'\n');
  console.log(JSON.stringify(output,null,2));
}
main().catch(e => { console.error(e); process.exitCode=1; });
