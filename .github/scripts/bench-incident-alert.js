// Page reth on-call through incident.io's Reth CI source (which posts to
// #eng-reth-alerts) for scheduled benchmark failures, and resolve the same alert
// on the next scheduled run that passes. Used from actions/github-script:
//
//   await require('./.github/scripts/bench-incident-alert.js')({ core, context });
//
// Env:
//   INCIDENT_IO_URL, INCIDENT_IO_TOKEN – incident.io HTTP alert source
//   BENCH_JOB_RESULTS   – toJSON(needs) of the alerting job
//   ALERT_KEY           – deduplication key, such as tempo:bench-e2e-nightly
//   ALERT_NAME          – human name, such as "Nightly e2e benchmark"
//   ALERT_WORKFLOW      – workflow file name, for the description and metadata
//   ALERT_RESOLVE_JOBS  – comma-separated jobs that must all succeed to resolve
//   ALERT_DETAIL        – optional extra line for a firing alert
//   BENCH_BASELINE_REF, BENCH_FEATURE_REF – optional refs for the description

const RETRY_DELAYS_MS = [2000, 4000];

module.exports = async function alert({ core, context, env = process.env, fetch = globalThis.fetch,
  setTimeout = globalThis.setTimeout }) {
  if (context.eventName !== 'schedule' ||
      `${context.repo.owner}/${context.repo.repo}` !== 'tempoxyz/tempo') return;

  const jobs = JSON.parse(env.BENCH_JOB_RESULTS);
  const failedJobs = Object.entries(jobs)
    .filter(([, job]) => job.result === 'failure').map(([name]) => name);
  const resolveJobs = (env.ALERT_RESOLVE_JOBS || '').split(',').map(s => s.trim()).filter(Boolean);
  let status;
  if (failedJobs.length) status = 'firing';
  else if (resolveJobs.length && resolveJobs.every(name => jobs[name]?.result === 'success')) status = 'resolved';
  if (status === 'resolved' && env.GITHUB_RUN_ATTEMPT !== '1') {
    // A rerun may be an older night: don't clear a page a newer night raised.
    core.info('Rerun of a scheduled run; leaving the incident.io alert unchanged');
    return;
  }
  if (!status) {
    core.info('Benchmark did not run; leaving the incident.io alert unchanged');
    return;
  }

  const url = env.INCIDENT_IO_URL;
  const token = env.INCIDENT_IO_TOKEN;
  if (!url || !token) {
    if (status === 'firing') {
      throw new Error('INCIDENT_IO_RETH_CI_URL or INCIDENT_IO_RETH_CI_TOKEN is not set; cannot alert reth on-call');
    }
    core.notice('INCIDENT_IO_RETH_CI_URL or INCIDENT_IO_RETH_CI_TOKEN is not set; skipping incident.io alert');
    return;
  }

  const name = env.ALERT_NAME;
  const workflow = env.ALERT_WORKFLOW;
  const attempt = env.GITHUB_RUN_ATTEMPT || '1';
  const runUrl = `https://github.com/tempoxyz/tempo/actions/runs/${context.runId}/attempts/${attempt}`;
  const lines = status === 'firing'
    ? [`The ${name.toLowerCase()} (${workflow}) failed.`, `Failed jobs: ${failedJobs.join(', ')}`,
       ...(env.ALERT_DETAIL ? [env.ALERT_DETAIL] : [])]
    : [`The ${name.toLowerCase()} (${workflow}) succeeded.`];
  if (env.BENCH_BASELINE_REF) lines.push(`Baseline: ${env.BENCH_BASELINE_REF}`);
  if (env.BENCH_FEATURE_REF) lines.push(`Feature: ${env.BENCH_FEATURE_REF}`);
  lines.push(`Attempt: ${attempt}`, `Run: ${runUrl}`);
  const payload = {
    title: status === 'firing' ? `${name} failed: ${failedJobs.join(', ')}` : `${name} recovered`,
    description: lines.join('\n'),
    status,
    deduplication_key: env.ALERT_KEY,
    source_url: runUrl,
    metadata: {
      team: 'reth',
      repository: 'tempoxyz/tempo',
      workflow,
      failed_jobs: failedJobs.join(','),
      baseline_ref: env.BENCH_BASELINE_REF || '',
      feature_ref: env.BENCH_FEATURE_REF || '',
      run_id: String(context.runId),
      run_attempt: String(attempt),
      run_url: runUrl,
    },
  };

  // The deduplication key makes a repeated event idempotent, so retrying is safe.
  let lastError;
  for (let i = 0; i <= RETRY_DELAYS_MS.length; i++) {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(15000),
      });
      if (response.ok) {
        core.info(`Sent incident.io ${status} event for ${payload.deduplication_key}`);
        return;
      }
      lastError = new Error(`HTTP ${response.status}`);
      // Other 4xx (such as a bad token) won't succeed on retry.
      if (response.status < 500 && response.status !== 429) break;
    } catch (error) { lastError = error; }
    if (i < RETRY_DELAYS_MS.length) await new Promise(resolve => setTimeout(resolve, RETRY_DELAYS_MS[i]));
  }
  // A failed resolve must not fail an otherwise green run; a failed page must.
  if (status === 'resolved') {
    core.warning(`Failed to send the incident.io resolved event: ${lastError.message}`);
    return;
  }
  throw new Error(`Failed to send the incident.io firing event: ${lastError.message}`);
};
