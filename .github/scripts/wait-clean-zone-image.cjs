// Keep the fork clock stopped until the independent source rebuild is done.
module.exports = async function waitCleanImage({ github, context, core,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  now = Date.now, timeoutMs = 45 * 60 * 1000 }) {
  const deadline = now() + timeoutMs;
  const attempt = Number(process.env.GITHUB_RUN_ATTEMPT);
  const params = { ...context.repo, run_id: context.runId };
  const name = `clean-tempo-zone-image-${attempt}`;
  let previous;
  while (now() < deadline) {
    const { data: run } = await github.rest.actions.getWorkflowRun(params);
    if (run.head_sha !== context.sha || run.run_attempt !== attempt) {
      throw new Error('Build ownership or attempt changed before genesis');
    }
    const jobs = await github.paginate(github.rest.actions.listJobsForWorkflowRunAttempt,
      { ...params, attempt_number: attempt, per_page: 100 });
    const job = jobs.find(job => job.name === 'Rebuild production tempo-zone image without cache');
    if (job?.status === 'completed') {
      if (job.conclusion !== 'success') {
        throw new Error(`Independent source rebuild failed: ${job.conclusion}`);
      }
      const artifacts = await github.paginate(github.rest.actions.listWorkflowRunArtifacts,
        { ...params, per_page: 100 });
      const artifact = artifacts.find(artifact => artifact.name === name && !artifact.expired);
      if (artifact) {
        core.setOutput('artifact-id', artifact.id);
        return artifact.id;
      }
    }
    const status = job ? `${job.status}/${job.conclusion || ''}` : 'not started';
    if (status !== previous) core.info(`Waiting for independent source rebuild: ${status}`);
    previous = status;
    await sleep(Math.min(15000, deadline - now()));
  }
  throw new Error('Timed out waiting for independent source rebuild before genesis');
};
