const fs = require('node:fs');
const path = require('node:path');

const repository = 'tempoxyz/tempo';
const imageNames = ['tempo', 'tempo-localnet', 'tempo-sidecar', 'tempo-xtask'];
const marker = id => `<!-- tempo-docker-run:${id} -->`;
const requestMarker = id => `<!-- tempo-docker-request:${id} -->`;

async function resolve(github, context, runId = context.payload.workflow_run?.id) {
  if (`${context.repo.owner}/${context.repo.repo}` !== repository) return null;
  if (!Number.isSafeInteger(runId) || runId <= 0) throw new Error('Invalid build run ID');
  // Events may arrive out of order (or belong to an earlier run attempt).
  const { data: run } = await github.rest.actions.getWorkflowRun({
    ...context.repo, run_id: runId,
  });
  if (run.event !== 'workflow_dispatch' || run.head_repository?.full_name !== repository ||
      run.head_branch !== context.payload.repository.default_branch) return null;
  const match = /^Docker PR #([1-9][0-9]*)( nightly| profiling)?(?: \(request ([1-9][0-9]*)\))?$/.exec(run.display_title);
  if (!match || !Number.isSafeInteger(Number(match[1]))) return null;
  if (match[3] && !Number.isSafeInteger(Number(match[3]))) return null;
  const mode = (match[2] || '').trim();
  const expectedPath = `.github/workflows/docker${mode === 'profiling' ? '-profiling' : ''}.yml`;
  if (run.path !== expectedPath) return null;
  const number = Number(match[1]);
  // Resolve a real PR, not an issue or an artifact-supplied comment destination.
  await github.rest.pulls.get({ ...context.repo, pull_number: number });
  const status = {
    id: run.id, attempt: run.run_attempt, number, mode,
    status: run.status, conclusion: run.conclusion,
  };
  if (match[3]) status.requestId = Number(match[3]);
  if (run.status === 'completed') {
    try {
      const artifacts = await github.paginate(github.rest.actions.listWorkflowRunArtifacts, {
        ...context.repo, run_id: run.id, per_page: 100,
      });
      const artifact = artifacts.find(a => a.name === `docker-pr-images-${run.run_attempt}` &&
        !a.expired && a.size_in_bytes < 100_000);
      if (artifact) status.artifactId = artifact.id;
    } catch {
      // Missing metadata must not prevent reporting a failure/cancellation.
      status.artifactLookupFailed = true;
    }
  }
  return status;
}

function validateImages(raw, status) {
  if (!raw || !/^[a-f0-9]{40}$/.test(raw.sha)) throw new Error('Invalid source SHA');
  const names = status.mode === 'profiling' ? ['tempo'] : imageNames;
  if (!Array.isArray(raw.images) || raw.images.length !== names.length) throw new Error('Invalid images');
  const prefix = status.mode === 'profiling' ? 'profiling-' : '';
  const tags = [`${prefix}pr-${status.number}`, `${prefix}sha-${raw.sha.slice(0, 7)}`];
  if (status.mode === 'nightly') tags.push('nightly');
  const registries = status.mode === 'profiling' ? ['ghcr.io'] : ['ghcr.io', 'docker.io'];
  for (const name of names) {
    const image = raw.images.find(image => image.name === name);
    if (!image || !Array.isArray(image.tags)) throw new Error('Missing image tags');
    const expected = registries.flatMap(registry => tags.map(tag => `${registry}/tempoxyz/${name}:${tag}`));
    if (image.tags.length !== expected.length || new Set(image.tags).size !== expected.length ||
        image.tags.some(tag => !expected.includes(tag))) throw new Error('Unexpected image reference');
    if (typeof image.digest !== 'string' || (image.digest && !/^sha256:[a-f0-9]{64}$/.test(image.digest))) {
      throw new Error('Invalid image digest');
    }
  }
  return raw;
}

function render(status, images) {
  const command = `/docker${status.mode ? ` ${status.mode}` : ''}`;
  const state = status.status === 'completed' ? status.conclusion :
    status.status === 'in_progress' ? 'running' : 'queued';
  const allowedStates = ['running', 'queued', 'success', 'failure', 'cancelled', 'timed_out',
    'action_required', 'neutral', 'skipped', 'stale', 'startup_failure'];
  if (!allowedStates.includes(state)) throw new Error('Unknown run state');
  const url = `https://github.com/${repository}/actions/runs/${status.id}`;
  const lines = [marker(status.id), ...(status.requestId ? [requestMarker(status.requestId)] : []),
    `**Docker request accepted: \`${command}\`**`, '',
    `Status: **${state}** · [Build run](${url}) · Attempt ${status.attempt}`];
  if (status.status !== 'completed') return lines.join('\n');
  if (!images) {
    lines.push('', 'Published image details are unavailable; check the build run. No image references are inferred.');
    return lines.join('\n');
  }
  validateImages(images, status);
  lines.push('', `Built commit: [\`${images.sha}\`](https://github.com/${repository}/commit/${images.sha})`, '',
    'Images reported by the successful push step (the overall run result above also includes later steps):', '',
    '| Image | Published references (registry URL and tags) | Immutable pull reference |',
    '| --- | --- | --- |');
  for (const image of images.images) {
    const packageLink = `[${image.name}](https://github.com/orgs/tempoxyz/packages/container/package/${image.name})`;
    const hub = status.mode === 'profiling' ? '' : ` · [Docker Hub](https://hub.docker.com/r/tempoxyz/${image.name})`;
    const immutable = image.digest ? `\`ghcr.io/tempoxyz/${image.name}@${image.digest}\`` : 'Digest unavailable';
    lines.push(`| ${packageLink}${hub} | ${image.tags.map(tag => `\`${tag}\``).join('<br>')} | ${immutable} |`);
  }
  lines.push('', 'Pull with `docker pull <reference>`. PR/nightly tags can move; use the digest reference to pin this image.');
  return lines.join('\n');
}

async function report(github, context, core, status) {
  let images;
  if (status.artifactLookupFailed) core.warning('Image artifact lookup failed; reporting run status only.');
  if (status.status === 'completed' && process.env.ARTIFACT_DOWNLOADED === 'true') {
    try {
      const filename = path.join(process.env.RUNNER_TEMP, 'docker-pr-report', 'docker-pr-images.json');
      // Artifact contents are untrusted data, never executable code or Markdown.
      const stat = fs.lstatSync(filename);
      if (!stat.isFile() || stat.size > 64_000) throw new Error('Invalid image report file');
      images = validateImages(JSON.parse(fs.readFileSync(filename, 'utf8')), status);
    } catch {
      core.warning('Published image details could not be validated; reporting run status only.');
    }
  }
  const body = render(status, images);
  const comments = await github.paginate(github.rest.issues.listComments, {
    ...context.repo, issue_number: status.number, per_page: 100,
  });
  const botComments = comments.filter(c => c.user?.login === 'github-actions[bot]' && c.user?.type === 'Bot');
  // The request ID is already in the build title when lifecycle events start,
  // so even an event arriving before dispatch returns can adopt the receipt.
  // Once linked, match by run ID and never adopt another run's comment.
  const existing = botComments.find(c => c.body?.startsWith(`${marker(status.id)}\n`)) ||
    (status.requestId && botComments.find(c => c.body?.startsWith(`${requestMarker(status.requestId)}\n`) &&
      !c.body.includes('<!-- tempo-docker-run:')));
  if (existing) {
    if (existing.body !== body) await github.rest.issues.updateComment({
      ...context.repo, comment_id: existing.id, body,
    });
  } else {
    await github.rest.issues.createComment({ ...context.repo, issue_number: status.number, body });
  }
}

module.exports = { resolve, validateImages, render, report };
