const REQUIRED = ['Problem', 'Changes', 'Validation'];

// Structure only: this cannot establish whether the prose is true.
function validate(body) {
  const sections = new Map();
  let section;
  let fence;
  for (const line of (body || '').replace(/<!--[\s\S]*?(?:-->|$)/g, '').split(/\r?\n/)) {
    const marker = line.match(/^\s{0,3}(`{3,}|~{3,})/);
    if (marker) {
      if (!fence) fence = marker[1];
      else if (marker[1][0] === fence[0] && marker[1].length >= fence.length) fence = undefined;
      continue;
    }
    const heading = !fence && line.match(/^##\s+(.+?)\s*#*\s*$/);
    if (heading) {
      section = heading[1].toLowerCase();
      if (sections.has(section)) return [`Duplicate section: ${heading[1]}`];
      sections.set(section, []);
    } else if (section) sections.get(section).push(line);
  }
  return REQUIRED.flatMap(name => {
    const lines = sections.get(name.toLowerCase());
    if (!lines) return [`Missing ## ${name}`];
    const content = lines.join('\n').replace(/<[^>]*>/g, '').replace(/^[\s>*_`\-\[\]x]+/gm, '').trim();
    if (!content) return [`Fill in ## ${name}`];
    if (/^(?:todo|tbd|n\/?a|none|\.\.\.|fill (?:this|in).*|describe .* here)[.!\s]*$/im.test(content)) {
      return [`Replace placeholder text in ## ${name}`];
    }
    return [];
  });
}

async function run({ github, context, core }) {
  const repo = context.repo;
  const group = context.payload.merge_group;
  const sha = group?.head_sha || context.payload.pull_request.head.sha;
  const status = (state, description) => github.rest.repos.createCommitStatus({
    ...repo, sha, state, context: 'PR description structure', description,
    target_url: `${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${context.runId}`,
  });
  await status('pending', 'Checking the current PR description');
  try {
    let numbers;
    if (group) {
      const pulls = await github.paginate(github.rest.repos.listPullRequestsAssociatedWithCommit, {
        ...repo, commit_sha: sha, per_page: 100,
      });
      numbers = pulls.filter(p => p.state === 'open' && `refs/heads/${p.base.ref}` === group.base_ref).map(p => p.number);
      if (!numbers.length) throw new Error('Cannot identify merge-group PRs; retry or inspect the merge queue.');
    } else numbers = [context.payload.pull_request.number];

    const errors = [];
    for (const number of numbers) {
      const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: number });
      if (!group && pr.head.sha !== sha) return; // A newer push owns the new SHA's result.
      errors.push(...validate(pr.body).map(error => `#${number}: ${error}`));
    }
    await core.summary.addHeading('PR description structure').addRaw(
      errors.length ? errors.join('\n\n') : 'Problem, Changes, and Validation contain text. Accuracy still requires review.',
    ).write();
    await status(errors.length ? 'failure' : 'success', errors.length ? 'Update Problem, Changes, and Validation; see the run summary' : 'Required sections are present and filled in');
    if (errors.length) core.setFailed(errors.join('; '));
  } catch (error) {
    await status('error', 'Description check could not complete; inspect the run and retry');
    throw error;
  }
}

module.exports = { validate, run };
