const { execFileSync } = require('node:child_process');
const fs = require('node:fs');

const repository = 'tempoxyz/docs';
const page = 'src/pages/docs/guide/node/network-upgrades.mdx';
const tagPattern = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function releaseEntry(release) {
  if (!tagPattern.test(release.tagName) || release.isDraft || !release.publishedAt) {
    throw new Error('Expected a published Tempo node release');
  }
  const date = new Date(release.publishedAt);
  if (Number.isNaN(date.getTime())) throw new Error('Invalid release publication date');
  const url = `https://github.com/tempoxyz/tempo/releases/tag/${release.tagName}`;
  const formattedDate = date.toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC',
  });
  // Do not infer network applicability or upgrade urgency from a version number.
  // The draft PR includes the source notes for a maintainer to classify the row.
  return `| [${release.tagName}](${url}) | ${formattedDate} | Review required | See [release notes](${url}) for changes and upgrade instructions. | <Badge variant="gray">${release.isPrerelease ? 'Pre-release' : 'Review required'}</Badge> |`;
}

function updatePage(content, release) {
  const row = releaseEntry(release);
  const section = /(^## Node Operator Updates\r?\n[\s\S]*?)(?=^## |$(?![\s\S]))/m;
  const match = content.match(section);
  if (!match) throw new Error('Node Operator Updates section not found');
  if (match[0].includes(`](${`https://github.com/tempoxyz/tempo/releases/tag/${release.tagName}`})`)) {
    return content;
  }
  const lines = match[0].split('\n');
  const separator = lines.findIndex((line) => /^\|\s*-+\s*\|/.test(line));
  if (separator < 0) throw new Error('Node operator release table not found');
  // Insert backfills in version order instead of presenting an old release as latest.
  const numbers = (tag) => tag.slice(1).split(/[-+]/)[0].split('.').map(Number);
  const compare = (left, right) => {
    const a = numbers(left);
    const b = numbers(right);
    return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
  };
  let index = separator + 1;
  while (index < lines.length && lines[index].startsWith('|')) {
    const existing = lines[index].match(/^\| \[(v[^\]]+)\]/);
    if (!existing) throw new Error('Unrecognized node operator release row');
    const order = compare(release.tagName, existing[1]);
    if (order > 0 || (order === 0 && !release.isPrerelease)) break;
    index++;
  }
  lines.splice(index, 0, row);
  return content.replace(section, () => lines.join('\n'));
}

function githubApi(method, endpoint, payload) {
  const args = ['api', '--method', method, endpoint];
  if (payload) args.push('--input', '-');
  const output = execFileSync('gh', args, {
    encoding: 'utf8', input: payload ? JSON.stringify(payload) : undefined,
  });
  return output.trim() ? JSON.parse(output) : null;
}

function run(release, api = githubApi) {
  // Validate before any API calls, including URL and branch construction.
  releaseEntry(release);
  const branch = `automation/tempo-release-${release.tagName}`;
  const prefix = `repos/${repository}`;
  const repo = api('GET', prefix);
  const base = repo.default_branch;
  const pulls = api('GET', `${prefix}/pulls?state=all&head=${encodeURIComponent(`tempoxyz:${branch}`)}`);
  if (pulls.length) {
    console.log(`Release PR already exists: ${pulls[0].html_url}`);
    return;
  }
  const ref = api('GET', `${prefix}/git/ref/heads/${encodeURIComponent(base)}`);
  // Read the file at the exact commit used to create the branch.
  const file = api('GET', `${prefix}/contents/${page}?ref=${ref.object.sha}`);
  const content = Buffer.from(file.content, 'base64').toString('utf8');
  const updated = updatePage(content, release);
  if (updated === content) {
    console.log('Release is already documented.');
    return;
  }
  const refs = api('GET', `${prefix}/git/matching-refs/heads/${encodeURIComponent(branch)}`);
  if (!refs.some((item) => item.ref === `refs/heads/${branch}`)) {
    api('POST', `${prefix}/git/refs`, { ref: `refs/heads/${branch}`, sha: ref.object.sha });
  }
  // Resume after a previous failure without overwriting a maintainer's edits.
  const branchFile = api('GET', `${prefix}/contents/${page}?ref=${encodeURIComponent(branch)}`);
  const branchContent = Buffer.from(branchFile.content, 'base64').toString('utf8');
  if (updatePage(branchContent, release) !== branchContent) {
    api('PUT', `${prefix}/contents/${page}`, {
      message: `docs: add Tempo ${release.tagName} release`, branch,
      sha: branchFile.sha,
      content: Buffer.from(updatePage(branchContent, release)).toString('base64'),
    });
  }
  const url = `https://github.com/tempoxyz/tempo/releases/tag/${release.tagName}`;
  const pr = api('POST', `${prefix}/pulls`, {
    base, head: branch, draft: true,
    title: `docs: add Tempo ${release.tagName} release`,
    body: `Adds [Tempo ${release.tagName}](${url}) to the node-operator release table. Merging also rebuilds the GitHub-backed node release notes.\n\nBefore marking ready for review:\n- Confirm the affected networks.\n- Summarize operator impact and classify upgrade priority.\n- Check whether linked network-upgrade or identity guidance needs changes.\n\nGenerated by [Update release docs](https://github.com/tempoxyz/tempo/actions/workflows/update-release-docs.yml).\n\n## Source release notes\n\n${release.body || 'No release notes were provided.'}`,
  });
  console.log(pr.html_url);
}

if (require.main === module) run(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')));

module.exports = { releaseEntry, updatePage, run };
