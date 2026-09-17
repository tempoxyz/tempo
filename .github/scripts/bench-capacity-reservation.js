// Experimental workflow adapter. All slots remain on their reserved runners;
// only the deterministic winner may execute the existing benchmark steps.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { performance } = require('node:perf_hooks');

const MAX_BYTES = 65536;
const PREFIX = 'bench-capacity-reservation-';
const silentLog = { debug() {}, info() {}, warn() {}, error() {} };

function requestOptions(timeout) {
  return { signal: AbortSignal.timeout(timeout), log: silentLog };
}

function requireValue(value) {
  if (!value) throw new Error('capacity reservation rejected');
}

function uint(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function binding(context, env) {
  requireValue(context.eventName === 'workflow_dispatch');
  requireValue(/^[0-9a-f]{40}$/.test(context.sha) && uint(context.runId));
  requireValue(/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT || ''));
  const attempt = Number(env.GITHUB_RUN_ATTEMPT);
  requireValue(/^[23]$/.test(env.BENCH_CAPACITY_SLOTS || ''));
  const slots = Number(env.BENCH_CAPACITY_SLOTS);
  requireValue(/^[123]$/.test(env.BENCH_CAPACITY_SLOT || ''));
  const slot = Number(env.BENCH_CAPACITY_SLOT);
  requireValue(uint(attempt) && slot <= slots);
  requireValue(env.BENCH_LIFECYCLE === 'true' && env.BENCH_NO_SLACK === 'true');
  return { workflow_sha: context.sha, run_id: context.runId, run_attempt: attempt, slot, slots };
}

async function source(github, context, filename, timeout = 10000) {
  const { data } = await github.rest.repos.getContent({
    ...context.repo, ref: context.sha, path: filename, request: requestOptions(timeout),
  });
  requireValue(data.type === 'file' && data.encoding === 'base64' && data.size <= MAX_BYTES);
  const bytes = Buffer.from(data.content, 'base64');
  requireValue(bytes.length === data.size && bytes.length <= MAX_BYTES);
  return bytes.toString('utf8');
}

function python(script, args, input, env, execute = spawnSync, accepted = [0], timeout = 60000) {
  const result = execute('python3', ['-I', '-c', script, ...args], {
    input, encoding: 'utf8', timeout, maxBuffer: MAX_BYTES,
    env: { PATH: env.PATH, GITHUB_WORKSPACE: env.GITHUB_WORKSPACE, RUNNER_TEMP: env.RUNNER_TEMP },
  });
  requireValue(!result.error && accepted.includes(result.status) && !result.stderr);
  requireValue(Buffer.byteLength(result.stdout) <= MAX_BYTES);
  return result.stdout;
}

function artifactName(bound, slot) {
  return `${PREFIX}${bound.run_id}-${bound.run_attempt}-${slot}`;
}

function validateCapacity(report) {
  const roles = ['root', 'workspace', 'runner_temp', 'optional_scratch'];
  const fields = ['role', 'exists', 'filesystem', 'total_bytes', 'free_bytes', 'read_only', 'writable', 'write_tested', 'status'];
  const statuses = ['unset', 'invalid_path', 'missing', 'redirected', 'not_directory', 'changed_directory', 'read_only', 'access_denied', 'write_failed', 'cleanup_failed', 'writable', 'unavailable'];
  const number = value => value === null || (Number.isSafeInteger(value) && value >= 0);
  const flag = value => value === null || typeof value === 'boolean';
  requireValue(report && Object.keys(report).sort().join() === 'locations,schema');
  requireValue(report.schema === 1 && Array.isArray(report.locations) && report.locations.length === 4);
  for (const [i, row] of report.locations.entries()) {
    requireValue(row && Object.keys(row).sort().join() === fields.slice().sort().join());
    requireValue(row.role === roles[i] && statuses.includes(row.status));
    requireValue(typeof row.exists === 'boolean' && typeof row.write_tested === 'boolean');
    requireValue(flag(row.read_only) && flag(row.writable));
    requireValue([row.filesystem, row.total_bytes, row.free_bytes].every(number));
    requireValue(row.filesystem === null || (row.filesystem >= 1 && row.filesystem <= 4));
  }
}

async function probe({ github, context, core, env = process.env, execute = spawnSync }) {
  try {
    const bound = binding(context, env);
    const script = await source(github, context, 'contrib/bench/lifecycle/capacity_preflight.py');
    const capacity = JSON.parse(python(script, [], '', env, execute));
    validateCapacity(capacity);
    // Expected slot count is trusted workflow configuration, not receipt data.
    const { slots, ...receiptBinding } = bound;
    const receipt = { schema: 1, ...receiptBinding, capacity };
    const encoded = JSON.stringify(receipt);
    requireValue(Buffer.byteLength(encoded) <= 16384);
    const workspace = env.GITHUB_WORKSPACE;
    requireValue(workspace && fs.realpathSync(workspace) === path.resolve(workspace));
    const owned = fs.mkdtempSync(path.join(workspace, '.capacity-reservation-'));
    fs.writeFileSync(path.join(owned, 'receipt.json'), encoded, { flag: 'wx', mode: 0o600 });
    core.setOutput('artifact-path', path.relative(workspace, path.join(owned, 'receipt.json')));
    core.setOutput('artifact-name', artifactName(bound, bound.slot));
    core.info('Numeric capacity receipt prepared');
  } catch (_) {
    core.setFailed('Capacity reservation probe rejected; benchmark not admitted');
  }
}

const EXTRACT_RECEIPT = `import io,stat,sys,zipfile
try:
 data=sys.stdin.buffer.read(65537)
 if len(data)>65536:raise ValueError()
 with zipfile.ZipFile(io.BytesIO(data)) as archive:
  entries=archive.infolist()
  if len(entries)!=1:raise ValueError()
  item=entries[0]
  mode=item.external_attr>>16
  if item.filename!='receipt.json' or item.is_dir() or item.file_size>16384 or item.compress_size>16384 or item.flag_bits&1 or stat.S_IFMT(mode) not in (0,stat.S_IFREG):raise ValueError()
  with archive.open(item) as stream:
   content=stream.read(16385)
   if len(content)>16384 or stream.read(1):raise ValueError()
  if len(content)!=item.file_size:raise ValueError()
  sys.stdout.buffer.write(content)
except BaseException:
 sys.exit(1)
`;

async function elect({ github, context, core, env = process.env, execute = spawnSync,
  now = () => performance.now(), sleep = ms => new Promise(resolve => setTimeout(resolve, ms)), timeoutMs = 180000 }) {
  try {
    const bound = binding(context, env);
    core.setOutput('selected', 'false');
    const deadline = now() + timeoutMs;
    const budget = maximum => {
      const remaining = Math.floor(deadline - now());
      requireValue(remaining > 0);
      return Math.min(maximum, remaining);
    };
    const script = await source(github, context, 'contrib/bench/lifecycle/capacity_election.py', budget(10000));
    budget(10000);
    const names = Array.from({ length: bound.slots }, (_, i) => artifactName(bound, i + 1));
    let artifacts;
    for (;;) {
      const { data } = await github.rest.actions.listWorkflowRunArtifacts({
        ...context.repo, run_id: bound.run_id, per_page: 100, request: requestOptions(budget(10000)),
      });
      budget(10000);
      requireValue(Number.isSafeInteger(data.total_count) && data.total_count <= 100);
      requireValue(Array.isArray(data.artifacts) && data.artifacts.length === data.total_count);
      const current = `${PREFIX}${bound.run_id}-${bound.run_attempt}-`;
      const selected = data.artifacts.filter(item => item.name.startsWith(current));
      requireValue(selected.every(item => names.includes(item.name)));
      requireValue(new Set(selected.map(item => item.name)).size === selected.length);
      if (selected.length === bound.slots) { artifacts = selected; break; }
      await sleep(budget(3000));
    }
    const receipts = [];
    for (const item of artifacts) {
      requireValue(uint(item.id) && item.expired === false && uint(item.size_in_bytes) && item.size_in_bytes <= MAX_BYTES);
      requireValue(item.workflow_run?.id === bound.run_id && item.workflow_run?.head_sha === bound.workflow_sha);
      const { data } = await github.rest.actions.downloadArtifact({
        ...context.repo, artifact_id: item.id, archive_format: 'zip', request: requestOptions(budget(10000)),
      });
      budget(10000);
      const bytes = Buffer.from(data);
      requireValue(bytes.length <= MAX_BYTES);
      // Preserve original JSON bytes, including duplicate keys, for the strict
      // Python decoder. Never parse/re-encode an unvalidated receipt in JS.
      const receipt = python(EXTRACT_RECEIPT, [], bytes, env, execute, [0], budget(60000));
      budget(10000);
      const parsed = JSON.parse(receipt);
      requireValue(item.name === artifactName(bound, parsed.slot) && uint(parsed.slot) && parsed.slot <= bound.slots);
      receipts.push(receipt);
    }
    const elected = JSON.parse(python(script, [
      '--workflow-sha', bound.workflow_sha, '--run-id', String(bound.run_id),
      '--run-attempt', String(bound.run_attempt), '--slots', String(bound.slots),
    ], `[${receipts.join(',')}]`, env, execute, [0, 2, 3], budget(60000)));
    budget(10000);
    const fields = ['schema', 'status', 'selected_slot', 'root_free_mib', 'workspace_free_mib', 'minimum_free_mib'];
    requireValue(Object.keys(elected).sort().join() === fields.sort().join());
    requireValue(Object.values(elected).every(value => Number.isSafeInteger(value) && value >= 0));
    requireValue(elected.schema === 1 && [0, 1, 2].includes(elected.status));
    if (elected.status !== 0) {
      requireValue(elected.selected_slot === 0 && elected.root_free_mib === 0 && elected.workspace_free_mib === 0 && elected.minimum_free_mib === 0);
      core.info(JSON.stringify(elected));
      requireValue(false);
    }
    requireValue(uint(elected.selected_slot) && elected.selected_slot <= bound.slots && elected.minimum_free_mib >= 65536);
    core.info(JSON.stringify(elected));
    core.setOutput('selected', String(elected.selected_slot === bound.slot));
  } catch (_) {
    core.setFailed('Capacity reservation election rejected; benchmark not admitted');
  }
}

module.exports = { probe, elect, binding, artifactName, EXTRACT_RECEIPT, validateCapacity };
