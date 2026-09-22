// Experimental workflow adapter. All slots remain on their reserved runners;
// only the deterministic winner may execute the existing benchmark steps.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const { createHash } = require('node:crypto');

const MAX_BYTES = 65536;
const PREFIX = 'bench-capacity-reservation-';
const SETUP_FAILURE_POLICY = 'setup_failure_v2';
const SINGLE_DIAGNOSTIC_POLICY = 'single_diagnostic_v1';
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
  requireValue(/^[12345]$/.test(env.BENCH_CAPACITY_SLOTS || ''));
  const slots = Number(env.BENCH_CAPACITY_SLOTS);
  requireValue(/^[12345]$/.test(env.BENCH_CAPACITY_SLOT || ''));
  const slot = Number(env.BENCH_CAPACITY_SLOT);
  requireValue(uint(attempt) && slot <= slots);
  const policy = env.BENCH_CAPACITY_POLICY ?? 'strict_v1';
  requireValue(['strict_v1', SETUP_FAILURE_POLICY, SINGLE_DIAGNOSTIC_POLICY].includes(policy));
  requireValue(policy !== 'strict_v1' || [2, 3, 4, 5].includes(slots));
  requireValue(policy !== SETUP_FAILURE_POLICY || [4, 5].includes(slots));
  requireValue(env.BENCH_LIFECYCLE === 'true' && env.BENCH_NO_SLACK === 'true');
  if (policy === SINGLE_DIAGNOSTIC_POLICY) {
    requireValue(slots === 1 && slot === 1);
    requireValue(env.BENCH_BINARY_MODE === 'prebuilt_v1');
    requireValue(env.BENCH_LIFECYCLE_DETAIL === 'milestones');
    const trial = env.BENCH_SELECTIVE_RETRY_TRIAL || '';
    requireValue(['', 'true'].includes(trial));
    requireValue(env.BENCH_RUN_SIDE === (trial === 'true' ? 'comparison' : 'feature') && env.BENCH_RUN_PAIRS === (trial === 'true' ? '6' : '1'));
    requireValue(env.BENCH_FEATURE_ENV === (trial === 'true' ? 'RETH_EXPERIMENTAL_SELECTIVE_STORAGE_RETRIES=1' : '') || (!trial && !env.BENCH_FEATURE_ENV));
    requireValue(env.BENCH_DURATION === (trial === 'true' ? '15' : '30'));
    requireValue(env.BENCH_READ_READINESS === (trial === 'true' ? 'false' : 'true'));
    requireValue(trial !== 'true' || (env.BENCH_PRESET === 'default' && env.BENCH_BLOAT === '100' && env.BENCH_TPS === '15000' && env.BENCH_ACCOUNTS === '1000' && env.BENCH_MAX_CONCURRENT_REQUESTS === '100' && env.BENCH_TOKEN_COUNT === '4'));
    requireValue(!env.BENCH_BASELINE_ENV && !env.BENCH_BENCH_ENV);
    const trialArgs = '--engine.storage-worker-count 32 --engine.account-worker-count 32 --engine.prewarming-threads 16';
    requireValue(trial !== 'true' || (env.BENCH_BASELINE_ARGS === trialArgs && env.BENCH_FEATURE_ARGS === trialArgs));
    requireValue(env.BENCH_LIFECYCLE_SCHEDULER === 'false');
    requireValue(env.BENCH_SAMPLY === 'false' && env.BENCH_TRACY === 'off');
    requireValue(env.BENCH_OTLP === 'false' && env.BENCH_VALSCOPE === 'false');
    requireValue(env.BENCH_METRICS === 'false');
  }
  return { workflow_sha: context.sha, run_id: context.runId, run_attempt: attempt, slot, slots, policy };
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

async function prebuilt(github, context, env, execute, timeout = 10000) {
  const allowance = () => typeof timeout === 'function' ? timeout() : timeout;
  const mode = env.BENCH_BINARY_MODE ?? 'build_v1';
  requireValue(['build_v1', 'prebuilt_v1'].includes(mode));
  if (mode === 'build_v1') {
    requireValue(!env.BENCH_PREBUILT_PLAN_SHA256);
    return null;
  }
  requireValue(
    (env.BENCH_CAPACITY_POLICY === SETUP_FAILURE_POLICY && env.BENCH_CAPACITY_SLOTS === '5') ||
    (env.BENCH_CAPACITY_POLICY === SINGLE_DIAGNOSTIC_POLICY && env.BENCH_CAPACITY_SLOTS === '1')
  );
  requireValue(/^[0-9a-f]{64}$/.test(env.BENCH_PREBUILT_PLAN_SHA256 || ''));
  const plan = await source(github, context, 'contrib/bench/lifecycle/prebuilt-plan.json', allowance());
  requireValue(createHash('sha256').update(plan).digest('hex') === env.BENCH_PREBUILT_PLAN_SHA256);
  const script = await source(github, context, 'contrib/bench/lifecycle/prebuilt.py', allowance());
  const proof = JSON.parse(python(script, [], plan, env, execute, [0], allowance()));
  requireValue(Object.keys(proof).sort().join() === 'mode,plan_sha256,required_bytes');
  requireValue(proof.mode === 'prebuilt_capture_v1' && proof.plan_sha256 === env.BENCH_PREBUILT_PLAN_SHA256);
  requireValue(uint(proof.required_bytes) && proof.required_bytes > 49152 * 1048576);
  return { plan, script, proof };
}

function withPrebuilt(script, config) {
  if (!config) return script;
  // Exact authenticated source, not imports from a writable runner checkout.
  const encoded = Buffer.from(config.script).toString('base64');
  return `import base64,types,sys\nm=types.ModuleType('prebuilt')\nexec(base64.b64decode('${encoded}'),m.__dict__)\nsys.modules['prebuilt']=m\n` + script;
}

async function probe({ github, context, core, env = process.env, execute = spawnSync }) {
  try {
    const bound = binding(context, env);
    const portable = await prebuilt(github, context, env, execute);
    const script = await source(github, context, 'contrib/bench/lifecycle/capacity_preflight.py');
    const capacity = JSON.parse(python(script, [], '', env, execute));
    validateCapacity(capacity);
    // Expected slot count is trusted workflow configuration, not receipt data.
    const { slots, policy, ...receiptBinding } = bound;
    const receipt = { schema: 1, ...receiptBinding, capacity, ...(portable ? { prebuilt: portable.proof } : {}) };
    const encoded = JSON.stringify(receipt);
    requireValue(Buffer.byteLength(encoded) <= 16384);
    const workspace = env.GITHUB_WORKSPACE;
    requireValue(workspace && fs.realpathSync(workspace) === path.resolve(workspace));
    const owned = fs.mkdtempSync(path.join(workspace, '.capacity-reservation-'));
    core.setOutput('artifact-path', path.relative(workspace, path.join(owned, 'receipt.json')));
    fs.writeFileSync(path.join(owned, 'receipt.json'), encoded, { flag: 'wx', mode: 0o600 });
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
  if item.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):raise ValueError()
  if item.filename!='receipt.json' or item.is_dir() or item.file_size>16384 or item.compress_size>16384 or item.flag_bits&1 or stat.S_IFMT(mode) not in (0,stat.S_IFREG):raise ValueError()
  with archive.open(item) as stream:
   content=stream.read(16385)
   if len(content)>16384 or stream.read(1):raise ValueError()
  if len(content)!=item.file_size:raise ValueError()
  sys.stdout.buffer.write(content)
except BaseException:
 sys.exit(1)
`;

function timestamp(value) {
  requireValue(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value));
  const parsed = Date.parse(value);
  requireValue(Number.isFinite(parsed) && new Date(parsed).toISOString() === value.replace('Z', '.000Z'));
  return parsed;
}

// Trust only authenticated, attempt-scoped terminal Actions accounting. Never
// inspect annotations/log text or export runner fields from the API response.
function setupFailures(data, bound) {
  requireValue(data && Number.isSafeInteger(data.total_count) && data.total_count >= 0 && data.total_count <= bound.slots);
  requireValue(Array.isArray(data.jobs) && data.jobs.length === data.total_count);
  requireValue(Buffer.byteLength(JSON.stringify(data)) <= MAX_BYTES);
  const seen = new Set(); const ids = new Set(); const failed = [];
  for (const job of data.jobs) {
    requireValue(uint(job.id) && !ids.has(job.id)); ids.add(job.id);
    requireValue(job.run_id === bound.run_id && job.run_attempt === bound.run_attempt && job.head_sha === bound.workflow_sha);
    const slot = Array.from({ length: bound.slots }, (_, i) => i + 1).find(i => job.name === `bench-e2e (reserved slot ${i})`);
    requireValue(slot && !seen.has(slot)); seen.add(slot);
    requireValue(['queued', 'in_progress', 'completed'].includes(job.status));
    requireValue(Array.isArray(job.steps) && job.steps.length <= 100);
    if (job.status !== 'completed') { requireValue(job.conclusion === null); continue; }
    if (job.conclusion === 'success') continue;
    requireValue(job.conclusion === 'failure' && job.steps.length === 1);
    const step = job.steps[0];
    requireValue(Object.keys(step).sort().join() === 'completed_at,conclusion,name,number,started_at,status');
    requireValue(step.number === 1 && step.name === 'Set up job' && step.status === 'completed' && step.conclusion === 'failure');
    const start = timestamp(job.started_at); const end = timestamp(job.completed_at);
    const stepStart = timestamp(step.started_at); const stepEnd = timestamp(step.completed_at);
    requireValue(start <= stepStart && stepStart <= stepEnd && stepEnd <= end);
    failed.push(slot);
  }
  return { complete: seen.size === bound.slots, failed: failed.sort((a, b) => a - b) };
}

function admissionReceipt(bound, failed, receipts, election, portable = null) {
  return { schema: 2, policy: SETUP_FAILURE_POLICY, workflow_sha: bound.workflow_sha,
    run_id: bound.run_id, run_attempt: bound.run_attempt, slots: bound.slots,
    selected_slot: election.selected_slot, setup_failed_slots: failed,
    ...(portable ? { prebuilt: portable.proof } : {}),
    capacity_receipts: receipts.map(value => ({ slot: JSON.parse(value).slot,
      sha256: createHash('sha256').update(value).digest('hex') })).sort((a, b) => a.slot - b.slot), election };
}

function publishAdmission(bound, failed, receipts, election, env, core, portable = null) {
  const workspace = env.GITHUB_WORKSPACE;
  requireValue(workspace && fs.realpathSync(workspace) === path.resolve(workspace));
  const encoded = JSON.stringify(admissionReceipt(bound, failed, receipts, election, portable));
  requireValue(Buffer.byteLength(encoded) <= 16384);
  const owned = fs.mkdtempSync(path.join(workspace, '.capacity-admission-'));
  core.setOutput('admission-path', path.relative(workspace, path.join(owned, 'admission.json')));
  fs.writeFileSync(path.join(owned, 'admission.json'), encoded, { flag: 'wx', mode: 0o600 });
  core.setOutput('admission-name', `bench-capacity-admission-${bound.run_id}-${bound.run_attempt}`);
}

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
    const portable = await prebuilt(github, context, env, execute, () => budget(10000));
    const script = withPrebuilt(await source(github, context, 'contrib/bench/lifecycle/capacity_election.py', budget(10000)), portable);
    budget(10000);
    const names = Array.from({ length: bound.slots }, (_, i) => artifactName(bound, i + 1));
    const accounted = bound.policy === SETUP_FAILURE_POLICY;
    const jobs = async () => {
      const { data } = await github.rest.actions.listJobsForWorkflowRunAttempt({
        ...context.repo, run_id: bound.run_id, attempt_number: bound.run_attempt, per_page: 100,
        request: requestOptions(budget(10000)),
      });
      budget(10000);
      return setupFailures(data, bound);
    };
    const inventory = async () => {
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
      return selected;
    };
    let artifacts; let failed = [];
    for (;;) {
      const state = accounted ? await jobs() : { complete: true, failed: [] };
      const selected = await inventory();
      requireValue(!state.failed.some(slot => selected.some(item => item.name === artifactName(bound, slot))));
      if (state.complete && selected.length + state.failed.length === bound.slots) {
        requireValue(selected.length > 0);
        artifacts = selected; failed = state.failed; break;
      }
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
    const electionArgs = [
      '--workflow-sha', bound.workflow_sha, '--run-id', String(bound.run_id),
      '--run-attempt', String(bound.run_attempt), '--slots', String(bound.slots),
    ];
    if (bound.policy !== 'strict_v1') electionArgs.push('--policy', bound.policy);
    if (portable) electionArgs.push('--binary-mode', 'prebuilt_v1');
    const input = portable && bound.policy === SINGLE_DIAGNOSTIC_POLICY ?
      `{"schema":3,"receipts":[${receipts.join(',')}],"prebuilt_plan":${JSON.stringify(portable.plan)}}` :
      portable ? `{"schema":2,"receipts":[${receipts.join(',')}],"setup_failed_slots":${JSON.stringify(failed)},"prebuilt_plan":${JSON.stringify(portable.plan)}}` :
      accounted ? `{"schema":2,"receipts":[${receipts.join(',')}],"setup_failed_slots":${JSON.stringify(failed)}}` : `[${receipts.join(',')}]`;
    const elected = JSON.parse(python(script, electionArgs, input, env, execute, [0, 2, 3], budget(60000)));
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
    requireValue(uint(elected.selected_slot) && elected.selected_slot <= bound.slots && elected.minimum_free_mib >= (portable ? Math.floor(portable.proof.required_bytes / 1048576) : 65536));
    requireValue(!failed.includes(elected.selected_slot) && receipts.some(value => JSON.parse(value).slot === elected.selected_slot));
    if (accounted) {
      const final = await jobs(); const latest = await inventory();
      requireValue(final.complete && JSON.stringify(final.failed) === JSON.stringify(failed));
      const identities = rows => rows.map(row => [row.name, row.id, row.size_in_bytes, row.expired, row.workflow_run]).sort((a, b) => a[0].localeCompare(b[0]));
      requireValue(JSON.stringify(identities(latest)) === JSON.stringify(identities(artifacts)));
      if (elected.selected_slot === bound.slot) {
        requireValue(receipts.some(value => JSON.parse(value).slot === bound.slot));
        publishAdmission(bound, failed, receipts, elected, env, core, portable);
      }
      budget(10000);
    }
    core.info(JSON.stringify(elected));
    core.setOutput('selected', String(elected.selected_slot === bound.slot));
  } catch (_) {
    core.setFailed('Capacity reservation election rejected; benchmark not admitted');
  }
}

module.exports = { probe, elect, binding, artifactName, EXTRACT_RECEIPT, validateCapacity, setupFailures, admissionReceipt, SETUP_FAILURE_POLICY, SINGLE_DIAGNOSTIC_POLICY, prebuilt, withPrebuilt };
