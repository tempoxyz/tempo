'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const adapter = require('./bench-capacity-reservation.js');
const root = path.resolve(__dirname, '../..');
const election = fs.readFileSync(path.join(root, 'contrib/bench/lifecycle/capacity_election.py'), 'utf8');
const probeSource = fs.readFileSync(path.join(root, 'contrib/bench/lifecycle/capacity_preflight.py'), 'utf8');
const prebuiltSource = fs.readFileSync(path.join(root, 'contrib/bench/lifecycle/prebuilt.py'), 'utf8');
const prebuiltPlan = fs.readFileSync(path.join(root, 'contrib/bench/lifecycle/prebuilt-plan.json'), 'utf8');
const prebuiltProofResult = spawnSync('python3', ['-I', '-c', prebuiltSource], {
  input: prebuiltPlan, encoding: 'utf8', maxBuffer: 65536,
});
assert.equal(prebuiltProofResult.status, 0, prebuiltProofResult.stderr);
const prebuiltProof = JSON.parse(prebuiltProofResult.stdout);
const SHA = '1'.repeat(40);
const context = { eventName: 'workflow_dispatch', sha: SHA, runId: 12345, repo: { owner: 'fixture', repo: 'repo' } };
const secret = 'PRIVATE_SENTINEL_TOKEN_HOST_PATH';

function capacity(freeGiB = 96) {
  const rows = ['root', 'workspace', 'runner_temp'].map(role => ({
    role, exists: true, filesystem: 1, total_bytes: 256 * 2 ** 30,
    free_bytes: freeGiB * 2 ** 30, read_only: false,
    writable: role !== 'root', write_tested: role !== 'root', status: role === 'root' ? 'access_denied' : 'writable',
  }));
  rows.push({ role: 'optional_scratch', exists: false, filesystem: null, total_bytes: null,
    free_bytes: null, read_only: null, writable: null, write_tested: false, status: 'unset' });
  return { schema: 1, locations: rows };
}
function receipt(slot, free = slot === 1 ? 96 : 144) {
  return { schema: 1, workflow_sha: SHA, run_id: 12345, run_attempt: 3, slot, capacity: capacity(free) };
}
function artifact(slot) {
  return { id: 100 + slot, name: `bench-capacity-reservation-12345-3-${slot}`, expired: false,
    size_in_bytes: 2048, workflow_run: { id: 12345, head_sha: SHA } };
}
function zip(content, options = {}) {
  const script = `import io,json,stat,sys,zipfile
value=json.load(sys.stdin);out=io.BytesIO()
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
 info=zipfile.ZipInfo(value.get('name','receipt.json'));info.compress_type=value.get('method',zipfile.ZIP_DEFLATED)
 info.external_attr=((stat.S_IFLNK|0o777) if value.get('symlink') else (stat.S_IFREG|0o600))<<16
 z.writestr(info,value['content'])
 if value.get('extra'):z.writestr('extra',b'private')
sys.stdout.buffer.write(out.getvalue())`;
  const result = spawnSync('python3', ['-I', '-c', script], {
    input: JSON.stringify({ content, ...options }), maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, String(result.stderr));
  return result.stdout;
}
const validZips = new Map([1, 2, 3, 4, 5].map(slot => [100 + slot, zip(JSON.stringify(receipt(slot)))]));

function fixture(options = {}) {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'capacity-transport-'));
  const env = { PATH: process.env.PATH, GITHUB_WORKSPACE: workspace, RUNNER_TEMP: workspace,
    GITHUB_RUN_ATTEMPT: '3', BENCH_CAPACITY_SLOT: String(options.slot || 1), BENCH_CAPACITY_SLOTS: String(options.slots || 2),
    BENCH_LIFECYCLE: 'true', BENCH_NO_SLACK: 'true', GITHUB_TOKEN: secret };
  if (options.policy !== undefined) env.BENCH_CAPACITY_POLICY = options.policy;
  if (options.policy === adapter.SINGLE_DIAGNOSTIC_POLICY) Object.assign(env, {
    BENCH_BINARY_MODE: 'prebuilt_v1',
    BENCH_PREBUILT_PLAN_SHA256: require('node:crypto').createHash('sha256').update(prebuiltPlan).digest('hex'),
    BENCH_LIFECYCLE_DETAIL: 'milestones', BENCH_RUN_SIDE: 'feature', BENCH_RUN_PAIRS: '1',
    BENCH_DURATION: '30', BENCH_FEATURE_ENV: '', BENCH_READ_READINESS: 'true',
    BENCH_BASELINE_ENV: '', BENCH_BENCH_ENV: '', BENCH_LIFECYCLE_SCHEDULER: 'false',
    BENCH_SAMPLY: 'false', BENCH_TRACY: 'off', BENCH_OTLP: 'false',
    BENCH_VALSCOPE: 'false', BENCH_METRICS: 'false',
  });
  const messages = []; const output = {}; const requests = []; let clock = 0; let lists = 0; let jobLists = 0;
  const core = { setOutput: (k, v) => { output[k] = v; }, info: m => messages.push(String(m)),
    setFailed: m => messages.push(`FAILED:${m}`) };
  const github = { rest: { repos: { getContent: async args => {
    requests.push(['source', args]);
    assert.equal(args.ref, SHA); assert.deepEqual({ owner: args.owner, repo: args.repo }, context.repo);
    assert.ok(['contrib/bench/lifecycle/capacity_election.py', 'contrib/bench/lifecycle/capacity_preflight.py',
      'contrib/bench/lifecycle/prebuilt-plan.json', 'contrib/bench/lifecycle/prebuilt.py'].includes(args.path));
    assert.ok(args.request.signal instanceof AbortSignal);
    assert.equal(args.request.signal.aborted, false);
    assert.equal(args.request.log.warn('private sentinel'), undefined);
    if (options.sourceError) throw new Error(secret);
    if (options.sourceData) return { data: options.sourceData };
    if (options.sourceClock) clock += options.sourceClock;
    const text = args.path.endsWith('capacity_election.py') ? election :
      args.path.endsWith('capacity_preflight.py') ? probeSource :
      args.path.endsWith('prebuilt-plan.json') ? prebuiltPlan : prebuiltSource;
    return { data: { type: 'file', encoding: 'base64', size: Buffer.byteLength(text), content: Buffer.from(text).toString('base64') } };
  } }, actions: { listJobsForWorkflowRunAttempt: async args => {
    requests.push(['jobs', args]);
    assert.equal(args.run_id, context.runId); assert.equal(args.attempt_number, 3); assert.equal(args.per_page, 100);
    assert.ok(args.request.signal instanceof AbortSignal);
    if (options.jobsError) throw new Error(secret);
    if (options.jobsClock) clock += options.jobsClock;
    const data = options.jobPages ? options.jobPages[Math.min(jobLists++, options.jobPages.length-1)] : options.jobs;
    return {data};
  }, listWorkflowRunArtifacts: async args => {
    requests.push(['list', args]); assert.equal(args.run_id, context.runId); assert.equal(args.per_page, 100);
    assert.ok(args.request.signal instanceof AbortSignal);
    assert.equal(args.request.signal.aborted, false);
    assert.equal(args.request.log.warn('private sentinel'), undefined);
    if (options.listError) throw new Error(secret);
    if (options.listClock) clock += options.listClock;
    const rows = options.pages ? options.pages[Math.min(lists++, options.pages.length - 1)] : options.artifacts || [artifact(1), artifact(2)];
    return { data: options.listData || { total_count: rows.length, artifacts: rows } };
  }, downloadArtifact: async args => {
    requests.push(['download', args]); assert.equal(args.archive_format, 'zip'); assert.ok([101, 102, 103, 104, 105].includes(args.artifact_id));
    assert.ok(args.request.signal instanceof AbortSignal);
    assert.equal(args.request.signal.aborted, false);
    assert.equal(args.request.log.warn('private sentinel'), undefined);
    assert.equal(args.url, undefined); assert.equal(args.headers, undefined); // Never consume artifact-supplied URLs/tokens.
    if (options.downloadError) throw new Error(secret);
    if (options.downloadClock) clock += options.downloadClock;
    return { data: (options.zips || validZips).get(args.artifact_id) };
  } } } };
  const execute = (command, args, opts) => {
    assert.equal(command, 'python3'); assert.equal(args[0], '-I'); assert.equal(args[1], '-c');
    assert.ok(args[2] === election || args[2] === adapter.EXTRACT_RECEIPT ||
      args[2] === prebuiltSource || args[2].endsWith(election));
    assert.equal(opts.env.GITHUB_TOKEN, undefined); assert.ok(opts.timeout > 0 && opts.timeout <= 60000);
    if (args.includes('--workflow-sha')) assert.deepEqual(args.slice(3), ['--workflow-sha', SHA, '--run-id', '12345', '--run-attempt', '3', '--slots', String(options.slots || 2), ...(!options.policy || options.policy === 'strict_v1' ? [] : ['--policy', options.policy]), ...(options.policy === adapter.SINGLE_DIAGNOSTIC_POLICY ? ['--binary-mode', 'prebuilt_v1'] : [])]);
    if (options.pythonResult) return options.pythonResult;
    const result = spawnSync(command, args, opts);
    if (options.pythonClock) clock += options.pythonClock;
    return result;
  };
  return { github, context, core, env, output, messages, requests, execute,
    now: () => clock, sleep: async ms => { assert.ok(ms > 0 && ms <= 3000); clock += ms; },
    close: () => fs.rmSync(workspace, { recursive: true, force: true }) };
}
async function elect(options = {}) {
  const f = fixture(options);
  try {
    await adapter.elect({ ...f, timeoutMs: options.timeoutMs ?? 9000 });
    assert.ok(f.messages.every(m => !m.includes(secret)));
    const admission = f.output['admission-path'] ? JSON.parse(fs.readFileSync(path.join(f.env.GITHUB_WORKSPACE,f.output['admission-path']),'utf8')) : null;
    assert.ok(!JSON.stringify(admission).includes(secret));
    return { output: f.output, messages: f.messages, requests: f.requests, elapsed: f.now(), admission };
  } finally { f.close(); }
}
function rejected(result) {
  assert.equal(result.output.selected, 'false');
  assert.ok(result.messages.some(m => m.startsWith('FAILED:')));
}

test('actual Python election and ZIP decoder elect one winner from either order/slot', async () => {
  for (const artifacts of [[artifact(1), artifact(2)], [artifact(2), artifact(1)]]) {
    const outcomes = await Promise.all([elect({ artifacts, slot: 1 }), elect({ artifacts, slot: 2 })]);
    assert.deepEqual(outcomes.map(r => r.output.selected), ['false', 'true']);
    assert.ok(outcomes.every(r => !r.messages.some(m => m.startsWith('FAILED:'))));
    for (const result of outcomes) {
      assert.equal(result.requests.filter(([kind]) => kind === 'source').length, 1);
      assert.equal(result.requests.filter(([kind]) => kind === 'download').length, 2);
    }
  }
});

test('delayed second receipt waits; missing or stale attempts time out without fallback', async () => {
  const ready = await elect({ slot: 2, pages: [[artifact(1)], [artifact(1), artifact(2)]] });
  assert.equal(ready.output.selected, 'true'); assert.equal(ready.elapsed, 3000);
  for (const rows of [[artifact(1)], [{ ...artifact(1), name: 'bench-capacity-reservation-12345-2-1' }]]) {
    const result = await elect({ artifacts: rows }); rejected(result);
    assert.equal(result.elapsed, 9000); assert.equal(result.requests.filter(([kind]) => kind === 'download').length, 0);
  }
});

test('deadline includes network/Python stages, not only polling sleeps', async () => {
  for (const options of [{ sourceClock: 10000 }, { listClock: 10000 }, { downloadClock: 10000 }, { pythonClock: 10000 }]) {
    rejected(await elect({ slot: 2, timeoutMs: 9000, ...options }));
  }
});

test('duplicate, foreign, stale, extra slot and filename/body mismatches reject', async () => {
  for (const rows of [
    [artifact(1), artifact(1)],
    [artifact(1), { ...artifact(2), workflow_run: { id: 12346, head_sha: SHA } }],
    [artifact(1), { ...artifact(2), workflow_run: { id: 12345, head_sha: '2'.repeat(40) } }],
    [artifact(1), { ...artifact(2), expired: true }],
    [artifact(1), { ...artifact(2), size_in_bytes: 65537 }],
    [artifact(1), { ...artifact(2), name: 'bench-capacity-reservation-12345-3-3' }],
  ]) rejected(await elect({ artifacts: rows }));
  for (const change of [{ slot: 1 }, { run_attempt: 2 }, { workflow_sha: '2'.repeat(40) }, { run_id: 12346 }]) {
    const zips = new Map(validZips); zips.set(102, zip(JSON.stringify({ ...receipt(2), ...change })));
    rejected(await elect({ zips }));
  }
});

test('no eligible pair emits closed unavailable result and fails', async () => {
  const zips = new Map([1, 2].map(slot => [100 + slot, zip(JSON.stringify(receipt(slot, 48)))]));
  const result = await elect({ zips }); rejected(result);
  const numeric = result.messages.filter(m => m.startsWith('{')).map(JSON.parse);
  assert.deepEqual(numeric, [{ schema: 1, status: 2, selected_slot: 0, root_free_mib: 0, workspace_free_mib: 0, minimum_free_mib: 0 }]);
});

test('invalid, oversized, traversing, multiple, symlink and duplicate-key archives reject', async () => {
  const content = JSON.stringify(receipt(2));
  const malformed = [Buffer.from('invalid ZIP'), Buffer.alloc(65537), zip('x'.repeat(16385)),
    zip(content, { name: '../receipt.json' }), zip(content, { extra: true }), zip(content, { symlink: true }),
    zip(content.replace('"slot":2', '"slot":1,"slot":2')),
    zip(content.replace('"schema":1', '"schema":1,"schema":1'))];
  for (const bytes of malformed) {
    const zips = new Map(validZips); zips.set(102, bytes); rejected(await elect({ zips }));
  }
});

test('CRC, encryption, unsupported method and declared ZIP size fail closed', async () => {
  for (const kind of ['crc', 'encrypted', 'method', 'size']) {
    const bytes = Buffer.from(validZips.get(102)); const central = bytes.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    assert.ok(central > 0);
    if (kind === 'crc') bytes.writeUInt32LE((bytes.readUInt32LE(central + 16) ^ 1) >>> 0, central + 16);
    if (kind === 'encrypted') bytes.writeUInt16LE(bytes.readUInt16LE(central + 8) | 1, central + 8);
    if (kind === 'method') bytes.writeUInt16LE(99, central + 10);
    if (kind === 'size') bytes.writeUInt32LE(16385, central + 24);
    const zips = new Map(validZips); zips.set(102, bytes); rejected(await elect({ zips }));
  }
});

test('bounded source/list shapes and subprocess failures reject without private output', async () => {
  const cases = [
    { sourceData: { type: 'dir', encoding: 'base64', size: 0, content: '' } },
    { sourceData: { type: 'file', encoding: 'base64', size: 65537, content: '' } },
    { sourceData: { type: 'file', encoding: 'base64', size: 1, content: '' } },
    { listData: { total_count: 101, artifacts: [] } },
    { listData: { total_count: 2, artifacts: [artifact(1)] } },
    { pythonResult: { error: new Error(secret), status: null, stdout: '', stderr: secret } },
    { pythonResult: { status: 0, stdout: '', stderr: secret } },
    { pythonResult: { status: 0, stdout: secret, stderr: '' } },
  ];
  for (const options of cases) rejected(await elect(options));
});

test('API failures cannot echo token/host/path/response sentinels', async () => {
  for (const options of [{ sourceError: true }, { listError: true }, { downloadError: true }]) {
    const result = await elect(options); rejected(result);
    assert.deepEqual(result.messages, ['FAILED:Capacity reservation election rejected; benchmark not admitted']);
  }
});

test('pre-upload probe validates closed privacy vocabulary and fetches immutable code', async () => {
  for (const mutation of [null, r => { r.hostname = secret; }, r => { r.locations[0].status = secret; },
    r => { r.locations[0].free_bytes = secret; }, r => { r.locations[0].filesystem = 5; }]) {
    const f = fixture(); const report = capacity(); if (mutation) mutation(report);
    try {
      // A stale workspace helper must never be loaded before reset/checkout.
      const stale = path.join(f.env.GITHUB_WORKSPACE, 'contrib/bench/lifecycle'); fs.mkdirSync(stale, { recursive: true });
      fs.writeFileSync(path.join(stale, 'capacity_preflight.py'), `raise Exception('${secret}')`);
      const execute = (command, args, options) => {
        assert.equal(command, 'python3'); assert.deepEqual(args, ['-I', '-c', probeSource]);
        assert.equal(options.env.GITHUB_TOKEN, undefined); assert.equal(options.env.PATH, process.env.PATH);
        return { status: 0, stdout: JSON.stringify(report), stderr: '' };
      };
      await adapter.probe({ ...f, execute });
      assert.ok(f.messages.every(m => !m.includes(secret)));
      if (mutation) {
        assert.equal(f.output['artifact-path'], undefined);
        assert.ok(f.messages.some(m => m.startsWith('FAILED:')));
        assert.equal(fs.readdirSync(f.env.GITHUB_WORKSPACE).filter(n => n.startsWith('.capacity-reservation-')).length, 0);
      } else {
        const receiptPath = path.join(f.env.GITHUB_WORKSPACE, f.output['artifact-path']);
        assert.deepEqual(JSON.parse(fs.readFileSync(receiptPath, 'utf8')), receipt(1, 96));
        assert.equal(f.output['artifact-name'], 'bench-capacity-reservation-12345-3-1');
        assert.equal(fs.statSync(receiptPath).mode & 0o777, 0o600);
        assert.deepEqual(fs.readdirSync(path.dirname(receiptPath)), ['receipt.json']);
      }
    } finally { f.close(); }
  }
});

// Only a real AbortSignal interrupts the request transport used by github-script.
// A numeric request.timeout option is ignored by its pinned Octokit version.
test('an awaited request aborts within the real election budget', async () => {
  const f = fixture();
  let observed = false;
  f.github.rest.repos.getContent = async args => new Promise((resolve, reject) => {
    args.request.signal.addEventListener('abort', () => {
      observed = true;
      reject(new Error('private transport sentinel'));
    }, { once: true });
  });
  const keepAlive = setTimeout(() => {}, 1000);
  try {
    await adapter.elect({ ...f, now: () => performance.now(), timeoutMs: 25 });
    assert.equal(observed, true);
    rejected({ output: f.output, messages: f.messages });
  } finally {
    clearTimeout(keepAlive);
    f.close();
  }
});


test('three receipts elect exactly one winner across all slot orders and capacity cases', async () => {
  const permutations = [[1,2,3],[1,3,2],[2,1,3],[2,3,1],[3,1,2],[3,2,1]];
  for (const [free, winner] of [[[144,96,48],1], [[48,96,144],3], [[96,144,96],2], [[96,96,96],1]]) {
    const zips = new Map(free.map((value, i) => [101+i, zip(JSON.stringify(receipt(i+1,value)))]));
    for (const order of permutations) {
      const outcomes = [];
      for (const slot of [1,2,3]) {
        const result = await elect({ slots: 3, slot, artifacts: order.map(artifact), zips });
        assert.ok(!result.messages.some(m => m.startsWith('FAILED:')));
        assert.equal(result.requests.filter(([kind]) => kind === 'download').length, 3);
        outcomes.push(result.output.selected);
      }
      assert.deepEqual(outcomes, [1,2,3].map(slot => String(slot === winner)));
    }
  }
});

test('three-slot admission requires every receipt and keeps the total deadline', async () => {
  for (const rows of [[artifact(1),artifact(2)], [artifact(1),artifact(3)], [artifact(2),artifact(3)]]) {
    const result = await elect({ slots: 3, artifacts: rows }); rejected(result);
    assert.equal(result.elapsed,9000);
    assert.equal(result.requests.filter(([kind]) => kind === 'download').length,0);
  }
  const all = [artifact(3),artifact(1),artifact(2)];
  const delayed = await elect({ slots: 3, slot: 3, pages: [[artifact(1),artifact(2)], all] });
  assert.equal(delayed.elapsed,3000);
  // Default fixture ties slot2/3: lower slot2 wins.
  assert.equal(delayed.output.selected,'false');
  for (const options of [{sourceClock:9000},{listClock:9000},{downloadClock:3000},{pythonClock:3000}]) {
    rejected(await elect({ slots:3, slot:3, artifacts:all, ...options }));
  }
  for (const artifacts of [[artifact(1),artifact(2),artifact(2)], [...all,{...artifact(1),name:'bench-capacity-reservation-12345-3-4'}]]) {
    rejected(await elect({ slots:3, artifacts }));
  }
  const zips = new Map([1,2,3].map(slot=>[100+slot,zip(JSON.stringify(receipt(slot,48)))]));
  const none = await elect({ slots:3, artifacts:all, zips }); rejected(none);
  assert.equal(JSON.parse(none.messages.find(m=>m.startsWith('{'))).status,2);
});

test('slot count is explicit private configuration and never expands receipt schema', async () => {
  const f=fixture({slots:3,slot:3});
  try {
    for (const slots of [undefined,'','1','6','03','3.0','04','4.0','05','5.0']) {
      assert.throws(()=>adapter.binding(context,{...f.env,BENCH_CAPACITY_SLOTS:slots}));
    }
    assert.throws(()=>adapter.binding(context,{...f.env,BENCH_CAPACITY_SLOTS:'2'}));
    const execute=()=>({status:0,stdout:JSON.stringify(capacity()),stderr:''});
    await adapter.probe({...f,execute});
    const value=JSON.parse(fs.readFileSync(path.join(f.env.GITHUB_WORKSPACE,f.output['artifact-path']),'utf8'));
    assert.deepEqual(value,receipt(3,96));
    assert.equal(Object.hasOwn(value,'slots'),false);
    assert.equal(f.output['artifact-name'],'bench-capacity-reservation-12345-3-3');
  } finally { f.close(); }
  const zips=new Map(validZips);
  zips.set(103,zip(JSON.stringify({...receipt(3),slots:3})));
  rejected(await elect({slots:3,artifacts:[artifact(1),artifact(2),artifact(3)],zips}));
});

function permutations(values) {
  if (values.length === 0) return [[]];
  return values.flatMap((value, i) => permutations(values.filter((_, j) => i !== j)).map(rest => [value, ...rest]));
}

test('four slots use complete receipts for every order and preserve deterministic ties', async () => {
  for (const [free, winner] of [[[48,96,112,144],4], [[96,96,96,96],1]]) {
    const zips = new Map(free.map((value, i) => [101+i, zip(JSON.stringify(receipt(i+1,value)))]));
    for (const order of permutations([1,2,3,4])) {
      const outcomes = [];
      for (const slot of [1,2,3,4]) {
        const result = await elect({ slots:4, slot, artifacts:order.map(artifact), zips });
        assert.ok(!result.messages.some(m => m.startsWith('FAILED:')));
        assert.equal(result.requests.filter(([kind])=>kind==='download').length,4);
        outcomes.push(result.output.selected);
      }
      assert.deepEqual(outcomes,[1,2,3,4].map(slot=>String(slot===winner)));
    }
  }
});

test('four slots reject incomplete foreign malformed and oversized receipt sets within deadline', async () => {
  const all=[1,2,3,4].map(artifact);
  for (let absent=0; absent<4; absent++) {
    const result=await elect({slots:4,artifacts:all.filter((_,i)=>i!==absent)});
    rejected(result);assert.equal(result.elapsed,9000);
    assert.equal(result.requests.filter(([kind])=>kind==='download').length,0);
  }
  for (const artifacts of [[...all,artifact(5)], [artifact(1),artifact(2),artifact(3),artifact(3)],
      all.map((a,i)=>i===3?{...a,workflow_run:{id:12346,head_sha:SHA}}:a),
      all.map((a,i)=>i===3?{...a,size_in_bytes:65537}:a),
      all.map((a,i)=>i===3?{...a,size_in_bytes:true}:a)]) {
    rejected(await elect({slots:4,artifacts}));
  }
  for (const options of [{sourceClock:9000},{listClock:9000},{downloadClock:2250},{pythonClock:2250}]) {
    rejected(await elect({slots:4,artifacts:all,...options}));
  }
  for (const body of [JSON.stringify({...receipt(4),slots:4}),
      JSON.stringify({...receipt(4),slot:3}), JSON.stringify({...receipt(4),run_attempt:2}),
      JSON.stringify(receipt(4)).replace('"slot":4','"slot":true'),
      JSON.stringify(receipt(4)).replace('"schema":1','"schema":1,"schema":1')]) {
    const zips=new Map(validZips);zips.set(104,zip(body));
    rejected(await elect({slots:4,artifacts:all,zips}));
  }
  const zips=new Map([1,2,3,4].map(slot=>[100+slot,zip(JSON.stringify(receipt(slot,48)))]));
  const none=await elect({slots:4,artifacts:all,zips});rejected(none);
  assert.equal(JSON.parse(none.messages.find(m=>m.startsWith('{'))).status,2);
  const delayed=await elect({slots:4,slot:2,pages:[all.slice(0,3),all]});
  assert.equal(delayed.elapsed,3000);assert.equal(delayed.output.selected,'true');
});

test('four-slot probe preserves closed receipt schema and exact configuration admission', async () => {
  const f=fixture({slots:4,slot:4});
  try {
    for (const value of ['','0','6','04','4.0','05','5.0']) {
      assert.throws(()=>adapter.binding(context,{...f.env,BENCH_CAPACITY_SLOT:value}));
    }
    for (const value of ['2','3','6','04','4.0','05','5.0']) {
      assert.throws(()=>adapter.binding(context,{...f.env,BENCH_CAPACITY_SLOTS:value}));
    }
    await adapter.probe({...f,execute:()=>({status:0,stdout:JSON.stringify(capacity()),stderr:''})});
    const value=JSON.parse(fs.readFileSync(path.join(f.env.GITHUB_WORKSPACE,f.output['artifact-path']),'utf8'));
    assert.deepEqual(value,receipt(4,96));
    assert.equal(f.output['artifact-name'],'bench-capacity-reservation-12345-3-4');
  } finally {f.close();}
});

function job(slot, failed = false) {
  return { id:500+slot, run_id:12345, run_attempt:3, head_sha:SHA,
    name:`bench-e2e (reserved slot ${slot})`, status:failed?'completed':'in_progress',
    conclusion:failed?'failure':null, started_at:'2026-09-17T09:00:00Z',
    completed_at:failed?'2026-09-17T09:00:10Z':null,
    runner_name:secret, labels:[secret], steps:[{number:1,name:'Set up job',status:'completed',
      conclusion:failed?'failure':'success',started_at:'2026-09-17T09:00:01Z',completed_at:'2026-09-17T09:00:09Z'}] };
}
function accountedOptions(failed = [4]) {
  return {slots:4,slot:2,policy:adapter.SETUP_FAILURE_POLICY,
    jobs:{total_count:4,jobs:[1,2,3,4].map(slot=>job(slot,failed.includes(slot)))},
    artifacts:[1,2,3,4].filter(slot=>!failed.includes(slot)).map(artifact)};
}

test('setup-only accounting requires every slot and emits only exact sanitized winner evidence', async () => {
  const base=accountedOptions();
  for (const order of permutations([1,2,3,4])) {
    for (const slot of [1,2,3]) {
      const result=await elect({...base,slot,jobs:{total_count:4,jobs:order.map(i=>job(i,i===4))}});
      assert.ok(!result.messages.some(m=>m.startsWith('FAILED:')));
      assert.equal(result.output.selected,String(slot===2));
      assert.equal(result.requests.filter(([kind])=>kind==='jobs').length,2);
      if(slot===2) {
        assert.deepEqual(Object.keys(result.admission).sort(),['schema','policy','workflow_sha','run_id','run_attempt','slots','selected_slot','setup_failed_slots','capacity_receipts','election'].sort());
        assert.deepEqual(result.admission.setup_failed_slots,[4]);
        assert.equal(result.output['admission-name'],'bench-capacity-admission-12345-3');
        assert.equal(result.admission.schema,2);assert.equal(result.admission.selected_slot,2);
        assert.deepEqual(result.admission.capacity_receipts,[1,2,3].map(slot=>({slot,sha256:require('node:crypto').createHash('sha256').update(JSON.stringify(receipt(slot))).digest('hex')})));
      } else assert.equal(result.admission,null);
    }
  }
  for (const failed of [[1],[2],[3],[4],[1,2,3]]) {
    const options=accountedOptions(failed);options.slot=failed.includes(2)?(failed.includes(3)?4:3):2;
    const result=await elect(options);assert.equal(result.output.selected,'true');
    assert.deepEqual(result.admission.setup_failed_slots,failed);
  }
  const normal=await elect(accountedOptions([]));assert.equal(normal.output.selected,'true');
  assert.deepEqual(normal.admission.setup_failed_slots,[]);
});

test('setup-only accounting rejects every ambiguous API step binding or timestamp', async () => {
  const changes=[
    j=>{j.status='in_progress';j.conclusion=null;},
    j=>{j.status='queued';j.conclusion=null;},
    j=>{j.conclusion='cancelled';},j=>{j.conclusion='timed_out';},j=>{j.conclusion='success';},
    j=>{j.steps.push({...j.steps[0],number:2,name:'Probe reserved runner capacity'});},
    j=>{j.steps.push({...j.steps[0],number:2,name:'Run e2e benchmark',conclusion:'skipped'});},
    j=>{j.steps[0].name='Probe reserved runner capacity';},j=>{j.steps[0].number=2;},
    j=>{j.steps[0].conclusion='success';},j=>{j.steps[0].status='in_progress';},
    j=>{j.steps[0].private=secret;},j=>{j.steps[0].started_at='2026-09-17T08:59:59Z';},
    j=>{j.steps[0].completed_at='2026-09-17T09:00:11Z';},
    j=>{j.completed_at='2026-09-17T08:00:00Z';},j=>{j.started_at='2026-02-31T09:00:00Z';},
    j=>{j.steps[0].completed_at=null;},j=>{j.steps[0].number=true;},
    j=>{j.run_id++;},j=>{j.run_attempt++;},j=>{j.head_sha='2'.repeat(40);},
    j=>{j.id=501;},j=>{j.name='bench-e2e (reserved slot 3)';},j=>{j.name='untrusted';},
  ];
  for(const change of changes) {
    const options=accountedOptions();change(options.jobs.jobs[3]);
    const result=await elect(options);rejected(result);assert.equal(result.admission,null);
  }
  for(const data of [{total_count:5,jobs:[1,2,3,4,5].map(i=>job(i,true))},
      {total_count:4,jobs:[job(1),job(2),job(3)]},
      {total_count:true,jobs:[]}, {total_count:4,jobs:[job(1),job(2),job(3),{...job(4,true),labels:['x'.repeat(65536)]}]}]) {
    rejected(await elect({...accountedOptions(),jobs:data}));
  }
});

test('setup accounting has no missing receipt API error deadline or final snapshot fallback', async () => {
  const base=accountedOptions();
  for(const options of [{jobsError:true},{jobsClock:9000},{jobsClock:4500},
      {downloadClock:3000},{pythonClock:3000}, {artifacts:[artifact(1),artifact(2)]},
      {artifacts:[artifact(1),artifact(2),artifact(3),artifact(4)]},
      {jobs:{total_count:3,jobs:[job(1),job(2),job(3)]}},
      {jobs:{total_count:4,jobs:[1,2,3,4].map(i=>job(i,true))},artifacts:[]}]) {
    rejected(await elect({...base,...options}));
  }
  const changed=structuredClone(base.jobs);changed.jobs[3].steps[0].name='Run e2e benchmark';
  rejected(await elect({...base,jobPages:[base.jobs,changed]}));
  const replaced=base.artifacts.map(a=>a.id===103?{...a,id:104}:a);
  rejected(await elect({...base,pages:[base.artifacts,replaced]}));
  const zips=new Map(validZips);zips.set(103,zip(JSON.stringify(receipt(3)).replace('"schema":1','"schema":1,"schema":1')));
  rejected(await elect({...base,zips}));
  const low=new Map([1,2,3].map(slot=>[100+slot,zip(JSON.stringify(receipt(slot,48)))]));
  rejected(await elect({...base,zips:low}));
  // No opt-in: a terminal setup shape never substitutes for a fourth receipt.
  const legacy=await elect({...base,policy:'strict_v1'});rejected(legacy);
  assert.equal(legacy.requests.filter(([kind])=>kind==='jobs').length,0);
});

test('setup policy is a closed fixed four-slot choice', () => {
  const f=fixture({slots:4,slot:2});
  try {
    for(const policy of ['',true,'setup_failure_v3']) assert.throws(()=>adapter.binding(context,{...f.env,BENCH_CAPACITY_POLICY:policy}));
    for(const slots of ['2','3']) assert.throws(()=>adapter.binding(context,{...f.env,BENCH_CAPACITY_POLICY:adapter.SETUP_FAILURE_POLICY,BENCH_CAPACITY_SLOTS:slots}));
    assert.equal(adapter.binding(context,f.env).policy,'strict_v1');
  } finally {f.close();}
});

test('single diagnostic policy admits one exact prebuilt receipt without setup fallback', async () => {
  const options = { slots: 1, slot: 1, policy: adapter.SINGLE_DIAGNOSTIC_POLICY,
    artifacts: [artifact(1)],
    zips: new Map([[101, zip(JSON.stringify({ ...receipt(1), prebuilt: prebuiltProof }))]]) };
  const result = await elect(options);
  assert.equal(result.output.selected, 'true');
  assert.equal(result.admission, null);
  assert.equal(result.requests.filter(([kind]) => kind === 'jobs').length, 0);
  assert.equal(result.requests.filter(([kind]) => kind === 'download').length, 1);

  const f = fixture(options);
  try {
    assert.equal(adapter.binding(context, f.env).policy, adapter.SINGLE_DIAGNOSTIC_POLICY);
    const trial = { ...f.env, BENCH_PROOF_GROUPING_TRIAL: 'true', BENCH_RUN_SIDE: 'comparison', BENCH_FEATURE_ENV: 'RETH_EXPERIMENTAL_PROOF_BACKLOG_GROUPING=1' };
    assert.equal(adapter.binding(context, trial).policy, adapter.SINGLE_DIAGNOSTIC_POLICY);
    for (const [field, value] of [
      ['BENCH_PROOF_GROUPING_TRIAL', 'false'], ['BENCH_RUN_SIDE', 'feature'],
      ['BENCH_FEATURE_ENV', ''], ['BENCH_FEATURE_ENV', 'RETH_EXPERIMENTAL_PROOF_BACKLOG_GROUPING=1 PRIVATE=1'],
      ['BENCH_BASELINE_ENV', 'PRIVATE=1'], ['BENCH_DURATION', '90'], ['BENCH_RUN_PAIRS', '2'],
    ]) assert.throws(() => adapter.binding(context, { ...trial, [field]: value }));

    for (const [field, value] of [
      ['BENCH_CAPACITY_SLOTS', '2'], ['BENCH_CAPACITY_SLOT', '2'],
      ['BENCH_BINARY_MODE', 'build_v1'], ['BENCH_LIFECYCLE_DETAIL', 'full'],
      ['BENCH_RUN_SIDE', 'comparison'], ['BENCH_RUN_PAIRS', '2'],
      ['BENCH_DURATION', '31'], ['BENCH_FEATURE_ENV', 'TEMPO_READ_READINESS=1'],
      ['BENCH_READ_READINESS', 'false'],
      ['BENCH_BASELINE_ENV', 'PRIVATE=1'], ['BENCH_BENCH_ENV', 'PRIVATE=1'],
      ['BENCH_LIFECYCLE_SCHEDULER', 'true'], ['BENCH_SAMPLY', 'true'],
      ['BENCH_TRACY', 'tracy'], ['BENCH_OTLP', 'true'], ['BENCH_VALSCOPE', 'true'],
      ['BENCH_METRICS', 'true'],
      ['BENCH_LIFECYCLE', 'false'], ['BENCH_NO_SLACK', 'false'],
    ]) assert.throws(() => adapter.binding(context, { ...f.env, [field]: value }));
  } finally { f.close(); }
});

test('setup metadata network await aborts under the same real deadline', async () => {
  const f=fixture(accountedOptions());let observed=false;
  f.github.rest.actions.listJobsForWorkflowRunAttempt=async args=>new Promise((resolve,reject)=>{
    args.request.signal.addEventListener('abort',()=>{observed=true;reject(new Error(secret));},{once:true});
  });
  const keepAlive=setTimeout(()=>{},1000);
  try {
    await adapter.elect({...f,now:()=>performance.now(),timeoutMs:25});
    assert.equal(observed,true);rejected({output:f.output,messages:f.messages});
    assert.ok(f.messages.every(m=>!m.includes(secret)));
    assert.equal(f.output['admission-path'],undefined);
  } finally {clearTimeout(keepAlive);f.close();}
});


test('receipt ZIP transport admits only stored or deflate codecs', async () => {
  for (const method of [0,8,12,14]) {
    const zips=new Map(validZips);zips.set(102,zip(JSON.stringify(receipt(2)),{method}));
    const result=await elect({zips});
    if ([0,8].includes(method)) assert.ok(!result.messages.some(m=>m.startsWith('FAILED:')));
    else rejected(result);
  }
});

function fiveOptions(failed = []) {
  return {slots:5,slot:5,policy:adapter.SETUP_FAILURE_POLICY,
    jobs:{total_count:5,jobs:[1,2,3,4,5].map(slot=>job(slot,failed.includes(slot)))},
    artifacts:[1,2,3,4,5].filter(slot=>!failed.includes(slot)).map(artifact)};
}

test('five-slot source-bound election selects its own winner across rotations and ties', async () => {
  for(const [free,winner] of [[[96,112,128,144,160],5],[[96,96,96,96,96],1]]) {
    const zips=new Map(free.map((value,i)=>[101+i,zip(JSON.stringify(receipt(i+1,value)))]));
    for(let rotate=0;rotate<5;rotate++) {
      const order=[1,2,3,4,5].slice(rotate).concat([1,2,3,4,5].slice(0,rotate));
      for(const slot of [1,2,3,4,5]) {
        const result=await elect({...fiveOptions(),slot,zips,artifacts:order.map(artifact),
          jobs:{total_count:5,jobs:order.toReversed().map(i=>job(i))}});
        assert.ok(!result.messages.some(m=>m.startsWith('FAILED:')));
        assert.equal(result.output.selected,String(slot===winner));
        if(slot===winner) {
          assert.equal(result.admission.slots,5);assert.equal(result.admission.selected_slot,winner);
          assert.deepEqual(result.admission.capacity_receipts.map(r=>r.slot),[1,2,3,4,5]);
        } else assert.equal(result.admission,null);
      }
    }
  }
});

test('five-slot setup accounting excludes only proven slots and does not assume distinct runners', async () => {
  for(const failed of [[1],[2],[3],[4],[5],[1,2,3,4]]) {
    const options=fiveOptions(failed);options.slot=failed.includes(2)?(failed.includes(3)?5:3):2;
    const result=await elect(options);assert.equal(result.output.selected,'true');
    assert.deepEqual(result.admission.setup_failed_slots,failed);assert.equal(result.admission.slots,5);
  }
  const options=fiveOptions([1,2,3,4]);
  // API job identities remain unique; native runner registration reuse is not
  // evidence of distinct hosts and must neither be exported nor force routing.
  options.jobs.jobs.forEach(j=>{j.runner_id=4321;j.runner_name=secret;});
  const result=await elect(options);assert.equal(result.output.selected,'true');
  assert.ok(!JSON.stringify(result.admission).includes('4321'));
});

test('fifth-slot missing conflicting stale oversized and delayed evidence remains bounded', async () => {
  const base=fiveOptions([4]);base.slot=2;
  for(const override of [
    {jobs:{total_count:4,jobs:[1,2,3,4].map(i=>job(i,i===4))}},
    {jobs:{total_count:6,jobs:[1,2,3,4,5,6].map(i=>job(i,i===4))}},
    {artifacts:[artifact(1),artifact(2),artifact(3)]},
    {artifacts:[1,2,3,4,5].map(artifact)},
    {artifacts:[artifact(1),artifact(2),artifact(3),artifact(6)]},
    {jobsClock:9000},{downloadClock:2250},{pythonClock:2250},
    {artifacts:base.artifacts.map(a=>a.id===105?{...a,size_in_bytes:65537}:a)},
  ]) rejected(await elect({...base,...override}));
  for(const field of ['run_id','run_attempt','head_sha','name','id']) {
    const options=fiveOptions([5]);
    options.jobs.jobs[4][field]=field==='head_sha'?'2'.repeat(40):field==='name'?'bench-e2e (reserved slot 4)':field==='id'?501:999;
    rejected(await elect(options));
  }
  const mutated=structuredClone(base.jobs);mutated.jobs[3].steps.push({...mutated.jobs[3].steps[0],number:2,name:'Probe reserved runner capacity',conclusion:'skipped'});
  rejected(await elect({...base,jobPages:[base.jobs,mutated]}));
  const low=new Map([1,2,3,5].map(slot=>[100+slot,zip(JSON.stringify(receipt(slot,48)))]));
  rejected(await elect({...base,zips:low}));
  rejected(await elect(fiveOptions([1,2,3,4,5])));
  const delayed=await elect({...base,pages:[base.artifacts.slice(0,3),base.artifacts]});
  assert.equal(delayed.elapsed,3000);assert.equal(delayed.output.selected,'true');
});

test('fifth-slot probe is closed, count is explicit, and six slots are forbidden', async () => {
  const f=fixture({slots:5,slot:5,policy:adapter.SETUP_FAILURE_POLICY});
  try {
    for(const slots of ['4','6','05','5.0','']) assert.throws(()=>adapter.binding(context,{...f.env,BENCH_CAPACITY_SLOTS:slots}));
    for(const slot of ['6','05','5.0','']) assert.throws(()=>adapter.binding(context,{...f.env,BENCH_CAPACITY_SLOT:slot}));
    await adapter.probe({...f,execute:()=>({status:0,stdout:JSON.stringify(capacity()),stderr:''})});
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(f.env.GITHUB_WORKSPACE,f.output['artifact-path']),'utf8')),receipt(5,96));
  } finally {f.close();}
});

test('prebuilt budget is bound to immutable plan bytes and Python contract', async () => {
  const {createHash}=require('node:crypto');
  const result=spawnSync('python3',['-c',`import sys,json;sys.path.insert(0,'contrib/bench/lifecycle');from test_prebuilt import fixture;print(json.dumps(fixture()[0],separators=(',',':')),end='')`],{cwd:root,encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  const plan=result.stdout,script=fs.readFileSync(path.join(root,'contrib/bench/lifecycle/prebuilt.py'),'utf8');
  const hash=createHash('sha256').update(plan).digest('hex');
  const env={PATH:process.env.PATH,BENCH_BINARY_MODE:'prebuilt_v1',BENCH_CAPACITY_SLOTS:'5',BENCH_CAPACITY_POLICY:adapter.SETUP_FAILURE_POLICY,BENCH_PREBUILT_PLAN_SHA256:hash};
  const requests=[];
  const github={rest:{repos:{getContent:async args=>{
    requests.push(args);assert.equal(args.ref,SHA);
    const raw=args.path.endsWith('prebuilt-plan.json')?plan:script;
    return {data:{type:'file',encoding:'base64',size:Buffer.byteLength(raw),content:Buffer.from(raw).toString('base64')}};
  }}}};
  const config=await adapter.prebuilt(github,context,env,spawnSync);
  assert.equal(config.proof.plan_sha256,hash);
  assert.ok(config.proof.required_bytes>49152*1048576 && config.proof.required_bytes<65536*1048576);
  assert.equal(requests.length,2);
  const rows=[1,2,3,4,5].map(slot=>({...receipt(slot,50),prebuilt:config.proof}));
  const input=JSON.stringify({schema:2,receipts:rows,setup_failed_slots:[],prebuilt_plan:plan});
  const args=['-I','-c',adapter.withPrebuilt(election,config),'--workflow-sha',SHA,'--run-id','12345','--run-attempt','3','--slots','5','--policy',adapter.SETUP_FAILURE_POLICY,'--binary-mode','prebuilt_v1'];
  const voted=spawnSync('python3',args,{input,encoding:'utf8'});assert.equal(voted.status,0,voted.stderr);
  assert.equal(JSON.parse(voted.stdout).selected_slot,1);
  await assert.rejects(adapter.prebuilt(github,context,{...env,BENCH_PREBUILT_PLAN_SHA256:'0'.repeat(64)},spawnSync));
  await assert.rejects(adapter.prebuilt(github,context,{...env,BENCH_BINARY_MODE:'build_v1'},spawnSync));
  assert.equal(await adapter.prebuilt(github,context,{PATH:process.env.PATH},spawnSync),null);
});
