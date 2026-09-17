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
 info=zipfile.ZipInfo(value.get('name','receipt.json'));info.compress_type=zipfile.ZIP_DEFLATED
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
const validZips = new Map([1, 2, 3].map(slot => [100 + slot, zip(JSON.stringify(receipt(slot)))]));

function fixture(options = {}) {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'capacity-transport-'));
  const env = { PATH: process.env.PATH, GITHUB_WORKSPACE: workspace, RUNNER_TEMP: workspace,
    GITHUB_RUN_ATTEMPT: '3', BENCH_CAPACITY_SLOT: String(options.slot || 1), BENCH_CAPACITY_SLOTS: String(options.slots || 2),
    BENCH_LIFECYCLE: 'true', BENCH_NO_SLACK: 'true', GITHUB_TOKEN: secret };
  const messages = []; const output = {}; const requests = []; let clock = 0; let lists = 0;
  const core = { setOutput: (k, v) => { output[k] = v; }, info: m => messages.push(String(m)),
    setFailed: m => messages.push(`FAILED:${m}`) };
  const github = { rest: { repos: { getContent: async args => {
    requests.push(['source', args]);
    assert.equal(args.ref, SHA); assert.deepEqual({ owner: args.owner, repo: args.repo }, context.repo);
    assert.ok(['contrib/bench/lifecycle/capacity_election.py', 'contrib/bench/lifecycle/capacity_preflight.py'].includes(args.path));
    assert.ok(args.request.signal instanceof AbortSignal);
    assert.equal(args.request.signal.aborted, false);
    assert.equal(args.request.log.warn('private sentinel'), undefined);
    if (options.sourceError) throw new Error(secret);
    if (options.sourceData) return { data: options.sourceData };
    if (options.sourceClock) clock += options.sourceClock;
    const text = args.path.endsWith('capacity_election.py') ? election : probeSource;
    return { data: { type: 'file', encoding: 'base64', size: Buffer.byteLength(text), content: Buffer.from(text).toString('base64') } };
  } }, actions: { listWorkflowRunArtifacts: async args => {
    requests.push(['list', args]); assert.equal(args.run_id, context.runId); assert.equal(args.per_page, 100);
    assert.ok(args.request.signal instanceof AbortSignal);
    assert.equal(args.request.signal.aborted, false);
    assert.equal(args.request.log.warn('private sentinel'), undefined);
    if (options.listError) throw new Error(secret);
    if (options.listClock) clock += options.listClock;
    const rows = options.pages ? options.pages[Math.min(lists++, options.pages.length - 1)] : options.artifacts || [artifact(1), artifact(2)];
    return { data: options.listData || { total_count: rows.length, artifacts: rows } };
  }, downloadArtifact: async args => {
    requests.push(['download', args]); assert.equal(args.archive_format, 'zip'); assert.ok([101, 102, 103].includes(args.artifact_id));
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
    assert.ok([election, adapter.EXTRACT_RECEIPT].includes(args[2]));
    assert.equal(opts.env.GITHUB_TOKEN, undefined); assert.ok(opts.timeout > 0 && opts.timeout <= 60000);
    if (args[2] === election) assert.deepEqual(args.slice(3), ['--workflow-sha', SHA, '--run-id', '12345', '--run-attempt', '3', '--slots', String(options.slots || 2)]);
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
    return { output: f.output, messages: f.messages, requests: f.requests, elapsed: f.now() };
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
    for (const slots of [undefined,'','1','4','03','3.0']) {
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
