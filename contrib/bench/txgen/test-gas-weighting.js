const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

function writeMocks(directory, sent = 0) {
  const mock = path.join(directory, 'mock.js');
  fs.writeFileSync(mock, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
const kind = path.basename(process.argv[1]);
fs.appendFileSync(process.env.BENCH_TEST_CALLS, JSON.stringify({ kind, args }) + '\\n');
if (kind === 'txgen-tempo') {
  const state = args.indexOf('--setup-state-out');
  if (state !== -1) fs.writeFileSync(args[state + 1], '{}');
  if (args.includes('--setup-state-in') && !fs.existsSync(args[args.indexOf('--setup-state-in') + 1])) process.exit(1);
  process.stdout.write('{}\\n');
} else {
  process.stdin.resume();
  process.stdin.on('end', () => {
    const report = args.find(arg => arg.startsWith('json:'));
    if (report) fs.writeFileSync(report.slice(5), JSON.stringify({ failed: 0, sent: ${sent} }));
  });
}
`, { mode: 0o755 });
  const tempo = path.join(directory, 'txgen-tempo');
  const bench = path.join(directory, 'txgen-bench');
  fs.symlinkSync(mock, tempo);
  fs.symlinkSync(mock, bench);
  return { tempo, bench };
}

function runPipeline({ tempo, bench, callsPath, report, preset, rpc, extraArgs, pipelineArgs }) {
  const spec = path.join(__dirname, 'presets', `${preset}.yml`);
  const command = `source ${JSON.stringify(path.join(__dirname, 'helpers.nu'))};
    let result = (txgen-run-preset-pipeline
      --txgen-tempo-bin ${JSON.stringify(tempo)} --txgen-bench-bin ${JSON.stringify(bench)}
      --preset-path ${JSON.stringify(spec)} --generate-rpc-url ${JSON.stringify(rpc)}
      --submit-rpc-url ${JSON.stringify(rpc)} --metrics-url [] --report-path ${JSON.stringify(report)}
      --tps 1 --duration 1 --accounts 2 --max-concurrent-requests 1
      --bench-args ${JSON.stringify(extraArgs)} --skip-funding ${pipelineArgs});
    if not $result.ok { error make { msg: 'pipeline failed' } }`;
  return new Promise((resolve, reject) => {
    const child = spawn('nu', ['-c', command], {
      env: { ...process.env, BENCH_TEST_CALLS: callsPath },
    });
    let text = '';
    child.stdout.on('data', data => { text += data; });
    child.stderr.on('data', data => { text += data; });
    child.on('error', reject);
    child.on('close', code => resolve({ code, text }));
  });
}

test('bench presets confirm setup and use gas weighting without opt-in', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-gas-weighting-'));
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', data => { body += data; });
    request.on('end', () => {
      // A fresh chain-1337 fixture: public-mix presets check the deployer nonce and policy counter.
      const results = { txpool_status: { pending: '0x0' }, eth_getTransactionCount: '0x0', eth_call: '0x2' };
      const result = results[JSON.parse(body).method] ?? '0x539';
      response.setHeader('Content-Type', 'application/json');
      response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const { tempo, bench } = writeMocks(directory);
    for (const [preset, extraArgs, pipelineArgs = ''] of [
      ['tip20', ''], ['mix', ''], ['dex', '--gas-weighted-mix'], ['mpp', ''],
      ['batch-payout', '', '--bloat-mib 1024'], ['access-key-mix', ''], ['agentic', ''],
    ]) {
      const callsPath = path.join(directory, `${preset}.calls`);
      const report = path.join(directory, `${preset}.json`);
      const rpc = `http://127.0.0.1:${server.address().port}`;
      const output = await runPipeline({ tempo, bench, callsPath, report, preset, rpc, extraArgs, pipelineArgs });
      assert.equal(output.code, 0, output.text);
      const calls = fs.readFileSync(callsPath, 'utf8').trim().split('\n').map(JSON.parse);
      const generations = calls.filter(call => call.kind === 'txgen-tempo' && call.args[0] === 'generate').map(call => call.args);
      assert.equal(generations.length, 2, preset);
      assert.equal(generations[0][generations[0].indexOf('-n') + 1], '0', preset);
      assert.equal(generations[0][generations[0].indexOf('--setup-state-out') + 1], `${report}.setup.json`, preset);
      assert.equal(generations[0].includes('--gas-weighted-mix'), false, preset);
      assert.equal(generations[1].filter(arg => arg === '--gas-weighted-mix').length, 1, preset);
      assert.equal(generations[1][generations[1].indexOf('--setup-state-in') + 1], `${report}.setup.json`, preset);
      const senders = calls.filter(call => call.kind === 'txgen-bench').map(call => call.args);
      assert.equal(senders.length, 2, preset);
      assert.equal(senders[1].includes('--skip-setup'), true, preset);
      assert.equal(senders[1].includes('workload_mix_weighting=gas'), true, preset);
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('zone-to-zone runs for the duration and tallies callback receipts', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-zone-to-zone-'));
  const marker = '0x45310f61ef78f3fcb9ab97ea27304d615534bc583c8ef2b31ecabd38fac9a4b7';
  const processed = '0x65042ea6dad60c26f055e80ec401b3437c854ed586a0704d305bb4e9ea4518cf';
  let block = 0x539;
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', data => { body += data; });
    request.on('end', () => {
      const { method } = JSON.parse(body);
      // One block holds a delivered transfer, a bounced one and a plain withdrawal.
      const receipts = [
        { type: '0x76', status: '0x1', gasUsed: '0x5a550', logs: [{ topics: [processed], data: '0x01' }, { topics: [marker], data: '0x' }] },
        { type: '0x76', status: '0x1', gasUsed: '0x186a0', logs: [{ topics: [processed], data: '0x00' }, { topics: [marker], data: '0x' }] },
        { type: '0x76', status: '0x1', gasUsed: '0x30d40', logs: [{ topics: [processed], data: '0x01' }] },
      ];
      const results = {
        txpool_status: { pending: '0x0' }, eth_getTransactionCount: '0x0',
        eth_blockNumber: '0x' + (block++).toString(16), eth_getBlockReceipts: receipts,
      };
      response.setHeader('Content-Type', 'application/json');
      response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: results[method] ?? '0x539' }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const { tempo, bench } = writeMocks(directory, 3);
    const callsPath = path.join(directory, 'zone-to-zone.calls');
    const report = path.join(directory, 'zone-to-zone.json');
    const output = await runPipeline({
      tempo, bench, callsPath, report, preset: 'zone-to-zone',
      rpc: `http://127.0.0.1:${server.address().port}`, extraArgs: '', pipelineArgs: '',
    });
    assert.equal(output.code, 0, output.text);
    const calls = fs.readFileSync(callsPath, 'utf8').trim().split('\n').map(JSON.parse);
    const generations = calls.filter(call => call.kind === 'txgen-tempo' && call.args[0] === 'generate').map(call => call.args);
    assert.equal(generations.length, 2);
    assert.equal(generations[1].includes('--duration'), true);
    assert.equal(generations[1].includes('--gas-weighted-mix'), true);
    const sender = calls.filter(call => call.kind === 'txgen-bench').map(call => call.args)[1];
    for (const metadata of ['zone_count=2', 'zone_to_zone_access=closed', 'zone_to_zone_share=100']) {
      assert.equal(sender.includes(metadata), true, metadata);
    }
    const summary = JSON.parse(fs.readFileSync(`${report}.zone-to-zone.json`, 'utf8'));
    assert.deepEqual(
      { transfers: summary.transfers, delivered: summary.delivered, bounced: summary.bounced, plain: summary.plain_withdrawals },
      { transfers: 2, delivered: 1, bounced: 1, plain: 1 },
    );
    assert.equal(summary.gas_per_transfer, 235000);
    assert.match(output.text, /zone-to-zone: 2 transfers, 1 delivered, 1 bounced/);
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
