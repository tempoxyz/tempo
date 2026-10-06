const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

test('bench presets confirm setup and use gas weighting without opt-in', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-gas-weighting-'));
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', data => { body += data; });
    request.on('end', () => {
      const result = JSON.parse(body).method === 'txpool_status' ? { pending: '0x0' } : '0x539';
      response.setHeader('Content-Type', 'application/json');
      response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
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
    if (report) fs.writeFileSync(report.slice(5), JSON.stringify({ failed: 0 }));
  });
}
`, { mode: 0o755 });
    const tempo = path.join(directory, 'txgen-tempo');
    const bench = path.join(directory, 'txgen-bench');
    fs.symlinkSync(mock, tempo);
    fs.symlinkSync(mock, bench);
    for (const [preset, extraArgs] of [['tip20', ''], ['mix', ''], ['dex', '--gas-weighted-mix'], ['mpp', '']]) {
      const callsPath = path.join(directory, `${preset}.calls`);
      const report = path.join(directory, `${preset}.json`);
      const spec = path.join(__dirname, 'presets', `${preset}.yml`);
      const rpc = `http://127.0.0.1:${server.address().port}`;
      const command = `source ${JSON.stringify(path.join(__dirname, 'helpers.nu'))};
        let result = (txgen-run-preset-pipeline
          --txgen-tempo-bin ${JSON.stringify(tempo)} --txgen-bench-bin ${JSON.stringify(bench)}
          --preset-path ${JSON.stringify(spec)} --generate-rpc-url ${JSON.stringify(rpc)}
          --submit-rpc-url ${JSON.stringify(rpc)} --metrics-url [] --report-path ${JSON.stringify(report)}
          --tps 1 --duration 1 --accounts 2 --max-concurrent-requests 1
          --bench-args ${JSON.stringify(extraArgs)} --skip-funding);
        if not $result.ok { error make { msg: 'pipeline failed' } }`;
      const output = await new Promise((resolve, reject) => {
        const child = spawn('nu', ['-c', command], {
          env: { ...process.env, BENCH_TEST_CALLS: callsPath },
        });
        let text = '';
        child.stdout.on('data', data => { text += data; });
        child.stderr.on('data', data => { text += data; });
        child.on('error', reject);
        child.on('close', code => resolve({ code, text }));
      });
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
