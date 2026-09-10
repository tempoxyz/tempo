const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { parseLine, scanLogs, buildMarkdown, main } = require('./bench-log-summary');

function fixture(t, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bench-logs-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) {
    const filename = path.join(dir, name);
    fs.mkdirSync(path.dirname(filename), { recursive: true });
    fs.writeFileSync(filename, content);
  }
  return dir;
}

const json = (level, message, fields = {}) =>
  JSON.stringify({ level, fields: { message, ...fields }, target: 'tempo::node' }) + '\n';

test('JSON excludes annotations but preserves key=value inside the actual message', () => {
  assert.equal(parseLine(json('WARN', 'failed with status=503', { peer: 42, error: 'many words' })),
    'failed with status=503');
  assert.equal(parseLine(json('TRACE', 'trace event')), 'trace event');
  for (const level of ['INFO', 'DEBUG']) assert.equal(parseLine(json(level, 'ignored')), null);
  assert.equal(parseLine('{"level":"ERROR","fields":{"error":"boom"}}'), '(no message)');
});

test('terminal output strips ANSI, target and structured fields', () => {
  assert.equal(parseLine('2026-09-10T01:02:03.123Z \x1b[33m WARN\x1b[0m tempo::node: Peer failed peer=1 error="connection refused"'), 'Peer failed');
  assert.equal(parseLine('ERROR Failed to submit batch=2 error.sources=[many words]'), 'Failed to submit');
  assert.equal(parseLine('WARN error="connection refused"'), '(no message)');
  assert.equal(parseLine('INFO normal message with WARN in it'), null);
  assert.equal(parseLine('DEBUG ignored'), null);
  assert.equal(parseLine('compiling crate; WARN is not a log level here'), null);
});

test('E2E scans every node and rotated file plus sender/setup/capture logs across runs', async t => {
  const dir = fixture(t, {
    'run-order.txt': 'feature-1\nbaseline-1\nbaseline-2\n',
    'logs-feature-1-a/tempo.log': json('ERROR', 'Peer failed', { peer: 1 }),
    'logs-feature-1-b/tempo.log': json('INFO', 'ignored'),
    'logs-baseline-1-a/tempo.log.1': json('WARN', 'Peer failed', { peer: 2 }),
    'logs-baseline-1-a/tempo.log': json('WARN', 'Peer failed', { peer: 3 }),
    'logs-baseline-1-b/tempo.log': json('DEBUG', 'ignored'),
    'logs-baseline-2-a/tempo.log': json('TRACE', 'Trace event'),
    'logs-baseline-2-b/tempo.log': json('WARN', 'Peer failed', { peer: 4 }),
    'txgen-logs-feature-1/setup-stderr.log': 'WARN Setup retry attempt=1\n',
    'txgen-logs-feature-1/sender-stderr.log': 'ERROR Submit failed batch=1\nERROR Submit failed batch=2\n',
    'tracy-capture-feature-1.log': 'WARN Capture warning\n',
    'logs-feature-99-a/tempo.log': json('ERROR', 'stale run'),
    'summary.md': '# Existing metrics\n',
  });
  await main(dir, 'e2e', 'summary.md');
  const report = JSON.parse(fs.readFileSync(path.join(dir, 'log-summary.json')));
  assert.deepEqual(report.runs.map(r => r.total), [5, 2, 2]);
  assert.deepEqual(report.messages.find(r => r.message === 'Peer failed'), {
    message: 'Peer failed', baseline: 3, feature: 1,
    per_run: { 'feature-1': 1, 'baseline-1': 2, 'baseline-2': 1 },
  });
  const markdown = fs.readFileSync(path.join(dir, 'summary.md'), 'utf8');
  assert.match(markdown, /^# Existing metrics/);
  assert.match(markdown, /\| Baseline \| 4 \|/);
  assert.match(markdown, /\| Feature \| 5 \|/);
  assert.match(markdown, /\| Peer failed \| 3 \| 1 \|/);
  assert.doesNotMatch(markdown, /peer=|stale run|incomplete/);
});

test('replay avoids duplicate node console logs and includes warmup and sender output', async t => {
  const dir = fixture(t, {
    'run-order.txt': 'baseline-1\nfeature-1',
    'baseline-1/tempo-logs/tempo.log': json('WARN', 'Repeated'),
    'baseline-1/node.log': 'WARN Repeated\n',
    'baseline-1/txgen-logs/warmup.log': 'WARN Repeated\n',
    'feature-1/tempo-logs/tempo.log': json('INFO', 'normal'),
    'feature-1/txgen-logs/sender.log': 'ERROR Failed\n',
    'comment.md': '# Replay metrics\n',
  });
  await main(dir, 'replay', 'comment.md');
  const markdown = fs.readFileSync(path.join(dir, 'comment.md'), 'utf8');
  assert.match(markdown, /\| Repeated \| 2 \| 0 \|/);
  assert.match(markdown, /\| Failed \| 0 \| 1 \|/);
  assert.match(markdown, /^# Replay metrics/);
});

test('missing file logs use replay console fallback and are visibly marked incomplete', async t => {
  const dir = fixture(t, { 'run-order.txt': 'feature-1\n', 'feature-1/node.log': 'ERROR Failed\n' });
  const report = await scanLogs(dir, 'replay');
  const markdown = buildMarkdown(report);
  assert.match(markdown, /incomplete/);
  assert.match(markdown, /\| Failed \| — \| 1 \|/);
});

test('zero counts, safe Markdown and bounded comment size', () => {
  const report = { runs: [{ side: 'feature', total: 0, missing_node_logs: [] }], messages: [] };
  assert.match(buildMarkdown(report), /\| Feature \| 0 \|/);
  assert.match(buildMarkdown(report), /No non-INFO\/DEBUG messages/);
  report.messages = [{ message: '<tag>|`code`\nnext', baseline: 0, feature: 1 }];
  assert.match(buildMarkdown(report), /&lt;tag&gt;&#124;&#96;code&#96; next/);
  report.messages = Array.from({ length: 1000 }, (_, i) => ({
    message: `Message ${i} ${'x'.repeat(100)}`, baseline: 0, feature: 1,
  }));
  const markdown = buildMarkdown(report);
  assert.ok(Buffer.byteLength(markdown) < 26000);
  assert.match(markdown, /Showing \d+ of 1000 messages/);
});

test('invalid run labels cannot read outside results', async t => {
  const dir = fixture(t, { 'run-order.txt': '../baseline-1' });
  await assert.rejects(scanLogs(dir, 'e2e'), /Invalid run label/);
});
