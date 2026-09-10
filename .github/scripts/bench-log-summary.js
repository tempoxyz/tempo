#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { stripVTControlCharacters } = require('node:util');

// Node file logs use tracing's JSON formatter. Support terminal output as well
// for txgen, profiling tools, and results collected before JSON logging.
function parseLine(raw) {
  const line = stripVTControlCharacters(raw).trim();
  if (line.startsWith('{')) {
    try {
      const entry = JSON.parse(line);
      if (!entry.level) return null;
      const level = entry.level.toUpperCase();
      if (level === 'INFO' || level === 'DEBUG') return null;
      return String(entry.fields?.message ?? entry.message ?? '(no message)');
    } catch {
      return null;
    }
  }
  const match = line.match(/^(?:\d{4}-\d\d-\d\dT\S+\s+)?(TRACE|DEBUG|INFO|WARN|ERROR)\s+(.*)$/);
  if (!match || match[1] === 'INFO' || match[1] === 'DEBUG') return null;
  // The terminal formatter puts the target before the message and annotated
  // fields after it. Keep formatted values in the message itself unchanged.
  return match[2]
    .replace(/^[\w]+(?:::[\w]+)*:\s+/, '')
    .split(/(?:^|\s)[\w.]+=/, 1)[0].trim() || '(no message)';
}

function filesUnder(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const filename = path.join(dir, entry.name);
    if (entry.isDirectory()) return filesUnder(filename);
    return entry.isFile() ? [filename] : [];
  }).sort();
}

async function scanLogs(resultsDir, mode) {
  if (!['e2e', 'replay'].includes(mode)) throw new Error(`Unknown benchmark mode: ${mode}`);
  const labels = fs.readFileSync(path.join(resultsDir, 'run-order.txt'), 'utf8')
    .split(/\r?\n/).filter(Boolean);
  if (labels.length === 0) throw new Error('No benchmark runs found in run-order.txt');
  const counts = new Map();
  const runs = [];
  for (const label of labels) {
    if (!/^(baseline|feature)-\d+$/.test(label)) throw new Error(`Invalid run label: ${label}`);
    const side = label.split('-')[0];
    const nodeDirs = mode === 'e2e'
      ? ['a', 'b'].map(role => path.join(resultsDir, `logs-${label}-${role}`))
      : [path.join(resultsDir, label, 'tempo-logs')];
    const missing = nodeDirs.filter(dir => filesUnder(dir).length === 0);
    const files = nodeDirs.flatMap(filesUnder);
    // Console output duplicates node file logs. Only fall back to it when the
    // replay node produced no file logs (e.g. file logging was disabled).
    if (mode === 'replay' && files.length === 0) {
      const consoleLog = path.join(resultsDir, label, 'node.log');
      if (fs.existsSync(consoleLog)) files.push(consoleLog);
    }
    files.push(...filesUnder(mode === 'e2e'
      ? path.join(resultsDir, `txgen-logs-${label}`)
      : path.join(resultsDir, label, 'txgen-logs')));
    const captureLog = path.join(resultsDir, `tracy-capture-${label}.log`);
    if (mode === 'e2e' && fs.existsSync(captureLog)) files.push(captureLog);
    const run = { label, side, total: 0, files: files.map(f => path.relative(resultsDir, f)),
      missing_node_logs: missing.map(f => path.relative(resultsDir, f)) };
    for (const filename of files) {
      const input = fs.createReadStream(filename);
      const lines = readline.createInterface({ input, crlfDelay: Infinity });
      // Forward stream errors to the iterator instead of leaving an unhandled
      // error event or silently reporting an incomplete scan as zero.
      input.on('error', () => lines.close());
      for await (const line of lines) {
        const message = parseLine(line);
        if (message === null) continue;
        const row = counts.get(message) || { message, baseline: 0, feature: 0, per_run: {} };
        row[side] += 1;
        row.per_run[label] = (row.per_run[label] || 0) + 1;
        counts.set(message, row);
        run.total += 1;
      }
      if (input.errored) throw input.errored;
    }
    runs.push(run);
  }
  return { runs, messages: [...counts.values()].sort((a, b) =>
    (b.baseline + b.feature) - (a.baseline + a.feature) || a.message.localeCompare(b.message)) };
}

function escapeCell(value) {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\|/g, '&#124;').replace(/`/g, '&#96;').replace(/[\r\n]+/g, ' ');
}

function buildMarkdown(report) {
  const total = side => report.runs.some(r => r.side === side)
    ? report.runs.filter(r => r.side === side).reduce((sum, r) => sum + r.total, 0) : '—';
  const lines = ['', '## Non-INFO/DEBUG logs', '',
    'Counts include all collected run logs, including setup, warmup, and shutdown. Annotated key/value fields are excluded; repeated messages are counted, not deduplicated. Unlevelled output is ignored.', '',
    '| Run type | Total lines |', '|----------|------------:|',
    `| Baseline | ${total('baseline')} |`, `| Feature | ${total('feature')} |`, ''];
  if (report.runs.some(r => r.missing_node_logs.length)) {
    lines.push('⚠️ Some node file logs are missing; counts may be incomplete. See `log-summary.json` for source coverage.', '');
  }
  if (report.messages.length) {
    lines.push('<details><summary>Counts by message</summary>', '',
      '| Message | Baseline | Feature |', '|---------|---------:|--------:|');
    // Leave room for metrics and observability links within GitHub's comment
    // limit. The artifact always retains the complete breakdown, including runs.
    let bytes = 0;
    for (const [index, row] of report.messages.entries()) {
      const line = `| ${escapeCell(row.message)} | ${total('baseline') === '—' ? '—' : row.baseline} | ${total('feature') === '—' ? '—' : row.feature} |`;
      bytes += Buffer.byteLength(line);
      if (bytes > 24000) {
        lines.push('', `Showing ${index} of ${report.messages.length} messages; the complete breakdown is in \`log-summary.json\` in the results artifact.`);
        break;
      }
      lines.push(line);
    }
    lines.push('', '</details>');
  } else {
    lines.push('No non-INFO/DEBUG messages found in the collected logs.');
  }
  return `${lines.join('\n')}\n`;
}

async function main(resultsDir, mode, markdownName) {
  const report = await scanLogs(resultsDir, mode);
  fs.writeFileSync(path.join(resultsDir, 'log-summary.json'), `${JSON.stringify(report, null, 2)}\n`);
  fs.appendFileSync(path.join(resultsDir, markdownName), buildMarkdown(report));
}

if (require.main === module) {
  const [resultsDir, mode, markdownName] = process.argv.slice(2);
  if (!resultsDir || !mode || !markdownName) {
    console.error('usage: bench-log-summary.js <results-dir> <e2e|replay> <markdown-file>');
    process.exit(2);
  }
  main(resultsDir, mode, markdownName).catch(error => { console.error(error); process.exitCode = 1; });
}

module.exports = { parseLine, scanLogs, buildMarkdown, main };
