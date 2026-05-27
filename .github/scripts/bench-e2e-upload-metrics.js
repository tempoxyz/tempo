#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const zlib = require('zlib');
const { spawn } = require('child_process');
const { performance } = require('perf_hooks');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

const CLICKHOUSE_CONFIG_KEYS = new Set(['tps', 'max_concurrent', 'chain_id', 'scrape_interval_ms']);
const CLICKHOUSE_REQUIRED_METADATA = ['scenario', 'platform', 'git-sha', 'git-ref'];

function log(message, fields = {}) {
  const details = Object.entries(fields)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${key}=${formatLogValue(value)}`)
    .join(' ');
  const suffix = details ? ` ${details}` : '';
  console.log(`[metrics] ${new Date().toISOString()} ${message}${suffix}`);
}

function logError(message, fields = {}) {
  const details = Object.entries(fields)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${key}=${formatLogValue(value)}`)
    .join(' ');
  const suffix = details ? ` ${details}` : '';
  console.error(`[metrics] ${new Date().toISOString()} ${message}${suffix}`);
}

function formatLogValue(value) {
  return String(value).replace(/\s+/g, ' ');
}

function elapsedMs(startedAt) {
  return Math.round(performance.now() - startedAt);
}

function parseArgs(argv) {
  const args = {
    resultsDir: '',
    victoriametricsUrl: '',
    clickhouseUrl: '',
    clickhouseRun: 'feature-1',
  };

  const rest = [...argv];
  args.resultsDir = rest.shift() || '';
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    if (arg === '--victoriametrics-url') {
      args.victoriametricsUrl = rest[++i] || '';
    } else if (arg === '--clickhouse-url') {
      args.clickhouseUrl = rest[++i] || '';
    } else if (arg === '--clickhouse-run') {
      args.clickhouseRun = rest[++i] ?? '';
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }

  if (!args.resultsDir) {
    throw new Error('usage: bench-e2e-upload-metrics.js <results-dir> [--victoriametrics-url URL] [--clickhouse-url URL] [--clickhouse-run RUN]');
  }
  return args;
}

function readRunLabels(resultsDir) {
  const runOrderPath = path.join(resultsDir, 'run-order.txt');
  if (fs.existsSync(runOrderPath)) {
    return fs.readFileSync(runOrderPath, 'utf8')
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean)
      .filter(label => fs.existsSync(path.join(resultsDir, `report-${label}.json`)));
  }

  return fs.readdirSync(resultsDir)
    .map(name => /^report-(.+)\.json$/.exec(name)?.[1])
    .filter(Boolean)
    .sort();
}

function loadReport(resultsDir, label) {
  const reportPath = path.join(resultsDir, `report-${label}.json`);
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  return { reportPath, report };
}

function samplesPathsForReport(reportPath) {
  const parsed = path.parse(reportPath);
  const base = path.join(parsed.dir, `${parsed.name}.samples.ndjson`);
  return {
    raw: base,
    gz: `${base}.gz`,
  };
}

async function* iterSamples(reportPath, report) {
  const samplesPaths = samplesPathsForReport(reportPath);
  let input = null;

  if (fs.existsSync(samplesPaths.gz)) {
    input = fs.createReadStream(samplesPaths.gz).pipe(zlib.createGunzip());
  } else if (fs.existsSync(samplesPaths.raw)) {
    input = fs.createReadStream(samplesPaths.raw);
  }

  if (input) {
    const rl = readline.createInterface({ input, crlfDelay: Infinity });
    for await (const line of rl) {
      const trimmed = line.trim();
      if (trimmed) {
        yield JSON.parse(trimmed);
      }
    }
    return;
  }

  if (Array.isArray(report.samples)) {
    for (const sample of report.samples) {
      yield sample;
    }
  }
}

function envPositiveInt(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function stableJson(value) {
  if (!value || typeof value !== 'object') return '{}';
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = String(value[key]);
  }
  return JSON.stringify(out);
}

function trimUrl(url) {
  return url.replace(/\/+$/, '');
}

function withQueryParam(url, name, value) {
  if (!value) return url;
  const parsed = new URL(url);
  parsed.searchParams.set(name, value);
  return parsed.toString();
}

async function post(url, body, headers, timeoutSecs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutSecs * 1000);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body,
      signal: controller.signal,
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${text || '<empty body>'}`);
    }
    return text;
  } finally {
    clearTimeout(timeout);
  }
}

function clickHouseConfig(clickhouseUrl) {
  return {
    url: trimUrl(clickhouseUrl),
    database: process.env.CLICKHOUSE_DATABASE || 'default',
    user: process.env.CLICKHOUSE_USER || '',
    password: process.env.CLICKHOUSE_PASSWORD || '',
    sampleBatchSize: envPositiveInt('CLICKHOUSE_SAMPLE_BATCH_SIZE', 50_000),
  };
}

async function insertClickHouseRows(config, table, rows, task) {
  if (rows.length === 0) return;

  const query = `INSERT INTO ${config.database}.${table} FORMAT JSONEachRow`;
  const url = `${config.url}/?query=${encodeURIComponent(query)}`;
  const headers = { 'Content-Type': 'application/json' };
  if (config.user) headers['X-ClickHouse-User'] = config.user;
  if (config.password) headers['X-ClickHouse-Key'] = config.password;

  const body = `${rows.map(row => JSON.stringify(row)).join('\n')}\n`;
  const startedAt = performance.now();
  log('clickhouse insert start', { task, table, rows: rows.length });
  await post(url, body, headers, 60);
  log('clickhouse insert complete', {
    task,
    table,
    rows: rows.length,
    duration_ms: elapsedMs(startedAt),
  });
}

function splitClickHouseMetadata(metadata) {
  const config = {};
  const extra = {};
  for (const [key, value] of Object.entries(metadata || {})) {
    const stringValue = String(value);
    if (CLICKHOUSE_CONFIG_KEYS.has(key)) {
      config[key] = stringValue;
    } else if (!CLICKHOUSE_REQUIRED_METADATA.includes(key)) {
      extra[key] = stringValue;
    }
  }
  return { config, extra };
}

function phaseRange(resultsDir, label) {
  const rangePath = path.join(resultsDir, `phase-range-${label}.json`);
  if (!fs.existsSync(rangePath)) {
    const now = Date.now();
    return { started_ms: now, finished_ms: now };
  }
  return JSON.parse(fs.readFileSync(rangePath, 'utf8'));
}

function clickHouseRunRow(resultsDir, label, report) {
  const metadata = report.metadata || {};
  const missing = CLICKHOUSE_REQUIRED_METADATA.filter(key => metadata[key] === undefined);
  if (missing.length > 0) {
    throw new Error(`${label}: ClickHouse upload requires metadata: ${missing.join(', ')}`);
  }
  if (!report.benchmark_id) {
    throw new Error(`${label}: report is missing benchmark_id`);
  }

  const range = phaseRange(resultsDir, label);
  const { config, extra } = splitClickHouseMetadata(metadata);
  return {
    run_id: report.benchmark_id,
    started_at: Number(range.started_ms || Date.now()),
    finished_at: Number(range.finished_ms || range.started_ms || Date.now()),
    scenario_name: String(metadata.scenario),
    platform: String(metadata.platform),
    mode: 'send',
    git_sha: String(metadata['git-sha']),
    git_ref: String(metadata['git-ref']),
    config,
    metadata: extra,
  };
}

function clickHouseBlockRows(runId, report) {
  return (report.blocks || []).map((block, index) => ({
    run_id: runId,
    block_index: index,
    block_number: Number(block.number || 0),
    chain_timestamp_ms: block.timestamp_ms ?? block.timestamp ?? null,
    tx_count: Number(block.tx_count || 0),
    gas_used: Number(block.gas_used || 0),
    gas_limit: Number(block.gas_limit || 0),
    block_time_ms: block.block_time_ms ?? null,
    new_payload_ms: block.new_payload_ms ?? null,
    forkchoice_updated_ms: block.forkchoice_updated_ms ?? null,
    new_payload_server_latency_us: block.new_payload_server_latency_us ?? null,
    persistence_wait_us: block.persistence_wait_us ?? null,
    execution_cache_wait_us: block.execution_cache_wait_us ?? null,
    sparse_trie_wait_us: block.sparse_trie_wait_us ?? null,
  }));
}

function clickHouseSampleRow(runId, sample) {
  const value = Number(sample.value);
  if (!Number.isFinite(value)) return null;
  const name = String(sample.name || '');
  return {
    run_id: runId,
    offset_ms: Number(sample.offset_ms || 0),
    unix_ms: Number(sample.unix_ms || 0),
    metric_name: name,
    labels_json: stableJson(sample.labels || {}),
    source: name.startsWith('txgen_') ? 'txgen' : 'prometheus',
    value,
  };
}

async function uploadClickHouseRun(resultsDir, label, loaded, config) {
  const task = `clickhouse:${label}`;
  const startedAt = performance.now();
  const { reportPath, report } = loaded;
  const runRow = clickHouseRunRow(resultsDir, label, report);
  const runId = runRow.run_id;
  const blockRows = clickHouseBlockRows(runId, report);

  log('task start', { task, run_id: runId });
  await insertClickHouseRows(config, 'txgen_runs', [runRow], task);
  await insertClickHouseRows(config, 'txgen_blocks', blockRows, task);

  let batch = [];
  let samples = 0;
  let batches = 0;
  for await (const sample of iterSamples(reportPath, report)) {
    const row = clickHouseSampleRow(runId, sample);
    if (!row) continue;
    batch.push(row);
    if (batch.length >= config.sampleBatchSize) {
      batches += 1;
      await insertClickHouseRows(config, 'txgen_metric_samples', batch, task);
      samples += batch.length;
      batch = [];
    }
  }
  if (batch.length > 0) {
    batches += 1;
    await insertClickHouseRows(config, 'txgen_metric_samples', batch, task);
    samples += batch.length;
  }

  log('task complete', {
    task,
    run_id: runId,
    blocks: blockRows.length,
    samples,
    batches,
    duration_ms: elapsedMs(startedAt),
  });
  return { label, runId };
}

function promtoolConfig(victoriametricsUrl, report) {
  let url = trimUrl(victoriametricsUrl);
  if (url.endsWith('/api/v1/import/prometheus')) {
    url = url.slice(0, -'/api/v1/import/prometheus'.length);
  } else if (url.endsWith('/api/v1/write')) {
    url = url.slice(0, -'/api/v1/write'.length);
  } else if (url.endsWith('/api/v1/import')) {
    url = url.slice(0, -'/api/v1/import'.length);
  }

  return {
    baseUrl: withQueryParam(url, 'accountID', process.env.PROMETHEUS_TENANT_ID || ''),
    bearerToken: process.env.PROMETHEUS_BEARER_TOKEN || '',
    user: process.env.PROMETHEUS_USER || '',
    password: process.env.PROMETHEUS_PASSWORD || '',
    bin: process.env.PROMTOOL_BIN || 'promtool',
    batchSize: envPositiveInt('PROMTOOL_BATCH_SIZE', envPositiveInt('PROMETHEUS_BATCH_SIZE', 10_000)),
    timeoutSecs: envPositiveInt('PROMETHEUS_TIMEOUT_SECS', 60),
    extraLabel: promtoolExtraLabel(report),
  };
}

function isValidMetricName(name) {
  return /^[A-Za-z_:][A-Za-z0-9_:]*$/.test(name);
}

function sanitizeLabelName(name) {
  if (!name) return '';
  let out = '';
  [...name].forEach((ch, index) => {
    const ok = index === 0 ? /[A-Za-z_]/.test(ch) : /[A-Za-z0-9_]/.test(ch);
    if (ok) {
      out += ch;
    } else if (index === 0) {
      out += '_';
      out += /[A-Za-z0-9]/.test(ch) ? ch : '_';
    } else {
      out += '_';
    }
  });
  return out;
}

function victoriaMetric(sample) {
  const name = String(sample.name || '');
  const value = Number(sample.value);
  const timestamp = Number(sample.unix_ms || 0);
  if (!isValidMetricName(name) || !Number.isFinite(value) || !Number.isFinite(timestamp) || timestamp <= 0) {
    return null;
  }

  const metric = { __name__: name };
  for (const [rawKey, rawValue] of Object.entries(sample.labels || {})) {
    const key = sanitizeLabelName(rawKey);
    if (key) metric[key] = String(rawValue);
  }
  return { metric, value, timestamp };
}

function promtoolExtraLabel(report) {
  const metadata = report.metadata || {};
  const gitSha = metadata['git-sha'] || metadata.git_sha || metadata.gitsha;
  if (gitSha) {
    return { name: 'git_sha', value: String(gitSha) };
  }
  return { name: 'bench_upload', value: 'promtool' };
}

function escapePrometheusLabelValue(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/"/g, '\\"');
}

function prometheusTextSample(sample) {
  const item = victoriaMetric(sample);
  if (!item) return null;

  const labels = sortedVictoriaLabels(item.metric)
    .filter(label => label.name !== '__name__')
    .map(label => `${label.name}="${escapePrometheusLabelValue(label.value)}"`)
    .join(',');
  const labelText = labels ? `{${labels}}` : '';
  return `${item.metric.__name__}${labelText} ${item.value} ${Math.trunc(item.timestamp)}`;
}

function promtoolHeaders(config) {
  const headers = {};
  if (config.bearerToken) {
    headers.Authorization = `Bearer ${config.bearerToken}`;
  }
  if (config.user) {
    const token = Buffer.from(`${config.user}:${config.password}`).toString('base64');
    headers.Authorization = `Basic ${token}`;
  }
  return headers;
}

function promtoolArgs(config) {
  const args = [
    'push',
    'metrics',
    `--timeout=${config.timeoutSecs}s`,
    `--label=${config.extraLabel.name}=${config.extraLabel.value}`,
  ];
  for (const [name, value] of Object.entries(promtoolHeaders(config))) {
    args.push(`--header=${name}=${value}`);
  }
  args.push(config.baseUrl);
  return args;
}

function pushPromtoolBatch(config, lines, task, batch) {
  return new Promise((resolve, reject) => {
    const startedAt = performance.now();
    const body = `${lines.join('\n')}\n`;
    const bodyBytes = Buffer.byteLength(body);
    const args = promtoolArgs(config);
    const child = spawn(config.bin, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const killAfter = setTimeout(() => {
      child.kill('SIGKILL');
    }, (config.timeoutSecs + 30) * 1000);

    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(killAfter);
      fn(value);
    };

    child.stdout.on('data', chunk => { stdout += chunk.toString(); });
    child.stderr.on('data', chunk => { stderr += chunk.toString(); });
    child.on('error', err => finish(reject, err));
    child.on('close', code => {
      const durationMs = elapsedMs(startedAt);
      if (code === 0) {
        log('victoriametrics batch complete', {
          task,
          batch,
          protocol: 'promtool',
          samples: lines.length,
          body_bytes: bodyBytes,
          duration_ms: durationMs,
        });
        finish(resolve);
      } else {
        const output = `${stderr}\n${stdout}`.trim();
        logError('victoriametrics batch failed', {
          task,
          batch,
          protocol: 'promtool',
          duration_ms: durationMs,
          exit_code: code,
          error: output || '<no promtool output>',
        });
        finish(reject, new Error(`promtool exited with code ${code}: ${output || '<no output>'}`));
      }
    });

    log('victoriametrics batch start', {
      task,
      batch,
      protocol: 'promtool',
      samples: lines.length,
      body_bytes: bodyBytes,
    });
    child.stdin.end(body);
  });
}

async function flushPromtoolLines(config, lines, task, batch) {
  if (lines.length === 0) return;
  await pushPromtoolBatch(config, lines, task, batch);
  lines.length = 0;
}

function sortedVictoriaLabels(metric) {
  return Object.entries(metric)
    .map(([name, value]) => ({ name, value: String(value) }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

async function uploadVictoriaRun(label, loaded, config) {
  const task = `victoriametrics:${label}`;
  const startedAt = performance.now();
  const { reportPath, report } = loaded;
  const lines = [];
  let samples = 0;
  let batches = 0;

  log('task start', { task, protocol: 'promtool', batch_size: config.batchSize });
  for await (const sample of iterSamples(reportPath, report)) {
    const line = prometheusTextSample(sample);
    if (!line) continue;
    lines.push(line);
    if (lines.length >= config.batchSize) {
      batches += 1;
      samples += lines.length;
      await flushPromtoolLines(config, lines, task, batches);
    }
  }
  if (lines.length > 0) {
    batches += 1;
    samples += lines.length;
    await flushPromtoolLines(config, lines, task, batches);
  }

  log('task complete', {
    task,
    protocol: 'promtool',
    samples,
    batches,
    duration_ms: elapsedMs(startedAt),
  });
  return { label, samples };
}

function uploadVictoriaRunInWorker(resultsDir, label, victoriametricsUrl) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const worker = new Worker(__filename, {
      workerData: {
        kind: 'victoriametrics',
        resultsDir,
        label,
        victoriametricsUrl,
      },
    });

    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      fn(value);
    };

    worker.on('message', message => {
      if (message?.error) {
        finish(reject, new Error(message.error));
      } else {
        finish(resolve, message.result);
      }
    });
    worker.on('error', err => finish(reject, err));
    worker.on('exit', code => {
      if (code !== 0) {
        finish(reject, new Error(`worker exited with code ${code}`));
      }
    });
  });
}

function addTask(tasks, task, promise) {
  tasks.push({ task, promise });
  return promise;
}

async function settleUploadTasks(tasks) {
  const settled = await Promise.allSettled(tasks.map(task => task.promise));
  const results = [];
  const failures = [];
  for (let i = 0; i < settled.length; i += 1) {
    const task = tasks[i];
    const result = settled[i];
    if (result.status === 'fulfilled') {
      results.push(result.value);
    } else {
      failures.push({ task: task.task, reason: result.reason });
      logError('task failed', {
        task: task.task,
        error: result.reason?.message || result.reason,
      });
    }
  }
  if (failures.length > 0) {
    throw new Error(`${failures.length} upload task${failures.length === 1 ? '' : 's'} failed`);
  }
  return results;
}

async function main() {
  const startedAt = performance.now();
  const args = parseArgs(process.argv.slice(2));
  if (!fs.existsSync(args.resultsDir)) {
    throw new Error(`results directory not found: ${args.resultsDir}`);
  }

  const runLabels = readRunLabels(args.resultsDir);
  if (runLabels.length === 0) {
    throw new Error(`no report files found in ${args.resultsDir}`);
  }

  const loadedReports = new Map(runLabels.map(label => [label, loadReport(args.resultsDir, label)]));
  const tasks = [];
  const clickHouseUploads = [];
  log('upload plan', {
    runs: runLabels.length,
    victoriametrics: args.victoriametricsUrl ? 'enabled' : 'disabled',
    clickhouse: args.clickhouseUrl ? 'enabled' : 'disabled',
    clickhouse_run: args.clickhouseUrl ? args.clickhouseRun : '',
  });

  if (args.victoriametricsUrl) {
    for (const label of runLabels) {
      const task = `victoriametrics:${label}`;
      addTask(tasks, task, uploadVictoriaRunInWorker(args.resultsDir, label, args.victoriametricsUrl));
    }
  }

  if (args.clickhouseUrl) {
    const clickHouseLabels = args.clickhouseRun === ''
      ? runLabels
      : runLabels.filter(label => label === args.clickhouseRun);
    if (clickHouseLabels.length === 0) {
      throw new Error(`--clickhouse-run must be one of: ${runLabels.join(', ')} (got '${args.clickhouseRun}')`);
    }

    const config = clickHouseConfig(args.clickhouseUrl);
    for (const label of clickHouseLabels) {
      const task = `clickhouse:${label}`;
      const promise = uploadClickHouseRun(args.resultsDir, label, loadedReports.get(label), config);
      clickHouseUploads.push(promise);
      addTask(tasks, task, promise);
    }
  }

  if (tasks.length === 0) {
    log('no upload destinations configured');
    return;
  }

  const results = await settleUploadTasks(tasks);
  const clickHouseResults = await Promise.all(clickHouseUploads);
  if (clickHouseResults.length > 0) {
    const preferred = clickHouseResults.find(result => result.label === args.clickhouseRun) || clickHouseResults[0];
    for (const result of clickHouseResults) {
      fs.writeFileSync(path.join(args.resultsDir, `clickhouse-run-id-${result.label}.txt`), `${result.runId}\n`);
    }
    fs.writeFileSync(path.join(args.resultsDir, 'clickhouse-run-id.txt'), `${preferred.runId}\n`);
  }

  log('uploads complete', { jobs: results.length, duration_ms: elapsedMs(startedAt) });
}

async function workerMain() {
  if (workerData?.kind !== 'victoriametrics') {
    throw new Error(`unknown worker kind: ${workerData?.kind}`);
  }

  const loaded = loadReport(workerData.resultsDir, workerData.label);
  const config = promtoolConfig(workerData.victoriametricsUrl, loaded.report);
  const result = await uploadVictoriaRun(workerData.label, loaded, config);
  parentPort.postMessage({ result });
}

if (isMainThread) {
  main().catch(err => {
    logError('upload failed', { error: err.stack || err.message });
    process.exit(1);
  });
} else {
  workerMain().catch(err => {
    logError('worker failed', {
      task: workerData?.kind && workerData?.label ? `${workerData.kind}:${workerData.label}` : '',
      error: err.stack || err.message,
    });
    parentPort.postMessage({ error: err.stack || err.message });
  });
}
