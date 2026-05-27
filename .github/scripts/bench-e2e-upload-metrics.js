#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const zlib = require('zlib');
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

function victoriaConfig(victoriametricsUrl) {
  let url = trimUrl(victoriametricsUrl);
  if (url.endsWith('/api/v1/import/prometheus')) {
    url = url.slice(0, -'/api/v1/import/prometheus'.length);
  } else if (url.endsWith('/api/v1/write')) {
    url = url.slice(0, -'/api/v1/write'.length);
  } else if (url.endsWith('/api/v1/import')) {
    url = url.slice(0, -'/api/v1/import'.length);
  }

  return {
    writeUrl: withQueryParam(`${url}/api/v1/write`, 'accountID', process.env.PROMETHEUS_TENANT_ID || ''),
    bearerToken: process.env.PROMETHEUS_BEARER_TOKEN || '',
    user: process.env.PROMETHEUS_USER || '',
    password: process.env.PROMETHEUS_PASSWORD || '',
    batchSize: envPositiveInt('PROMETHEUS_BATCH_SIZE', 10_000),
    timeoutSecs: envPositiveInt('PROMETHEUS_TIMEOUT_SECS', 60),
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

function addVictoriaSample(series, sample) {
  const item = victoriaMetric(sample);
  if (!item) return false;

  const key = stableJson(item.metric);
  let entry = series.get(key);
  if (!entry) {
    entry = { metric: item.metric, values: [], timestamps: [] };
    series.set(key, entry);
  }
  entry.values.push(item.value);
  entry.timestamps.push(item.timestamp);
  return true;
}

function victoriaHeaders(config) {
  const headers = {
    'Content-Type': 'application/x-protobuf',
    'Content-Encoding': 'snappy',
    'X-Prometheus-Remote-Write-Version': '0.1.0',
  };
  if (config.bearerToken) {
    headers.Authorization = `Bearer ${config.bearerToken}`;
  }
  if (config.user) {
    const token = Buffer.from(`${config.user}:${config.password}`).toString('base64');
    headers.Authorization = `Basic ${token}`;
  }
  return headers;
}

function protoVarint(value) {
  let n = BigInt(value);
  const bytes = [];
  while (n >= 0x80n) {
    bytes.push(Number((n & 0x7fn) | 0x80n));
    n >>= 7n;
  }
  bytes.push(Number(n));
  return Buffer.from(bytes);
}

function protoTag(field, wireType) {
  return protoVarint((field << 3) | wireType);
}

function protoBytes(field, bytes) {
  return Buffer.concat([protoTag(field, 2), protoVarint(bytes.length), bytes]);
}

function protoString(field, value) {
  return protoBytes(field, Buffer.from(String(value), 'utf8'));
}

function protoDouble(field, value) {
  const bytes = Buffer.allocUnsafe(9);
  bytes[0] = (field << 3) | 1;
  bytes.writeDoubleLE(value, 1);
  return bytes;
}

function protoInt64(field, value) {
  return Buffer.concat([protoTag(field, 0), protoVarint(Math.trunc(value))]);
}

function protoLabel(name, value) {
  return Buffer.concat([protoString(1, name), protoString(2, value)]);
}

function protoSample(value, timestamp) {
  return Buffer.concat([protoDouble(1, value), protoInt64(2, timestamp)]);
}

function sortedVictoriaLabels(metric) {
  return Object.entries(metric)
    .map(([name, value]) => ({ name, value: String(value) }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

function victoriaRemoteWriteBody(series) {
  const timeseries = [];
  for (const item of series.values()) {
    const labels = sortedVictoriaLabels(item.metric)
      .map(label => protoBytes(1, protoLabel(label.name, label.value)));
    const samples = item.values
      .map((value, index) => ({ value, timestamp: item.timestamps[index] }))
      .sort((a, b) => a.timestamp - b.timestamp)
      .map(sample => protoBytes(2, protoSample(sample.value, sample.timestamp)));
    timeseries.push(protoBytes(1, Buffer.concat([...labels, ...samples])));
  }
  return Buffer.concat(timeseries);
}

function snappyLiteral(chunk) {
  if (chunk.length === 0) return Buffer.alloc(0);

  if (chunk.length < 60) {
    return Buffer.concat([Buffer.from([(chunk.length - 1) << 2]), chunk]);
  }

  const lengthBytes = [];
  let lengthMinusOne = chunk.length - 1;
  while (lengthMinusOne > 0) {
    lengthBytes.push(lengthMinusOne & 0xff);
    lengthMinusOne >>= 8;
  }
  return Buffer.concat([
    Buffer.from([(59 + lengthBytes.length) << 2, ...lengthBytes]),
    chunk,
  ]);
}

function snappyCopy(offset, length) {
  const chunks = [];
  let remaining = length;
  while (remaining > 0) {
    const chunkLength = Math.min(remaining, 64);
    chunks.push(Buffer.from([
      ((chunkLength - 1) << 2) | 2,
      offset & 0xff,
      (offset >> 8) & 0xff,
    ]));
    remaining -= chunkLength;
  }
  return chunks;
}

function snappyHash(value) {
  return (Math.imul(value, 0x1e35a7bd) >>> 17) & 0x7fff;
}

function snappyLoad32(bytes, offset) {
  return (
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24)
  ) >>> 0;
}

function snappyCompressBlock(input) {
  const out = [];
  const table = new Int32Array(1 << 15);
  table.fill(-1);

  let anchor = 0;
  let ip = 0;
  const limit = input.length - 4;
  while (ip <= limit) {
    const seq = snappyLoad32(input, ip);
    const hash = snappyHash(seq);
    const candidate = table[hash];
    table[hash] = ip;

    if (
      candidate >= 0 &&
      ip - candidate <= 0xffff &&
      snappyLoad32(input, candidate) === seq
    ) {
      out.push(snappyLiteral(input.subarray(anchor, ip)));

      let matched = 4;
      while (
        ip + matched < input.length &&
        input[candidate + matched] === input[ip + matched]
      ) {
        matched += 1;
      }
      out.push(...snappyCopy(ip - candidate, matched));
      ip += matched;
      anchor = ip;

      if (ip <= limit) {
        table[snappyHash(snappyLoad32(input, ip - 1))] = ip - 1;
      }
    } else {
      ip += 1;
    }
  }

  out.push(snappyLiteral(input.subarray(anchor)));
  return Buffer.concat(out);
}

function snappyCompress(input) {
  const chunks = [protoVarint(input.length)];
  for (let offset = 0; offset < input.length; offset += 65536) {
    chunks.push(snappyCompressBlock(input.subarray(offset, offset + 65536)));
  }
  return Buffer.concat(chunks);
}

async function flushVictoriaSeries(config, series, task, batch) {
  if (series.size === 0) return;

  const seriesCount = series.size;
  const sampleCount = [...series.values()].reduce((sum, item) => sum + item.values.length, 0);
  const startedAt = performance.now();
  const body = snappyCompress(victoriaRemoteWriteBody(series));

  log('victoriametrics batch start', {
    task,
    batch,
    protocol: 'remote_write',
    samples: sampleCount,
    series: seriesCount,
    body_bytes: body.length,
  });
  try {
    await post(config.writeUrl, body, victoriaHeaders(config), config.timeoutSecs);
    log('victoriametrics batch complete', {
      task,
      batch,
      protocol: 'remote_write',
      samples: sampleCount,
      series: seriesCount,
      body_bytes: body.length,
      duration_ms: elapsedMs(startedAt),
    });
    series.clear();
  } catch (err) {
    logError('victoriametrics batch failed', {
      task,
      batch,
      protocol: 'remote_write',
      duration_ms: elapsedMs(startedAt),
      error: err.message,
    });
    throw err;
  }
}

async function uploadVictoriaRun(label, loaded, config) {
  const task = `victoriametrics:${label}`;
  const startedAt = performance.now();
  const { reportPath, report } = loaded;
  let series = new Map();
  let batchSamples = 0;
  let samples = 0;
  let batches = 0;

  log('task start', { task });
  for await (const sample of iterSamples(reportPath, report)) {
    if (!addVictoriaSample(series, sample)) continue;
    batchSamples += 1;
    if (batchSamples >= config.batchSize) {
      batches += 1;
      await flushVictoriaSeries(config, series, task, batches);
      samples += batchSamples;
      batchSamples = 0;
    }
  }
  if (batchSamples > 0) {
    batches += 1;
    await flushVictoriaSeries(config, series, task, batches);
    samples += batchSamples;
  }

  log('task complete', { task, samples, batches, duration_ms: elapsedMs(startedAt) });
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

  const config = victoriaConfig(workerData.victoriametricsUrl);
  const loaded = loadReport(workerData.resultsDir, workerData.label);
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
