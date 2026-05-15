// Sends Slack notifications for tempo-bench results.
//
// Reads from environment:
//   SLACK_BENCH_BOT_TOKEN  – Slack Bot User OAuth Token (xoxb-...)
//   SLACK_BENCH_CHANNEL    – Public channel ID for results
//   BENCH_WORK_DIR         – Directory containing summary.json
//   BENCH_PR               – PR number (may be empty)
//   BENCH_ACTOR            – GitHub user who triggered the bench
//   BENCH_JOB_URL          – URL to the Actions job page
//   BENCH_RUN_LABEL        – Replay Slack title label (for example, Replay Bench)
//
// Usage from actions/github-script:
//   const notify = require('./.github/scripts/bench-slack-notify.js');
//   await notify.e2e.success({ core, context });
//   await notify.e2e.failure({ core, context, failedStep: '...' });
//   await notify.replay.success({ core, context });
//   await notify.replay.failure({ core, context, failedStep: '...' });

const fs = require('fs');
const path = require('path');

const SLACK_API = 'https://slack.com/api/chat.postMessage';

// Significance thresholds (percentage change)
const THRESHOLD_PCT = 5;
const SIG_EMOJI = { good: '✅', bad: '❌', neutral: '⚪' };

function loadSlackUsers(repoRoot) {
  try {
    const raw = fs.readFileSync(path.join(repoRoot, '.github', 'scripts', 'bench-slack-users.json'), 'utf8');
    const data = JSON.parse(raw);
    const users = {};
    for (const [k, v] of Object.entries(data)) {
      if (!k.startsWith('_') && typeof v === 'string' && v.startsWith('U')) {
        users[k] = v;
      }
    }
    return users;
  } catch {
    return {};
  }
}

async function postToSlack(token, channel, blocks, text, core, threadTs) {
  const payload = { channel, blocks, text, unfurl_links: false };
  if (threadTs) payload.thread_ts = threadTs;
  const resp = await fetch(SLACK_API, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  const data = await resp.json();
  if (!data.ok) {
    core.warning(`Slack API error (channel ${channel}): ${JSON.stringify(data)}`);
  }
  return data;
}

function cell(text) {
  return { type: 'raw_text', text: String(text) || ' ' };
}

function fmtMs(v) { return v != null ? v.toFixed(2) + 'ms' : '-'; }
function fmtVal(v, suffix = '', precision = 2) { return v != null ? v.toFixed(precision) + suffix : '-'; }
function fmtS(v) { return v != null ? v.toFixed(2) + 's' : '-'; }

function classifyPctChange(pct, lowerIsBetter) {
  if (pct == null || Math.abs(pct) < THRESHOLD_PCT) return 'neutral';
  return (pct < 0) === lowerIsBetter ? 'good' : 'bad';
}

function changeFromPct(pct, lowerIsBetter) {
  return { pct, sig: classifyPctChange(pct, lowerIsBetter) };
}

function fmtChange(change) {
  if (!change || change.pct == null) return '';
  const sign = change.pct >= 0 ? '+' : '';
  const ci = change.ci_pct ? ` (±${change.ci_pct.toFixed(2)}%)` : '';
  return `${sign}${change.pct.toFixed(2)}%${ci} ${SIG_EMOJI[change.sig] || ''}`.trim();
}

function verdictFromChanges(changes, neutralLabel = 'No Difference') {
  const vals = Object.values(changes || {});
  const hasBad = vals.some(v => v.sig === 'bad');
  const hasGood = vals.some(v => v.sig === 'good');
  if (hasBad && hasGood) return { emoji: ':warning:', label: 'Mixed Results' };
  if (hasBad) return { emoji: ':x:', label: 'Regression' };
  if (hasGood) return { emoji: ':white_check_mark:', label: 'Improvement' };
  return { emoji: ':white_circle:', label: neutralLabel };
}

function hasImprovement(changes) {
  return Object.values(changes || {}).some(v => v.sig === 'good');
}

function e2eChanges(deltas) {
  return {
    tps: changeFromPct(deltas.tps, false),
    tps_p50: changeFromPct(deltas.tps_p50, false),
    tps_p90: changeFromPct(deltas.tps_p90, false),
    tps_p99: changeFromPct(deltas.tps_p99, false),
    mgas_s: changeFromPct(deltas.mgas_s, false),
    block_time_p50: changeFromPct(deltas.block_time_p50, true),
    block_time_p90: changeFromPct(deltas.block_time_p90, true),
    block_time_p99: changeFromPct(deltas.block_time_p99, true),
  };
}

function refLink(commitUrl, sha, refName, fallbackLabel) {
  const label = refName || fallbackLabel;
  return sha ? `<${commitUrl}/${sha}|${label}>` : label;
}

function repoLink(repo) {
  return `<https://github.com/${repo}|Tempo>`;
}

function buildGrafanaUrl(benchmarkId, referenceEpoch) {
  if (!benchmarkId || !referenceEpoch) return null;
  const fromMs = referenceEpoch * 1000;
  const toMs = Date.now();
  return `https://tempoxyz.grafana.net/d/dffj6qf1o30oowe/performance?orgId=1&from=${fromMs}&to=${toMs}&var-datasource=efk1hcn87dnnkd&var-filter_label=benchmark_id&var-filter_value=${benchmarkId}&var-group_by=benchmark_run`;
}

function fmtBlockCount(baselineBlocks, featureBlocks) {
  if (baselineBlocks == null && featureBlocks == null) return '-';
  if (baselineBlocks === featureBlocks) return `\`${baselineBlocks}\``;
  if (baselineBlocks == null) return `feature \`${featureBlocks}\``;
  if (featureBlocks == null) return `baseline \`${baselineBlocks}\``;
  return `baseline \`${baselineBlocks}\` | feature \`${featureBlocks}\``;
}

function buildMetricRows(summary) {
  const b = summary.results.baseline;
  const f = summary.results.feature;
  const d = summary.results.deltas;
  const c = e2eChanges(d);
  return [
    { label: 'Avg TPS',         baseline: fmtVal(b.tps, '', 0),     feature: fmtVal(f.tps, '', 0),     change: fmtChange(c.tps) },
    { label: 'TPS P50',         baseline: fmtVal(b.tps_p50, '', 1), feature: fmtVal(f.tps_p50, '', 1), change: fmtChange(c.tps_p50) },
    { label: 'TPS P90',         baseline: fmtVal(b.tps_p90, '', 1), feature: fmtVal(f.tps_p90, '', 1), change: fmtChange(c.tps_p90) },
    { label: 'TPS P99',         baseline: fmtVal(b.tps_p99, '', 1), feature: fmtVal(f.tps_p99, '', 1), change: fmtChange(c.tps_p99) },
    { label: 'Gas/s',           baseline: fmtVal(b.mgas_s, ' Mgas/s', 1), feature: fmtVal(f.mgas_s, ' Mgas/s', 1), change: fmtChange(c.mgas_s) },
    { label: 'Block P50',       baseline: fmtMs(b.block_time_p50),  feature: fmtMs(f.block_time_p50),  change: fmtChange(c.block_time_p50) },
    { label: 'Block P90',       baseline: fmtMs(b.block_time_p90),  feature: fmtMs(f.block_time_p90),  change: fmtChange(c.block_time_p90) },
    { label: 'Block P99',       baseline: fmtMs(b.block_time_p99),  feature: fmtMs(f.block_time_p99),  change: fmtChange(c.block_time_p99) },
  ];
}

function buildSuccessBlocks({ summary, prNumber, actor, actorSlackId, jobUrl, repo }) {
  const b = summary.results.baseline;
  const f = summary.results.feature;
  const d = summary.results.deltas;
  const { emoji, label } = verdictFromChanges(e2eChanges(d), 'No Significant Change');

  const prUrl = prNumber ? `https://github.com/${repo}/pull/${prNumber}` : '';
  const commitUrl = `https://github.com/${repo}/commit`;
  const baselineName = process.env.BENCH_BASELINE_NAME || 'baseline';
  const featureName = process.env.BENCH_FEATURE_NAME || 'feature';
  const baselineLink = refLink(commitUrl, summary.baseline_ref, baselineName, 'baseline');
  const featureLink = refLink(commitUrl, summary.feature_ref, featureName, 'feature');

  const metaParts = [];
  if (prNumber) metaParts.push(`*<${prUrl}|PR #${prNumber}>*`);
  metaParts.push(`triggered by ${actorSlackId ? `<@${actorSlackId}>` : `@${actor}`}`);

  const config = summary.config;
  const blockCount = fmtBlockCount(b.blocks, f.blocks);

  const sectionText = [
    `*Repo:* ${repoLink(repo)}`,
    metaParts.join(' | '),
    '',
    `*Baseline:* ${baselineLink}`,
    `*Feature:* ${featureLink}`,
    '',
    `*Preset:* \`${config.preset}\` | *Bloat:* \`${Math.round(config.bloat / 1000)} GB\``,
    `*Duration:* \`${config.duration}s\` | *Target TPS:* \`${config.tps}\` | *Blocks:* ${blockCount}`,
  ].join('\n');

  const rows = buildMetricRows(summary);
  const tableRows = [
    [cell('Metric'), cell('Baseline'), cell('Feature'), cell('Change')],
    ...rows.map(r => [cell(r.label), cell(r.baseline), cell(r.feature), cell(r.change || ' ')]),
  ];

  const buttons = [
    {
      type: 'button',
      text: { type: 'plain_text', text: 'CI :github:', emoji: true },
      url: jobUrl,
      action_id: 'ci_button',
    },
  ];
  if (prNumber) {
    const diffUrl = `https://github.com/${repo}/pull/${prNumber}/files`;
    buttons.push({
      type: 'button',
      text: { type: 'plain_text', text: 'Diff :github:', emoji: true },
      url: diffUrl,
      action_id: 'diff_button',
    });
  }
  const grafanaUrl = buildGrafanaUrl(summary.benchmark_id, summary.reference_epoch);
  if (grafanaUrl) {
    buttons.push({
      type: 'button',
      text: { type: 'plain_text', text: 'Grafana :chart_with_upwards_trend:', emoji: true },
      url: grafanaUrl,
      action_id: 'grafana_button',
    });
  }

  return [
    {
      type: 'header',
      text: { type: 'plain_text', text: `${emoji} Tempo Bench ${label}`, emoji: true },
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: sectionText },
    },
    {
      type: 'table',
      column_settings: [
        { align: 'left' },
        { align: 'right' },
        { align: 'right' },
        { align: 'right' },
      ],
      rows: tableRows,
    },
    {
      type: 'actions',
      elements: buttons,
    },
  ];
}

function buildFailureBlocks({ prNumber, actor, actorSlackId, jobUrl, repo, failedStep }) {
  const prUrl = prNumber ? `https://github.com/${repo}/pull/${prNumber}` : '';
  const actorMention = actorSlackId ? `<@${actorSlackId}>` : `@${actor}`;
  const parts = [
    `*Repo:* ${repoLink(repo)}`,
    prNumber ? `*<${prUrl}|PR #${prNumber}>*` : '',
    `by ${actorMention}`,
    `failed while *${failedStep}*`,
  ].filter(Boolean);

  return [
    {
      type: 'header',
      text: { type: 'plain_text', text: ':rotating_light: Bench Failed', emoji: true },
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: parts.join(' | ') },
    },
    {
      type: 'actions',
      elements: [{
        type: 'button',
        text: { type: 'plain_text', text: 'View Logs :github:', emoji: true },
        url: jobUrl,
        action_id: 'ci_button',
      }],
    },
  ];
}

async function success({ core, context }) {
  const token = process.env.SLACK_BENCH_BOT_TOKEN;
  if (!token) {
    core.info('SLACK_BENCH_BOT_TOKEN not set, skipping Slack notification');
    return;
  }

  let summary;
  try {
    summary = JSON.parse(fs.readFileSync(process.env.BENCH_WORK_DIR + '/summary.json', 'utf8'));
  } catch (e) {
    core.warning('Could not read summary.json for Slack notification');
    return;
  }

  const repo = `${context.repo.owner}/${context.repo.repo}`;
  const prNumber = process.env.BENCH_PR;
  const actor = process.env.BENCH_ACTOR;
  const jobUrl = process.env.BENCH_JOB_URL ||
    `${context.serverUrl}/${repo}/actions/runs/${context.runId}`;

  const slackUsers = loadSlackUsers(process.env.GITHUB_WORKSPACE || '.');
  const actorSlackId = slackUsers[actor];

  const blocks = buildSuccessBlocks({ summary, prNumber, actor, actorSlackId, jobUrl, repo });
  const text = `Tempo bench: baseline vs feature`;

  const changes = e2eChanges(summary.results.deltas);
  const channel = process.env.SLACK_BENCH_CHANNEL;
  const slackMode = process.env.BENCH_SLACK || 'always';
  let postedToChannel = false;

  // Match reth-bench: post to the public channel only for significant improvements.
  if (channel && hasImprovement(changes)) {
    await postToSlack(token, channel, blocks, text, core);
    postedToChannel = true;
  } else if (channel) {
    core.info('No significant improvement, skipping public channel notification');
  }

  if (slackMode === 'on-win') {
    if (!postedToChannel) {
      core.info('on-win mode: no improvement detected, skipping all notifications');
    }
    return;
  }

  // DM the actor when results were not posted to the public channel
  if (!postedToChannel) {
    if (actorSlackId) {
      await postToSlack(token, actorSlackId, blocks, text, core);
    } else {
      core.info(`No Slack user mapping for GitHub user '${actor}', skipping DM`);
    }
  } else {
    core.info(`Results posted to channel, skipping DM to ${actor}`);
  }
}

async function failure({ core, context, failedStep }) {
  const token = process.env.SLACK_BENCH_BOT_TOKEN;
  if (!token) {
    core.info('SLACK_BENCH_BOT_TOKEN not set, skipping Slack notification');
    return;
  }

  const repo = `${context.repo.owner}/${context.repo.repo}`;
  const prNumber = process.env.BENCH_PR;
  const actor = process.env.BENCH_ACTOR;
  const jobUrl = process.env.BENCH_JOB_URL ||
    `${context.serverUrl}/${repo}/actions/runs/${context.runId}`;

  const slackUsers = loadSlackUsers(process.env.GITHUB_WORKSPACE || '.');
  const actorSlackId = slackUsers[actor];

  const blocks = buildFailureBlocks({ prNumber, actor, actorSlackId, jobUrl, repo, failedStep });
  const text = `Bench failed while ${failedStep}`;

  // DM the actor on failure
  if (actorSlackId) {
    await postToSlack(token, actorSlackId, blocks, text, core);
  } else {
    core.info(`No Slack user mapping for GitHub user '${actor}', skipping DM`);
  }
}

function shortRef(ref) {
  if (!ref) return 'unknown';
  return /^[0-9a-f]{40}$/i.test(ref) ? ref.slice(0, 8) : ref;
}

function replayRefLink(repo, ref, name) {
  const label = name || shortRef(ref);
  if (!ref || ref === 'unknown') return label;
  return `<https://github.com/${repo}/commit/${ref}|${label}>`;
}

function buildReplayMetricRows(summary) {
  const baseline = summary.baseline?.stats || {};
  const feature = summary.feature?.stats || {};
  const changes = summary.changes || {};

  return [
    { label: 'Mean', baseline: fmtMs(baseline.mean_ms), feature: fmtMs(feature.mean_ms), change: fmtChange(changes.mean) },
    { label: 'StdDev', baseline: fmtMs(baseline.stddev_ms), feature: fmtMs(feature.stddev_ms), change: '' },
    { label: 'P50', baseline: fmtMs(baseline.p50_ms), feature: fmtMs(feature.p50_ms), change: fmtChange(changes.p50) },
    { label: 'P90', baseline: fmtMs(baseline.p90_ms), feature: fmtMs(feature.p90_ms), change: fmtChange(changes.p90) },
    { label: 'P99', baseline: fmtMs(baseline.p99_ms), feature: fmtMs(feature.p99_ms), change: fmtChange(changes.p99) },
    { label: 'Mgas/s', baseline: fmtVal(baseline.mean_mgas_s), feature: fmtVal(feature.mean_mgas_s), change: fmtChange(changes.mgas_s) },
    { label: 'Wall Clock', baseline: fmtS(baseline.wall_clock_s), feature: fmtS(feature.wall_clock_s), change: fmtChange(changes.wall_clock) },
    { label: 'Persist Wait', baseline: fmtMs(baseline.mean_persist_ms || 0), feature: fmtMs(feature.mean_persist_ms || 0), change: fmtChange(changes.persist_wait) },
  ];
}

function buildReplayWaitRows(summary) {
  return Object.values(summary.wait_times || {}).map(wt => ({
    title: wt.title,
    baseline: fmtMs(wt.baseline?.mean_ms),
    feature: fmtMs(wt.feature?.mean_ms),
  }));
}

function replayRunLabel() {
  return (process.env.BENCH_RUN_LABEL || 'Replay Bench').trim() || 'Replay Bench';
}

function buildReplaySuccessBlocks({ summary, prNumber, actor, actorSlackId, jobUrl, repo, chain, blocks, warmup, runLabel }) {
  const { emoji, label } = verdictFromChanges(summary.changes || {});
  const prUrl = prNumber ? `https://github.com/${repo}/pull/${prNumber}` : '';
  const baseline = summary.baseline || {};
  const feature = summary.feature || {};
  const baselineLink = replayRefLink(repo, baseline.ref, baseline.name);
  const featureLink = replayRefLink(repo, feature.ref, feature.name);
  const diffUrl = `https://github.com/${repo}/compare/${baseline.ref || ''}...${feature.ref || ''}`;

  const metaParts = [`*Repo:* ${repoLink(repo)}`];
  if (prNumber) metaParts.push(`*<${prUrl}|PR #${prNumber}>*`);
  metaParts.push(`triggered by ${actorSlackId ? `<@${actorSlackId}>` : `@${actor}`}`);

  const blockCount = summary.blocks || blocks || '-';
  const warmupCount = summary.warmup_blocks || warmup || '-';
  const sectionText = [
    metaParts.join(' | '),
    '',
    `*Baseline:* ${baselineLink}`,
    `*Feature:* ${featureLink}`,
    `*Chain:* \`${chain || '-'}\` | *Warmup:* \`${warmupCount}\` | *Blocks:* \`${blockCount}\``,
  ].join('\n');

  const rows = buildReplayMetricRows(summary);
  const tableRows = [
    [cell('Metric'), cell('Baseline'), cell('Feature'), cell('Change')],
    ...rows.map(row => [cell(row.label), cell(row.baseline), cell(row.feature), cell(row.change || ' ')]),
  ];

  const blocksPayload = [
    {
      type: 'header',
      text: { type: 'plain_text', text: `${emoji} Tempo ${runLabel}: ${label}`, emoji: true },
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: sectionText },
    },
    {
      type: 'table',
      column_settings: [{ align: 'left' }, { align: 'right' }, { align: 'right' }, { align: 'right' }],
      rows: tableRows,
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: 'CI :github:', emoji: true },
          url: jobUrl,
          action_id: 'ci_button',
        },
        {
          type: 'button',
          text: { type: 'plain_text', text: 'Diff :github:', emoji: true },
          url: diffUrl,
          action_id: 'diff_button',
        },
        ...((() => {
          const gUrl = buildGrafanaUrl(process.env.BENCH_BENCHMARK_ID, Number(process.env.BENCH_REFERENCE_EPOCH));
          return gUrl ? [{
            type: 'button',
            text: { type: 'plain_text', text: 'Grafana :chart_with_upwards_trend:', emoji: true },
            url: gUrl,
            action_id: 'grafana_button',
          }] : [];
        })()),
      ],
    },
  ];

  const threadBlocks = [];
  const waitRows = buildReplayWaitRows(summary);
  if (waitRows.length > 0) {
    threadBlocks.push({
      type: 'table',
      column_settings: [{ align: 'left' }, { align: 'right' }, { align: 'right' }],
      rows: [
        [cell('Wait Time'), cell('Baseline'), cell('Feature')],
        ...waitRows.map(row => [cell(row.title), cell(row.baseline), cell(row.feature)]),
      ],
    });
  }

  return { blocks: blocksPayload, threadBlocks };
}

function buildReplayFailureBlocks({ prNumber, actor, actorSlackId, jobUrl, repo, chain, failedStep, runLabel }) {
  const prUrl = prNumber ? `https://github.com/${repo}/pull/${prNumber}` : '';
  const actorMention = actorSlackId ? `<@${actorSlackId}>` : `@${actor}`;
  const parts = [
    `*Repo:* ${repoLink(repo)}`,
    prNumber ? `*<${prUrl}|PR #${prNumber}>*` : '',
    `by ${actorMention}`,
    `chain \`${chain || '-'}\``,
    `failed while *${failedStep}*`,
  ].filter(Boolean);

  return [
    {
      type: 'header',
      text: { type: 'plain_text', text: `:rotating_light: Tempo ${runLabel} Failed`, emoji: true },
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: parts.join(' | ') },
    },
    {
      type: 'actions',
      elements: [{
        type: 'button',
        text: { type: 'plain_text', text: 'View Logs :github:', emoji: true },
        url: jobUrl,
        action_id: 'ci_button',
      }],
    },
  ];
}

async function replaySuccess({ core, context }) {
  const token = process.env.SLACK_BENCH_BOT_TOKEN;
  if (!token) {
    core.info('SLACK_BENCH_BOT_TOKEN not set, skipping replay Slack notification');
    return;
  }

  let summary;
  try {
    summary = JSON.parse(fs.readFileSync(process.env.BENCH_WORK_DIR + '/summary.json', 'utf8'));
  } catch (e) {
    core.warning('Could not read summary.json for replay Slack notification');
    return;
  }

  const repo = `${context.repo.owner}/${context.repo.repo}`;
  const prNumber = process.env.BENCH_PR;
  const actor = process.env.BENCH_ACTOR;
  const jobUrl = process.env.BENCH_JOB_URL ||
    `${context.serverUrl}/${repo}/actions/runs/${context.runId}`;
  const chain = process.env.BENCH_CHAIN || 'mainnet';
  const blocks = process.env.BENCH_BLOCKS || '5000';
  const warmup = process.env.BENCH_WARMUP_BLOCKS || '1000';
  const runLabel = replayRunLabel();

  const slackUsers = loadSlackUsers(process.env.GITHUB_WORKSPACE || '.');
  const actorSlackId = slackUsers[actor];
  const { blocks: slackBlocks, threadBlocks } = buildReplaySuccessBlocks({
    summary,
    prNumber,
    actor,
    actorSlackId,
    jobUrl,
    repo,
    chain,
    blocks,
    warmup,
    runLabel,
  });
  const text = `Tempo ${runLabel.toLowerCase()}: ${summary.baseline?.name || 'baseline'} vs ${summary.feature?.name || 'feature'} (${chain})`;

  async function sendWithThread(channel) {
    const res = await postToSlack(token, channel, slackBlocks, text, core);
    if (res.ok && res.ts && threadBlocks.length > 0) {
      for (const threadBlock of threadBlocks) {
        await postToSlack(token, channel, [threadBlock], 'Replay wait time breakdown', core, res.ts);
      }
    }
  }

  const slackMode = process.env.BENCH_SLACK || 'always';
  const channel = process.env.SLACK_BENCH_CHANNEL;
  let postedToChannel = false;
  if (channel && hasImprovement(summary.changes || {})) {
    await sendWithThread(channel);
    postedToChannel = true;
  } else if (channel) {
    core.info('No significant replay improvement, skipping public channel notification');
  }

  if (slackMode === 'on-win') {
    if (!postedToChannel) {
      core.info('on-win mode: no replay improvement detected, skipping all notifications');
    }
    return;
  }

  if (!postedToChannel) {
    if (actorSlackId) {
      await sendWithThread(actorSlackId);
    } else {
      core.info(`No Slack user mapping for GitHub user '${actor}', skipping DM`);
    }
  } else {
    core.info(`Replay results posted to channel, skipping DM to ${actor}`);
  }
}

async function replayFailure({ core, context, failedStep }) {
  const token = process.env.SLACK_BENCH_BOT_TOKEN;
  if (!token) {
    core.info('SLACK_BENCH_BOT_TOKEN not set, skipping replay Slack notification');
    return;
  }

  const repo = `${context.repo.owner}/${context.repo.repo}`;
  const prNumber = process.env.BENCH_PR;
  const actor = process.env.BENCH_ACTOR;
  const jobUrl = process.env.BENCH_JOB_URL ||
    `${context.serverUrl}/${repo}/actions/runs/${context.runId}`;
  const chain = process.env.BENCH_CHAIN || 'mainnet';
  const runLabel = replayRunLabel();

  const slackUsers = loadSlackUsers(process.env.GITHUB_WORKSPACE || '.');
  const actorSlackId = slackUsers[actor];
  const blocks = buildReplayFailureBlocks({ prNumber, actor, actorSlackId, jobUrl, repo, chain, failedStep, runLabel });
  const text = `Tempo ${runLabel.toLowerCase()} failed while ${failedStep}`;

  if (actorSlackId) {
    await postToSlack(token, actorSlackId, blocks, text, core);
  } else {
    core.info(`No Slack user mapping for GitHub user '${actor}', skipping DM`);
  }
}

module.exports = {
  success,
  failure,
  e2e: {
    success,
    failure,
  },
  replay: {
    success: replaySuccess,
    failure: replayFailure,
  },
};
