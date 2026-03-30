// Sends Slack notifications for tempo-bench results.
//
// Reads from environment:
//   SLACK_BENCH_BOT_TOKEN  – Slack Bot User OAuth Token (xoxb-...)
//   SLACK_BENCH_CHANNEL    – Public channel ID for results
//   BENCH_WORK_DIR         – Directory containing summary.json
//   BENCH_PR               – PR number (may be empty)
//   BENCH_ACTOR            – GitHub user who triggered the bench
//   BENCH_JOB_URL          – URL to the Actions job page
//
// Usage from actions/github-script:
//   const notify = require('./.github/scripts/bench-slack-notify.js');
//   await notify.success({ core, context });
//   await notify.failure({ core, context, failedStep: '...' });

const fs = require('fs');
const path = require('path');

const SLACK_API = 'https://slack.com/api/chat.postMessage';

// Significance thresholds (percentage change)
const THRESHOLD_PCT = 5;

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

function tempoBlockTimeDeltas(deltas) {
  return [deltas.block_time_p50, deltas.block_time_p90, deltas.block_time_p99];
}

function tempoThroughputDeltas(deltas) {
  return [deltas.tps, deltas.tps_p50, deltas.tps_p90, deltas.tps_p99, deltas.mgas_s];
}

function fmtDelta(pct) {
  if (pct == null) return '';
  const sign = pct >= 0 ? '+' : '';
  const emoji = classifyDelta(pct);
  return `${sign}${pct.toFixed(2)}% ${emoji}`;
}

// For latency: negative = good (faster), positive = bad (slower)
function classifyDelta(pct) {
  if (Math.abs(pct) < THRESHOLD_PCT) return '⚪';
  return pct < 0 ? '✅' : '❌';
}

// For throughput: positive = good (more tps/mgas), negative = bad
function classifyDeltaInverse(pct) {
  if (Math.abs(pct) < THRESHOLD_PCT) return '⚪';
  return pct > 0 ? '✅' : '❌';
}

function fmtDeltaInverse(pct) {
  if (pct == null) return '';
  const sign = pct >= 0 ? '+' : '';
  const emoji = classifyDeltaInverse(pct);
  return `${sign}${pct.toFixed(2)}% ${emoji}`;
}

function verdict(deltas) {
  const blockTimeDeltas = tempoBlockTimeDeltas(deltas);
  const throughputDeltas = tempoThroughputDeltas(deltas);

  const hasBad = blockTimeDeltas.some(d => d != null && d > THRESHOLD_PCT) ||
                 throughputDeltas.some(d => d != null && d < -THRESHOLD_PCT);
  const hasGood = blockTimeDeltas.some(d => d != null && d < -THRESHOLD_PCT) ||
                  throughputDeltas.some(d => d != null && d > THRESHOLD_PCT);

  if (hasBad && hasGood) return { emoji: ':warning:', label: 'Mixed Results' };
  if (hasBad) return { emoji: ':x:', label: 'Regression' };
  if (hasGood) return { emoji: ':white_check_mark:', label: 'Improvement' };
  return { emoji: ':white_circle:', label: 'No Significant Change' };
}

function hasSignificantChange(deltas) {
  const all = [...tempoThroughputDeltas(deltas), ...tempoBlockTimeDeltas(deltas)];
  return all.some(d => d != null && Math.abs(d) >= THRESHOLD_PCT);
}

function refLink(commitUrl, sha, refName, fallbackLabel) {
  const label = refName || fallbackLabel;
  return sha ? `<${commitUrl}/${sha}|${label}>` : label;
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
  return [
    { label: 'Avg TPS',         baseline: fmtVal(b.tps, '', 0),     feature: fmtVal(f.tps, '', 0),     change: fmtDeltaInverse(d.tps) },
    { label: 'TPS P50',         baseline: fmtVal(b.tps_p50, '', 1), feature: fmtVal(f.tps_p50, '', 1), change: fmtDeltaInverse(d.tps_p50) },
    { label: 'TPS P90',         baseline: fmtVal(b.tps_p90, '', 1), feature: fmtVal(f.tps_p90, '', 1), change: fmtDeltaInverse(d.tps_p90) },
    { label: 'TPS P99',         baseline: fmtVal(b.tps_p99, '', 1), feature: fmtVal(f.tps_p99, '', 1), change: fmtDeltaInverse(d.tps_p99) },
    { label: 'Gas/s',           baseline: fmtVal(b.mgas_s, ' Mgas/s', 1), feature: fmtVal(f.mgas_s, ' Mgas/s', 1), change: fmtDeltaInverse(d.mgas_s) },
    { label: 'Block P50',       baseline: fmtMs(b.block_time_p50),  feature: fmtMs(f.block_time_p50),  change: fmtDelta(d.block_time_p50) },
    { label: 'Block P90',       baseline: fmtMs(b.block_time_p90),  feature: fmtMs(f.block_time_p90),  change: fmtDelta(d.block_time_p90) },
    { label: 'Block P99',       baseline: fmtMs(b.block_time_p99),  feature: fmtMs(f.block_time_p99),  change: fmtDelta(d.block_time_p99) },
  ];
}

function buildSuccessBlocks({ summary, prNumber, actor, actorSlackId, jobUrl, repo }) {
  const b = summary.results.baseline;
  const f = summary.results.feature;
  const d = summary.results.deltas;
  const { emoji, label } = verdict(d);

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
    metaParts.join(' | '),
    '',
    `*Baseline:* ${baselineLink}`,
    `*Feature:* ${featureLink}`,
    '',
    `*Preset:* \`${config.preset}\` | *Bloat:* \`${config.bloat} MiB\``,
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

  const deltas = summary.results.deltas;
  const channel = process.env.SLACK_BENCH_CHANNEL;
  let postedToChannel = false;

  // Post to public channel if any metric shows significant change
  if (channel && hasSignificantChange(deltas)) {
    await postToSlack(token, channel, blocks, text, core);
    postedToChannel = true;
  } else if (channel) {
    core.info('No significant change, skipping public channel notification');
  }

  // DM the actor when results were not posted to the public channel
  if (!postedToChannel) {
    if (actorSlackId) {
      await postToSlack(token, actorSlackId, blocks, text, core);
    } else {
      core.info(`No Slack user mapping for GitHub user '${actor}', skipping DM`);
    }
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

module.exports = { success, failure };
