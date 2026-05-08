// Sends Slack notifications for replay benchmark results.
//
// Reads from environment:
//   SLACK_BENCH_BOT_TOKEN  - Slack Bot User OAuth Token (xoxb-...)
//   SLACK_BENCH_CHANNEL    - Public channel ID for results
//   BENCH_WORK_DIR         - Directory containing summary.json
//   BENCH_CHAIN            - Replay chain name
//   BENCH_BLOCKS           - Number of replay blocks
//   BENCH_WARMUP_BLOCKS    - Number of warmup blocks
//   BENCH_SLACK            - Notification policy: always, on-win, on-error, never
//   BENCH_JOB_URL          - URL to the Actions job page

const fs = require('fs');

const SLACK_API = 'https://slack.com/api/chat.postMessage';
const SIG_EMOJI = {
  good: ':white_check_mark:',
  bad: ':x:',
  neutral: ':white_circle:',
};

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
  return { type: 'raw_text', text: String(text == null || text === '' ? ' ' : text) };
}

function numberOrNull(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function fmt(v, precision = 2, suffix = '') {
  const n = numberOrNull(v);
  return n == null ? '-' : `${n.toFixed(precision)}${suffix}`;
}

function fmtMs(v) {
  return fmt(v, 2, 'ms');
}

function fmtMgas(v) {
  return fmt(v, 2);
}

function fmtS(v) {
  return fmt(v, 2, 's');
}

function fmtChange(ch) {
  if (!ch) return '';
  const pct = numberOrNull(ch.pct) || 0;
  const ciPct = numberOrNull(ch.ci_pct) || 0;
  const sign = pct >= 0 ? '+' : '';
  const ci = ciPct ? ` (+/-${ciPct.toFixed(2)}%)` : '';
  const emoji = SIG_EMOJI[ch.sig] || '';
  return `${sign}${pct.toFixed(2)}%${ci} ${emoji}`.trim();
}

function verdict(changes) {
  const vals = Object.values(changes || {});
  const hasBad = vals.some(v => v.sig === 'bad');
  const hasGood = vals.some(v => v.sig === 'good');
  if (hasBad && hasGood) return { emoji: ':warning:', label: 'Mixed Results' };
  if (hasBad) return { emoji: ':x:', label: 'Regression' };
  if (hasGood) return { emoji: ':white_check_mark:', label: 'Improvement' };
  return { emoji: ':white_circle:', label: 'No Difference' };
}

function hasImprovement(changes) {
  return Object.values(changes || {}).some(v => v.sig === 'good');
}

function repoLink(repo) {
  return `<https://github.com/${repo}|Tempo>`;
}

function shortRef(ref) {
  if (!ref) return 'unknown';
  return /^[0-9a-f]{40}$/i.test(ref) ? ref.slice(0, 8) : ref;
}

function refLink(repo, ref, name) {
  const label = name || shortRef(ref);
  if (!ref || ref === 'unknown') return label;
  return `<https://github.com/${repo}/commit/${ref}|${label}>`;
}

function metricRows(summary) {
  const baseline = summary.baseline?.stats || {};
  const feature = summary.feature?.stats || {};
  const changes = summary.changes || {};

  return [
    { label: 'newPayload Mean', baseline: fmtMs(baseline.mean_ms), feature: fmtMs(feature.mean_ms), change: fmtChange(changes.mean) },
    { label: 'newPayload StdDev', baseline: fmtMs(baseline.stddev_ms), feature: fmtMs(feature.stddev_ms), change: '' },
    { label: 'newPayload P50', baseline: fmtMs(baseline.p50_ms), feature: fmtMs(feature.p50_ms), change: fmtChange(changes.p50) },
    { label: 'newPayload P90', baseline: fmtMs(baseline.p90_ms), feature: fmtMs(feature.p90_ms), change: fmtChange(changes.p90) },
    { label: 'newPayload P99', baseline: fmtMs(baseline.p99_ms), feature: fmtMs(feature.p99_ms), change: fmtChange(changes.p99) },
    { label: 'Mgas/s', baseline: fmtMgas(baseline.mean_mgas_s), feature: fmtMgas(feature.mean_mgas_s), change: fmtChange(changes.mgas_s) },
    { label: 'Wall Clock', baseline: fmtS(baseline.wall_clock_s), feature: fmtS(feature.wall_clock_s), change: fmtChange(changes.wall_clock) },
    { label: 'Persist Wait', baseline: fmtMs(baseline.mean_persist_ms || 0), feature: fmtMs(feature.mean_persist_ms || 0), change: fmtChange(changes.persist_wait) },
  ];
}

function waitTimeRows(summary) {
  const waitTimes = summary.wait_times || {};
  return Object.values(waitTimes).map(wt => ({
    title: wt.title,
    baseline: fmtMs(wt.baseline?.mean_ms),
    feature: fmtMs(wt.feature?.mean_ms),
  }));
}

function buildSuccessBlocks({ summary, repo, jobUrl, chain, blocks, warmup }) {
  const { emoji, label } = verdict(summary.changes || {});
  const baseline = summary.baseline || {};
  const feature = summary.feature || {};
  const commitUrl = `https://github.com/${repo}/compare/${baseline.ref || ''}...${feature.ref || ''}`;
  const blockCount = summary.blocks || blocks || '-';
  const warmupCount = summary.warmup_blocks || warmup || '-';

  const sectionText = [
    `*Repo:* ${repoLink(repo)}`,
    `*Chain:* \`${chain || '-'}\` | *Warmup:* \`${warmupCount}\` | *Blocks:* \`${blockCount}\``,
    '',
    `*Baseline:* ${refLink(repo, baseline.ref, baseline.name)}`,
    `*Feature:* ${refLink(repo, feature.ref, feature.name)}`,
  ].join('\n');

  const rows = metricRows(summary);
  const tableRows = [
    [cell('Metric'), cell('Baseline'), cell('Feature'), cell('Change')],
    ...rows.map(row => [cell(row.label), cell(row.baseline), cell(row.feature), cell(row.change || ' ')]),
  ];

  return [
    {
      type: 'header',
      text: { type: 'plain_text', text: `${emoji} Tempo Replay Nightly: ${label}`, emoji: true },
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
          url: commitUrl,
          action_id: 'diff_button',
        },
      ],
    },
  ];
}

function buildFailureBlocks({ repo, jobUrl, chain, actor, failedStep }) {
  const parts = [
    `*Repo:* ${repoLink(repo)}`,
    `*Chain:* \`${chain || '-'}\``,
    actor ? `*Actor:* \`${actor}\`` : '',
    `failed while *${failedStep || 'unknown step'}*`,
  ].filter(Boolean);

  return [
    {
      type: 'header',
      text: { type: 'plain_text', text: ':rotating_light: Tempo Replay Nightly Failed', emoji: true },
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: parts.join('\n') },
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
  const channel = process.env.SLACK_BENCH_CHANNEL;
  if (!token || !channel) {
    core.info('Slack credentials not set, skipping replay notification');
    return;
  }

  const slackMode = process.env.BENCH_SLACK || 'never';
  if (slackMode === 'never' || slackMode === 'on-error') {
    core.info(`${slackMode} mode: skipping replay success notification`);
    return;
  }

  let summary;
  try {
    summary = JSON.parse(fs.readFileSync(`${process.env.BENCH_WORK_DIR}/summary.json`, 'utf8'));
  } catch (e) {
    core.warning('Could not read summary.json for replay Slack notification');
    return;
  }

  if (slackMode === 'on-win' && !hasImprovement(summary.changes || {})) {
    core.info('on-win mode: no replay improvement detected, skipping Slack notification');
    return;
  }

  const repo = `${context.repo.owner}/${context.repo.repo}`;
  const jobUrl = process.env.BENCH_JOB_URL || `${context.serverUrl}/${repo}/actions/runs/${context.runId}`;
  const chain = process.env.BENCH_CHAIN || 'mainnet';
  const blocks = process.env.BENCH_BLOCKS || '5000';
  const warmup = process.env.BENCH_WARMUP_BLOCKS || '1000';
  const slackBlocks = buildSuccessBlocks({ summary, repo, jobUrl, chain, blocks, warmup });
  const text = `Tempo replay nightly: ${summary.baseline?.name || 'baseline'} vs ${summary.feature?.name || 'feature'} (${chain})`;

  const data = await postToSlack(token, channel, slackBlocks, text, core);
  const wtRows = waitTimeRows(summary);
  if (data.ts && wtRows.length > 0) {
    const waitTableRows = [
      [cell('Wait Time'), cell('Baseline'), cell('Feature')],
      ...wtRows.map(row => [cell(row.title), cell(row.baseline), cell(row.feature)]),
    ];
    await postToSlack(token, channel, [{
      type: 'table',
      column_settings: [{ align: 'left' }, { align: 'right' }, { align: 'right' }],
      rows: waitTableRows,
    }], 'Replay wait time breakdown', core, data.ts);
  }
}

async function failure({ core, context, failedStep }) {
  const token = process.env.SLACK_BENCH_BOT_TOKEN;
  const channel = process.env.SLACK_BENCH_CHANNEL;
  if (!token || !channel) {
    core.info('Slack credentials not set, skipping replay failure notification');
    return;
  }

  const slackMode = process.env.BENCH_SLACK || 'never';
  if (slackMode === 'never' || slackMode === 'on-win') {
    core.info(`${slackMode} mode: skipping replay failure notification`);
    return;
  }

  const repo = `${context.repo.owner}/${context.repo.repo}`;
  const jobUrl = process.env.BENCH_JOB_URL || `${context.serverUrl}/${repo}/actions/runs/${context.runId}`;
  const chain = process.env.BENCH_CHAIN || 'mainnet';
  const actor = process.env.BENCH_ACTOR;
  const blocks = buildFailureBlocks({ repo, jobUrl, chain, actor, failedStep });
  const text = `Tempo replay nightly failed while ${failedStep || 'unknown step'} (${chain})`;

  await postToSlack(token, channel, blocks, text, core);
}

module.exports = {
  success,
  failure,
};
