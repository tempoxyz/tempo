"""Exercise the trusted workflow's publication code without network requests."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

WORKFLOW = yaml.safe_load((Path(__file__).parents[1] / "workflows/zones-prover-benchmark.yml").read_text())
SCRIPT = next(step for step in WORKFLOW["jobs"]["benchmark"]["steps"]
              if step.get("name") == "Publish latency metrics and nightly status")["with"]["script"]


class ReportingTests(unittest.TestCase):
    def run_report(self, *, event="schedule", outcome="success", metrics_status=204, slack_ok=True, missing_metrics=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "results"
            root.mkdir()
            if outcome == "success":
                (root / "comparison.prom").write_text(
                    'tempo_zone_benchmark_latency_seconds{prover="on"} 0.2\n'
                    'tempo_zone_benchmark_completed_timestamp_seconds{comparison="prover"} 1\n')
                latency = {key: dict(p50_ms=100.0, p95_ms=200.0) for key in ("journey", "deposit", "withdrawal")}
                (root / "comparison.json").write_text(json.dumps(dict(
                    metadata=dict(feature="a" * 40, count=20), latencies=dict(baseline=latency, feature=latency))))
            payload = dict(script=SCRIPT, event=event, metricsStatus=metrics_status, slackOk=slack_ok,
                           env=dict(BENCH_RESULTS_PATH=directory, BENCH_OUTCOME=outcome,
                                    BENCH_METRICS_URL="" if missing_metrics else "https://user:p%40ss@metrics.test/insert/0/prometheus/",
                                    SLACK_BENCH_BOT_TOKEN="secret", SLACK_BENCH_CHANNEL="C0B96B0RRMJ", GITHUB_RUN_ATTEMPT="2"))
            result = subprocess.run(["node", "-e", """
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
Object.assign(process.env, input.env);
const calls = [], failures = [];
const context = {eventName: input.event, serverUrl: 'https://github.com',
  repo: {owner: 'tempoxyz', repo: 'tempo'}, runId: 123};
const core = {setFailed: text => failures.push(text), setSecret: () => {}};
const fetch = async (url, request) => {
  calls.push({url: String(url), ...request, signal: undefined});
  return String(url).includes('slack.com')
    ? {ok: true, json: async () => ({ok: input.slackOk})}
    : {ok: input.metricsStatus === 204, status: input.metricsStatus};
};
const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
new AsyncFunction('context', 'core', 'require', 'fetch', input.script)(context, core, require, fetch)
  .then(() => console.log(JSON.stringify({calls, failures})))
  .catch(error => {console.error(error); process.exit(1);});
"""], input=json.dumps(payload), capture_output=True, text=True, check=True)
            return json.loads(result.stdout)

    def test_success_publishes_metrics_and_observed_latency_summary(self):
        result = self.run_report()
        self.assertEqual(result["failures"], [])
        metrics, slack = result["calls"]
        self.assertEqual(metrics["url"], "https://metrics.test/insert/0/prometheus/api/v1/import/prometheus")
        self.assertEqual(metrics["headers"]["Authorization"], "Basic dXNlcjpwQHNz")
        self.assertIn('tempo_zone_benchmark_latency_seconds{run_kind="nightly",', metrics["body"])
        self.assertIn('tempo_zone_benchmark_completed_timestamp_seconds{run_kind="nightly",', metrics["body"])
        message = json.loads(slack["body"])
        self.assertEqual(message["channel"], "C0B96B0RRMJ")
        self.assertIn("/actions/runs/123/attempts/2", message["text"])
        self.assertIn("withdrawal p50/p95 (ms), off → on: 100.0/200.0 → 100.0/200.0", message["text"])

    def test_manual_metrics_do_not_overwrite_nightlies_or_notify(self):
        result = self.run_report(event="workflow_dispatch")
        self.assertEqual(result["failures"], [])
        self.assertEqual(len(result["calls"]), 1)
        self.assertIn('run_kind="manual"', result["calls"][0]["body"])

    def test_failed_benchmark_does_not_import_or_claim_measurements(self):
        result = self.run_report(outcome="failure")
        self.assertEqual(len(result["calls"]), 1)
        message = json.loads(result["calls"][0]["body"])["text"]
        self.assertIn("benchmark failed or did not run", message)
        self.assertNotIn("p50", message)

    def test_metric_failure_still_notifies_and_fails_publication(self):
        for missing in (False, True):
            result = self.run_report(metrics_status=503, missing_metrics=missing)
            self.assertEqual(len(result["failures"]), 1)
            self.assertIn("Grafana metrics publication FAILED", json.loads(result["calls"][-1]["body"])["text"])

    def test_slack_rejection_fails_delivery(self):
        result = self.run_report(slack_ok=False)
        self.assertEqual(result["failures"], ["Nightly Zone Slack delivery failed"])
