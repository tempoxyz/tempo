"""Run with uv run --with pyyaml python -m unittest discover -s .github/scripts -p 'test_zones_*.py'."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

WORKFLOW = yaml.safe_load(
    (Path(__file__).parents[1] / "workflows/zones-prover-benchmark.yml").read_text()
)
SHA = "a" * 40
OTHER_SHA = "b" * 40


HARNESS = """
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
Object.assign(process.env, input.env);
const result = {failures: [], outputs: {}, checked: [], calls: []};
const core = {
  setFailed: message => result.failures.push(message),
  setOutput: (key, value) => result.outputs[key] = value,
  setSecret: () => {},
};
const github = {rest: {
  orgs: {checkMembershipForUser: async ({username}) => {
    result.checked.push(username);
    if (!input.members.includes(username)) throw new Error('Not a member');
  }},
  pulls: {get: async () => ({data: {head: input.head}})},
}};
const fetch = async (url, request) => {
  result.calls.push({url: String(url), ...request, signal: undefined});
  return String(url).includes('slack.com')
    ? {ok: true, json: async () => ({ok: input.slackOk})}
    : {ok: input.metricsStatus === 204, status: input.metricsStatus};
};
const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
new AsyncFunction('github', 'core', 'context', 'require', 'fetch', input.script)(github, core, input.context, require, fetch)
  .then(() => console.log(JSON.stringify(result)))
  .catch(error => { console.error(error); process.exit(1); });
"""


def run_script(job, name, **payload):
    """Run a workflow github-script step against fake GitHub, Actions core, and fetch."""
    step = next(s for s in WORKFLOW["jobs"][job]["steps"] if s.get("name") == name)
    result = subprocess.run(["node", "-e", HARNESS], input=json.dumps({"script": step["with"]["script"], **payload}),
                            text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def run_step(job, name, *, actor="member", triggering_actor="member", members=None,
             body=None, head=SHA, repo="tempoxyz/tempo", event="issue_comment", feature_sha=""):
    return run_script(
        job, name,
        context={"actor": actor, "eventName": event, "sha": SHA,
                 "payload": {"comment": {"body": body if body is not None else f"derek bench {SHA}"}},
                 "issue": {"number": 1507}, "repo": {"owner": "tempoxyz", "repo": "tempo"}},
        members=members if members is not None else ["member", "other-member"],
        head={"sha": head, "repo": {"full_name": repo} if repo else None},
        env={"TRIGGERING_ACTOR": triggering_actor, "FEATURE_SHA": feature_sha},
    )


def run_report(*, event="schedule", outcome="success", metrics_status=204, slack_ok=True, missing_metrics=False):
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
        return run_script(
            "benchmark", "Publish latency metrics and nightly status",
            context={"eventName": event, "serverUrl": "https://github.com",
                     "repo": {"owner": "tempoxyz", "repo": "tempo"}, "runId": 123},
            metricsStatus=metrics_status, slackOk=slack_ok,
            env=dict(BENCH_RESULTS_PATH=directory, BENCH_OUTCOME=outcome,
                     BENCH_METRICS_URL="" if missing_metrics else "https://user:p%40ss@metrics.test/insert/0/prometheus/",
                     SLACK_BENCH_BOT_TOKEN="secret", GITHUB_RUN_ATTEMPT="2"),
        )


class AuthorizationTests(unittest.TestCase):
    def test_membership_in_both_jobs(self):
        for job in ("authorize", "benchmark"):
            for actor, trigger, allowed in (("member", "member", True),
                                            ("member", "other-member", True),
                                            ("member", "outsider", False),
                                            ("outsider", "member", False)):
                with self.subTest(job=job, actor=actor, trigger=trigger):
                    result = run_step(job, "Check org membership", actor=actor, triggering_actor=trigger)
                    self.assertEqual(not result["failures"], allowed)
            self.assertTrue(run_step(job, "Check org membership", members=[])["failures"])

    def test_approved_sha(self):
        for command in (f"derek bench {SHA}", f"derek bench prover {SHA}"):
            result = run_step("authorize", "Resolve PR SHA", body=command)
            self.assertFalse(result["failures"])
            self.assertEqual(result["outputs"], {"feature-sha": SHA, "pr-number": 1507})

    def test_invalid_or_changed_approval(self):
        cases = [{"body": body} for body in ("derek bench", "derek bench prover",
                 "derek bench abc123", f"derek bench {SHA} extra")]
        cases += [{"head": OTHER_SHA}, {"repo": "outsider/zones"}, {"repo": None}]
        for case in cases:
            with self.subTest(case=case):
                result = run_step("authorize", "Resolve PR SHA", **case)
                self.assertTrue(result["failures"])
                self.assertEqual(result["outputs"], {})

    def test_schedule_uses_immutable_event_sha(self):
        result = run_step("authorize", "Resolve PR SHA", event="schedule", feature_sha=OTHER_SHA)
        self.assertEqual(result["outputs"], {"feature-sha": SHA})
        self.assertFalse(result["failures"])

    def test_dispatch(self):
        for sha, allowed in ((SHA, True), ("main", False), ("", False)):
            result = run_step("authorize", "Resolve PR SHA", event="workflow_dispatch", feature_sha=sha)
            self.assertEqual(not result["failures"], allowed)
            self.assertEqual(result["outputs"], {"feature-sha": SHA} if allowed else {})

    def test_benchmark_checks_before_feature_execution(self):
        steps = WORKFLOW["jobs"]["benchmark"]["steps"]
        names = [step.get("name") for step in steps]
        check = names.index("Check org membership")
        for name in ("Mint Earn read token", "Check out feature Tempo with Zones", "Configure AWS benchmark role"):
            self.assertLess(check, names.index(name))
        checkout = steps[names.index("Check out feature Tempo with Zones")]
        self.assertEqual(checkout["with"]["ref"], "${{ needs.authorize.outputs.feature-sha }}")


class ReportingTests(unittest.TestCase):
    def test_success_publishes_metrics_and_observed_latency_summary(self):
        result = run_report()
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
        result = run_report(event="workflow_dispatch")
        self.assertEqual(result["failures"], [])
        self.assertEqual(len(result["calls"]), 1)
        self.assertIn('run_kind="manual"', result["calls"][0]["body"])

    def test_failed_benchmark_does_not_import_or_claim_measurements(self):
        result = run_report(outcome="failure")
        self.assertEqual(len(result["calls"]), 1)
        message = json.loads(result["calls"][0]["body"])["text"]
        self.assertIn("benchmark failed or did not run", message)
        self.assertNotIn("p50", message)

    def test_metric_failure_still_notifies_and_fails_publication(self):
        for missing in (False, True):
            result = run_report(metrics_status=503, missing_metrics=missing)
            self.assertEqual(len(result["failures"]), 1)
            self.assertIn("Grafana metrics publication FAILED", json.loads(result["calls"][-1]["body"])["text"])

    def test_slack_rejection_fails_delivery(self):
        result = run_report(slack_ok=False)
        self.assertEqual(result["failures"], ["Nightly Zone Slack delivery failed"])
