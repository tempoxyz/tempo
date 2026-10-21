"""Run with uv run --with pyyaml python -m unittest discover -s .github/scripts -p 'test_zones_*.py'."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 40
OTHER_SHA = "b" * 40

HARNESS = """
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
Object.assign(process.env, input.env);
const result = {failures: [], outputs: {}, exported: {}, comments: [], calls: [], warnings: []};
const core = {
  setFailed: message => result.failures.push(message),
  setOutput: (key, value) => result.outputs[key] = value,
  exportVariable: (key, value) => result.exported[key] = value,
  setSecret: () => {},
  info: () => {},
  warning: message => result.warnings.push(message),
};
const github = {rest: {
  pulls: {get: async () => ({data: {head: input.head}})},
  issues: {createComment: async ({body}) => { result.comments.push(body); return {data: {id: 1}}; }},
  repos: {
    getCommit: async ({ref}) => ({data: {sha: input.commits[ref]}}),
    compareCommitsWithBasehead: async ({basehead}) => ({data: {merge_base_commit: {sha: input.commits[basehead]}}}),
  },
}};
globalThis.fetch = async (url, request) => {
  result.calls.push({url: String(url), ...request, signal: undefined});
  return String(url).includes('slack.com')
    ? {ok: true, json: async () => ({ok: true})}
    : {ok: input.metricsStatus === 204, status: input.metricsStatus};
};
const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
new AsyncFunction('github', 'core', 'context', 'require', input.script)(github, core, input.context, require)
  .then(() => console.log(JSON.stringify(result)))
  .catch(error => { console.error(error); process.exit(1); });
"""


def run_script(workflow, job, name, **payload):
    """Run a workflow github-script step from the repository root against fake GitHub, core, and fetch."""
    steps = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())["jobs"][job]["steps"]
    step = next(s for s in steps if s.get("name") == name)
    result = subprocess.run(["node", "-e", HARNESS], input=json.dumps({"script": step["with"]["script"], **payload}),
                            text=True, capture_output=True, check=True, cwd=ROOT)
    return json.loads(result.stdout)


def parse(body, enabled="true"):
    return run_script(
        "bench.yml", "tempo-bench-ack", "Parse arguments",
        context={"payload": {"comment": {"body": body, "user": {"login": "member"}}},
                 "issue": {"number": 7}, "repo": {"owner": "tempoxyz", "repo": "tempo"}},
        head={"sha": SHA, "ref": "feature-branch"},
        env={"ZONES_BENCHMARK_ENABLED": enabled, "INPUT_REF_NAME": "main"},
    )


def resolve_refs(**env):
    return run_script(
        "zones-prover-benchmark.yml", "bench-zones", "Resolve baseline and feature refs",
        context={"sha": OTHER_SHA, "serverUrl": "https://github.com", "runId": 9,
                 "repo": {"owner": "tempoxyz", "repo": "tempo"}},
        commits={"main": OTHER_SHA, "release": "c" * 40, f"main...{SHA}": "d" * 40},
        env={"BENCH_PROVER": "true", "BENCH_PRESET": "full-journey"} | env,
    )


def run_with_results(name, files, **payload):
    with tempfile.TemporaryDirectory() as directory:
        results = Path(directory) / "results"
        results.mkdir()
        for file, content in files.items():
            (results / file).write_text(content)
        payload["env"] = {"BENCH_RESULTS_PATH": directory, "BENCH_WORK_DIR": str(results)} | payload.get("env", {})
        return run_script("zones-prover-benchmark.yml", "bench-zones", name,
                          context={"repo": {"owner": "tempoxyz", "repo": "tempo"}, "serverUrl": "https://github.com",
                                   "runId": 9}, **payload)


class BenchCommandTests(unittest.TestCase):
    def test_zones_command_defaults_to_prover_on_full_journey(self):
        for body, prover, preset in (("derek bench zones", "true", "full-journey"),
                                     ("derek bench zones prover=false preset=private-withdrawal", "false", "private-withdrawal")):
            with self.subTest(body=body):
                result = parse(body)
                self.assertEqual(result["failures"], [])
                self.assertEqual({key: result["outputs"][key] for key in ("mode", "prover", "preset", "pr-head-sha")},
                                 {"mode": "zones", "prover": prover, "preset": preset, "pr-head-sha": SHA})

    def test_rejects_prover_and_unsupported_arguments(self):
        for body, enabled, message in (
                ("derek bench prover=false", "true", "`prover` is only supported with `derek bench zones`."),
                ("derek bench zones duration=10", "true", "`duration` is not supported with `derek bench zones`."),
                ("derek bench zones preset=default", "true", "`preset=default` is not a Zone preset."),
                ("derek bench zones", "false", "Zone benchmarks are not enabled in this repository.")):
            with self.subTest(body=body, enabled=enabled):
                result = parse(body, enabled)
                self.assertEqual(len(result["failures"]), 1)
                self.assertIn(message, result["failures"][0])
                self.assertEqual(result["comments"], result["failures"])


class RefTests(unittest.TestCase):
    def test_baseline_and_feature_resolution(self):
        for env, baseline, feature, names in (
                ({"BENCH_PR": "7", "INPUT_PR_HEAD_SHA": SHA}, "d" * 40, SHA, ("merge-base", SHA[:8])),
                ({"BENCH_PR": "7", "INPUT_PR_HEAD_SHA": SHA, "INPUT_BASELINE": "main", "INPUT_FEATURE": "release"},
                 OTHER_SHA, "c" * 40, ("main", "release")),
                ({"INPUT_BASELINE": "release", "INPUT_FEATURE": "main"}, "c" * 40, OTHER_SHA, ("release", "main")),
                ({"INPUT_BASELINE": "release", "INPUT_FEATURE": "main", "INPUT_BASELINE_NAME": "nightly-c",
                  "INPUT_FEATURE_NAME": "nightly-b"}, "c" * 40, OTHER_SHA, ("nightly-c", "nightly-b")),
                ({}, OTHER_SHA, OTHER_SHA, ("main", OTHER_SHA[:8]))):
            with self.subTest(env=env):
                result = resolve_refs(**env)
                self.assertEqual(result["failures"], [])
                self.assertEqual(result["outputs"], {"baseline-sha": baseline, "feature-sha": feature})
                self.assertEqual((result["exported"]["BENCH_BASELINE_NAME"], result["exported"]["BENCH_FEATURE_NAME"]), names)

    def test_pr_runs_require_the_pinned_head(self):
        result = resolve_refs(BENCH_PR="7")
        self.assertEqual(result["failures"], ["PR benchmarks require the PR head SHA pinned by the ack job"])
        self.assertEqual(result["outputs"], {})


class ReportingTests(unittest.TestCase):
    PROM = 'tempo_zone_benchmark_latency_seconds{prover="on"} 0.2\n'

    def publish(self, files, status=204, url="https://user:p%40ss@metrics.test/insert/0/prometheus/"):
        return run_with_results("Publish latency metrics", files, metricsStatus=status,
                                env={"BENCH_METRICS_URL": url, "BENCH_RUN_KIND": "nightly"})

    def test_publishes_labelled_latency(self):
        result = self.publish({"comparison.prom": self.PROM})
        self.assertEqual(result["failures"], [])
        [call] = result["calls"]
        self.assertEqual(call["url"], "https://metrics.test/insert/0/prometheus/api/v1/import/prometheus")
        self.assertEqual(call["headers"]["Authorization"], "Basic dXNlcjpwQHNz")
        self.assertEqual(call["body"], 'tempo_zone_benchmark_latency_seconds{run_kind="nightly",prover="on"} 0.2\n')

    def test_skips_runs_without_latency_and_fails_on_publication_errors(self):
        self.assertEqual(self.publish({})["calls"], [])
        for status, url in ((503, "https://metrics.test/"), (204, "")):
            with self.subTest(status=status, url=url):
                result = self.publish({"comparison.prom": self.PROM}, status, url)
                self.assertEqual(result["failures"],
                                 ["Zone latency metrics publication failed; comparison evidence remains in the artifact"])

    def test_slack_posts_improvements_to_the_channel_and_otherwise_dms(self):
        actor = next(key for key in json.loads((ROOT / ".github/scripts/bench-slack-users.json").read_text())
                     if not key.startswith("_"))
        latency = lambda ms: {name: {"p50_ms": ms, "p95_ms": ms} for name in ("journey", "deposit", "withdrawal")}
        metadata = {"baseline": OTHER_SHA, "feature": SHA, "prover": True, "preset": "full-journey",
                    "tempoHardfork": "t13", "count": 20, "tps": 5, "region": "us-east-1"}
        env = {"SLACK_BENCH_BOT_TOKEN": "token", "SLACK_BENCH_CHANNEL": "CHANNEL", "BENCH_ACTOR": actor,
               "GITHUB_WORKSPACE": str(ROOT)}
        for feature_ms, destination in ((50.0, "CHANNEL"), (100.0, "DM")):
            with self.subTest(feature_ms=feature_ms):
                comparison = {"metadata": metadata, "latencies": {"baseline": latency(100.0), "feature": latency(feature_ms)}}
                result = run_with_results("Send Slack notification (success)", {"comparison.json": json.dumps(comparison)},
                                          env=env)
                [call] = result["calls"]
                message = json.loads(call["body"])
                self.assertEqual(message["channel"] == "CHANNEL", destination == "CHANNEL")
                self.assertIn("Improvement" if destination == "CHANNEL" else "No Significant Change",
                              message["blocks"][0]["text"]["text"])
        result = run_with_results("Send Slack notification (success)", {}, env=env)
        self.assertEqual((result["calls"], result["warnings"]),
                         ([], ["Could not read comparison.json for Zones Slack notification"]))


if __name__ == "__main__":
    unittest.main()
