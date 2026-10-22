"""Run with uv run --with pyyaml python -m unittest discover -s .github/scripts -p 'test_zones_*.py'."""

import json
from pathlib import Path
import random
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
  orgs: {checkMembershipForUser: async ({username}) => {
    if (!input.members.includes(username)) throw new Error('Not a member');
  }},
  pulls: {get: async () => ({data: {head: input.head}})},
  issues: {createComment: async ({body}) => { result.comments.push(body); return {data: {id: 1}}; }},
  repos: {
    getCommit: async ({ref}) => ({data: {sha: input.commits[ref]}}),
    compareCommitsWithBasehead: async ({basehead}) => ({data: {merge_base_commit: {sha: input.commits[basehead]}}}),
  },
}};
globalThis.fetch = async (url, request) => {
  result.calls.push({url: String(url), ...request, signal: undefined});
  return {ok: true, json: async () => ({ok: true})};
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


def parse(body):
    return run_script(
        "bench.yml", "tempo-bench-ack", "Parse arguments",
        context={"payload": {"comment": {"body": body, "user": {"login": "member"}}},
                 "issue": {"number": 7}, "repo": {"owner": "tempoxyz", "repo": "tempo"}},
        head={"sha": SHA, "ref": "feature-branch"},
        env={"INPUT_REF_NAME": "main"},
    )


def resolve_refs(head_repo="tempoxyz/tempo", **env):
    return run_script(
        "zones-prover-benchmark.yml", "bench-zones", "Resolve baseline and feature refs",
        context={"sha": OTHER_SHA, "serverUrl": "https://github.com", "runId": 9,
                 "repo": {"owner": "tempoxyz", "repo": "tempo"}},
        head={"repo": {"full_name": head_repo}},
        commits={"main": OTHER_SHA, "release": "c" * 40, f"main...{SHA}": "d" * 40},
        env={"BENCH_PROVER": "true", "BENCH_PRESET": "full-journey"} | env,
    )


def run_with_results(name, files, **payload):
    with tempfile.TemporaryDirectory() as directory:
        results = Path(directory) / "results"
        results.mkdir()
        for file, content in files.items():
            (results / file).parent.mkdir(parents=True, exist_ok=True)
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
        for body, message in (
                ("derek bench prover=false", "`prover` is only supported with `derek bench zones`."),
                ("derek bench zones duration=10", "`duration` is not supported with `derek bench zones`."),
                ("derek bench zones preset=default", "`preset=default` is not a Zone preset.")):
            with self.subTest(body=body):
                result = parse(body)
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

    def test_pr_runs_require_a_pinned_same_repository_head(self):
        for head_repo, env, failure in (
                ("tempoxyz/tempo", {}, "PR benchmarks require the PR head SHA pinned by the ack job"),
                ("someone/tempo", {"INPUT_PR_HEAD_SHA": SHA}, "Zones benchmark PR head must be in tempoxyz/tempo")):
            with self.subTest(head_repo=head_repo):
                result = resolve_refs(head_repo, BENCH_PR="7", **env)
                self.assertEqual(result["failures"], [failure])
                self.assertEqual(result["outputs"], {})


class MembershipTests(unittest.TestCase):
    def test_actor_and_triggering_actor_must_be_members(self):
        for actor, trigger, failures in (("member", "member", []),
                                         ("outsider", "member", ["@outsider must be a tempoxyz member"]),
                                         ("member", "outsider", ["@outsider must be a tempoxyz member"])):
            with self.subTest(actor=actor, trigger=trigger):
                result = run_script("zones-prover-benchmark.yml", "bench-zones", "Check org membership",
                                    context={"actor": actor}, members=["member"], env={"TRIGGERING_ACTOR": trigger})
                self.assertEqual(result["failures"], failures)

    def test_membership_is_checked_before_feature_code_or_aws(self):
        steps = yaml.safe_load((ROOT / ".github/workflows/zones-prover-benchmark.yml").read_text())["jobs"]["bench-zones"]["steps"]
        names = [step.get("name") for step in steps]
        for name in ("Check out feature Tempo with Zones", "Configure AWS benchmark role"):
            self.assertLess(names.index("Check org membership"), names.index(name))


# Run 11 of #8488 (one commit on both sides) moved the deposit p50 by 29.5%. These are its
# traced deposit latencies (ms), which cluster on block timing.
DEPOSIT_MS = [122, 934, 733, 1047, 971, 770, 569, 513, 513, 311]


def traced_report(deposits, withdrawal=2000.0):
    """A txgen report.json tracing every journey, as the classifier reads it."""
    def edge(source, destination, ms):  # The last milestone, not the command finish, ends the edge.
        return [{"id": source, "finished_offset_ms": 0, "milestones": [{"run_offset_ms": 100}]},
                {"id": destination, "finished_offset_ms": 0, "milestones": [{"run_offset_ms": 1}, {"run_offset_ms": 100 + ms}]}]
    return {"completed": len(deposits), "sampled_instances": [
        {"outcome": "completed", "client_observed_e2e_latency_ms": 6000.0 + d,
         "steps": edge("offramp", "offramp_processed", withdrawal) + edge("onramp.zone_before", "onramp.zone_deposit.processed", d)}
        for d in deposits]}


class ReportingTests(unittest.TestCase):
    def test_slack_posts_only_significant_p95_improvements_between_distinct_commits(self):
        actor = next(key for key in json.loads((ROOT / ".github/scripts/bench-slack-users.json").read_text())
                     if not key.startswith("_"))
        env = {"SLACK_BENCH_BOT_TOKEN": "token", "SLACK_BENCH_CHANNEL": "CHANNEL", "BENCH_ACTOR": actor,
               "GITHUB_WORKSPACE": str(ROOT)}
        rows = [{"key": key, "label": key, "end_to_end": key != "sub_leg"} for key in ("withdrawal", "deposit", "journey", "sub_leg")]
        latency = lambda ms: {"p50_ms": ms, "p95_ms": ms}
        base = traced_report(DEPOSIT_MS * 10)
        rng = random.Random(35)  # A draw an unsmoothed bootstrap flags as a change.
        noise = traced_report([rng.choice(DEPOSIT_MS) for _ in range(100)])
        scaled = lambda factor, n=10: traced_report([d * factor for d in DEPOSIT_MS * n])
        for name, baseline, feature, verdict, feature_sha in (
                ("improvement", base, scaled(0.8), "Improvement", SHA),
                ("regression", base, scaled(1.2), "Regression", SHA),
                ("same commit", base, scaled(0.8), "Improvement", OTHER_SHA),
                ("clustered noise", base, noise, "No Significant Change", SHA),
                ("within floor", base, traced_report(DEPOSIT_MS * 10, withdrawal=1970.0), "No Significant Change", SHA),
                ("tight row beyond floor", base, traced_report(DEPOSIT_MS * 10, withdrawal=1900.0), "Improvement", SHA),
                ("under 100 journeys", scaled(1, 2), scaled(0.5, 2), "Unclassified", SHA),
                ("partial traces", base, dict(scaled(0.6), completed=200), "Unclassified", SHA),
                ("missing traces", None, None, "Unclassified", SHA)):
            with self.subTest(name):
                comparison = {"rows": rows, "metadata": {
                    "baseline": OTHER_SHA, "feature": feature_sha, "prover": True, "preset": "full-journey",
                    "tempoHardfork": "t13", "count": 100, "tps": 5, "region": "us-east-1"}, "latencies": {
                    "baseline": {row["key"]: latency(100.0) for row in rows},
                    "feature": {row["key"]: latency(50.0) for row in rows}}}
                files = {"comparison.json": json.dumps(comparison)}
                if baseline:
                    files |= {"baseline/report.json": json.dumps(baseline), "feature/report.json": json.dumps(feature)}
                result = run_with_results("Send Slack notification (success)", files, env=env)
                [call] = result["calls"]
                message = json.loads(call["body"])
                self.assertEqual(message["channel"] == "CHANNEL", verdict == "Improvement" and feature_sha == SHA)
                self.assertIn(verdict, message["blocks"][0]["text"]["text"])
                self.assertEqual(len(result["warnings"]), baseline is None)
                table = [[cell["text"] for cell in row] for row in message["blocks"][2]["rows"]]
                self.assertEqual(table[:2], [["Latency (s)", "base (p50)", "feat (p50)", "change", "base (p95)", "feat (p95)", "change"],
                                             ["withdrawal", "0.100", "0.050", "-50.0%", "0.100", "0.050", "-50.0%"]])
        result = run_with_results("Send Slack notification (success)", {}, env=env)
        self.assertEqual((result["calls"], result["warnings"]),
                         ([], ["Could not read comparison.json for Zones Slack notification"]))


if __name__ == "__main__":
    unittest.main()
