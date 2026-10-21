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


def parse(body, enabled="true"):
    return run_script(
        "bench.yml", "tempo-bench-ack", "Parse arguments",
        context={"payload": {"comment": {"body": body, "user": {"login": "member"}}},
                 "issue": {"number": 7}, "repo": {"owner": "tempoxyz", "repo": "tempo"}},
        head={"sha": SHA, "ref": "feature-branch"},
        env={"ZONES_BENCHMARK_ENABLED": enabled, "INPUT_REF_NAME": "main"},
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
        for name in ("Mint Earn read token", "Check out feature Tempo with Zones", "Configure AWS benchmark role"):
            self.assertLess(names.index("Check org membership"), names.index(name))


class ReportingTests(unittest.TestCase):
    def test_slack_posts_improvements_to_the_channel_and_otherwise_dms(self):
        actor = next(key for key in json.loads((ROOT / ".github/scripts/bench-slack-users.json").read_text())
                     if not key.startswith("_"))
        rows = [{"key": "withdrawal", "label": "Withdrawal: submit → L1 funds", "end_to_end": True},
                {"key": "withdrawal_zone_to_l1", "label": "↳ Zone → L1 processed", "end_to_end": False}]
        latency = lambda ms: {"p50_ms": ms, "p95_ms": ms}
        metadata = {"baseline": OTHER_SHA, "feature": SHA, "prover": True, "preset": "full-journey",
                    "tempoHardfork": "t13", "count": 20, "tps": 5, "region": "us-east-1"}
        env = {"SLACK_BENCH_BOT_TOKEN": "token", "SLACK_BENCH_CHANNEL": "CHANNEL", "BENCH_ACTOR": actor,
               "GITHUB_WORKSPACE": str(ROOT)}
        # Only end-to-end rows gate the channel post; a faster sub-leg alone is informational.
        for end_to_end_ms, sub_leg_ms, destination, verdict in ((50.0, 100.0, "CHANNEL", "Improvement"),
                                                                 (100.0, 50.0, "DM", "No Significant Change"),
                                                                 (100.0, 100.0, "DM", "No Significant Change")):
            with self.subTest(end_to_end_ms=end_to_end_ms, sub_leg_ms=sub_leg_ms):
                comparison = {"metadata": metadata, "rows": rows, "latencies": {
                    "baseline": {"withdrawal": latency(100.0), "withdrawal_zone_to_l1": latency(100.0)},
                    "feature": {"withdrawal": latency(end_to_end_ms), "withdrawal_zone_to_l1": latency(sub_leg_ms)}}}
                result = run_with_results("Send Slack notification (success)", {"comparison.json": json.dumps(comparison)},
                                          env=env)
                [call] = result["calls"]
                message = json.loads(call["body"])
                self.assertEqual(message["channel"] == "CHANNEL", destination == "CHANNEL")
                self.assertIn(verdict, message["blocks"][0]["text"]["text"])
                table = [[cell["text"] for cell in row] for row in message["blocks"][2]["rows"]]
                self.assertEqual(table[1][:3], ["Withdrawal: submit → L1 funds", "100 | 100", f"{end_to_end_ms:.0f} | {end_to_end_ms:.0f}"])
        result = run_with_results("Send Slack notification (success)", {}, env=env)
        self.assertEqual((result["calls"], result["warnings"]),
                         ([], ["Could not read comparison.json for Zones Slack notification"]))


if __name__ == "__main__":
    unittest.main()
