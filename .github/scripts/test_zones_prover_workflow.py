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
        for name in ("Mint Earn read token", "Check out feature Tempo with Zones", "Configure AWS benchmark role"):
            self.assertLess(names.index("Check org membership"), names.index(name))


# Run 11 of #8488 (one commit on both sides): the deposit p50 moved 29.5% between phases.
# These are its feature phase's traced deposit latencies (ms), which cluster on block timing.
DEPOSIT_MS = [122, 934, 733, 1047, 971, 770, 569, 513, 513, 311]


def traced_report(journeys):
    """A txgen report.json tracing every journey; each journey maps row key -> latency in ms."""
    instances = []
    for index, journey in enumerate(journeys):
        steps = [{"id": "start", "finished_offset_ms": 0, "milestones": []}]
        for key, (source, destination) in (("withdrawal", ("offramp", "offramp_processed")),
                                           ("deposit", ("onramp.zone_before", "onramp.zone_deposit.processed"))):
            steps.append({"id": source, "finished_offset_ms": 999_999, "milestones": [{"kind": "submit", "run_offset_ms": 100}]})
            # The last milestone, not the step's command finish, is the edge's endpoint.
            steps.append({"id": destination, "depends_on": [source], "finished_offset_ms": 999_999,
                          "milestones": [{"kind": "included", "run_offset_ms": 1},
                                         {"kind": "observed", "run_offset_ms": 100 + journey[key]}]})
        instances.append({"instance": index, "outcome": "completed",
                          "client_observed_e2e_latency_ms": journey["journey"], "steps": steps})
    return {"completed": len(journeys), "sampled_instances": instances}


def classify(rows, baseline, feature):
    script = ("const c = require('./.github/scripts/bench-zones-classify.js');"
              "const i = JSON.parse(require('fs').readFileSync(0, 'utf8'));"
              "console.log(JSON.stringify(c.classify({rows: i.rows}, i.reports)));")
    result = subprocess.run(["node", "-e", script], input=json.dumps({"rows": rows, "reports": {
        "baseline": baseline, "feature": feature}}), text=True, capture_output=True, check=True, cwd=ROOT)
    return json.loads(result.stdout)


ROWS = [{"key": "withdrawal", "label": "Withdrawal: submit → L1 funds", "end_to_end": True},
        {"key": "deposit", "label": "Deposit: submit → zone credited", "end_to_end": True},
        {"key": "journey", "label": "Full private journey", "end_to_end": True}]


def journeys(deposits, withdrawal=2000.0, journey=None):
    return [{"deposit": d, "withdrawal": withdrawal, "journey": journey or 6000.0 + d} for d in deposits]


class ClassifyTests(unittest.TestCase):
    def test_same_commit_noise_is_not_significant(self):
        # Two draws of 100 journeys from run 11's clustered deposit latencies.
        rng = random.Random(1)
        baseline, feature = (journeys([rng.choice(DEPOSIT_MS) for _ in range(100)]) for _ in range(2))
        changes = classify(ROWS, traced_report(baseline), traced_report(feature))
        self.assertEqual({key: change["sig"] for key, change in changes.items()},
                         {"withdrawal": "neutral", "deposit": "neutral", "journey": "neutral"})

    def test_p95_change_beyond_ci_and_floor_is_classified(self):
        baseline = journeys(DEPOSIT_MS * 10)
        for factor, sig in ((0.8, "good"), (1.2, "bad"), (0.99, "neutral")):
            with self.subTest(factor=factor):
                feature = journeys([d * factor for d in DEPOSIT_MS * 10])
                change = classify(ROWS, traced_report(baseline), traced_report(feature))["deposit"]
                self.assertEqual(change["sig"], sig)
                self.assertAlmostEqual(change["pct"], (factor - 1) * 100)

    def test_tight_rows_need_more_than_the_floor(self):
        baseline = journeys(DEPOSIT_MS * 10, withdrawal=2000.0)
        for withdrawal, sig in ((1970.0, "neutral"), (1900.0, "good")):
            with self.subTest(withdrawal=withdrawal):
                feature = journeys(DEPOSIT_MS * 10, withdrawal=withdrawal)
                self.assertEqual(classify(ROWS, traced_report(baseline), traced_report(feature))["withdrawal"]["sig"], sig)

    def test_sub_legs_small_runs_and_partial_traces_are_informational(self):
        rows = ROWS + [{"key": "withdrawal_zone_to_l1", "label": "> zone → L1 processed", "end_to_end": False}]
        full = traced_report(journeys(DEPOSIT_MS * 10))
        partial = dict(full, sampled_instances=full["sampled_instances"][:10])
        small = traced_report(journeys([d * 0.5 for d in DEPOSIT_MS * 2]))
        for name, baseline, feature in (("partial", partial, full), ("20 journeys", traced_report(journeys(DEPOSIT_MS * 2)), small)):
            with self.subTest(name):
                changes = classify(rows, baseline, feature)
                self.assertTrue(all(change["informational"] and change["pct"] is None for change in changes.values()))


class ReportingTests(unittest.TestCase):
    def test_slack_posts_significant_improvements_to_the_channel_and_otherwise_dms(self):
        actor = next(key for key in json.loads((ROOT / ".github/scripts/bench-slack-users.json").read_text())
                     if not key.startswith("_"))
        rows = ROWS + [{"key": "withdrawal_zone_to_l1", "label": "> zone → L1 processed", "end_to_end": False}]
        latency = lambda ms: {"p50_ms": ms, "p95_ms": ms}
        env = {"SLACK_BENCH_BOT_TOKEN": "token", "SLACK_BENCH_CHANNEL": "CHANNEL", "BENCH_ACTOR": actor,
               "GITHUB_WORKSPACE": str(ROOT)}
        baseline = journeys(DEPOSIT_MS * 10)
        faster = journeys([d * 0.6 for d in DEPOSIT_MS * 10])
        # A faster mean posts only between different commits; noise and self-comparisons DM the actor.
        for name, feature_sha, feature, destination, verdict in (
                ("improvement", SHA, faster, "CHANNEL", "Improvement"),
                ("same commit", OTHER_SHA, faster, "DM", "Improvement"),
                ("no change", SHA, baseline, "DM", "No Significant Change")):
            with self.subTest(name):
                metadata = {"baseline": OTHER_SHA, "feature": feature_sha, "prover": True, "preset": "full-journey",
                            "tempoHardfork": "t13", "count": 20, "tps": 5, "region": "us-east-1"}
                comparison = {"metadata": metadata, "rows": rows, "latencies": {
                    phase: {row["key"]: latency(100.0) for row in rows} | {"journey": latency(7121.0)}
                    for phase in ("baseline", "feature")}}
                result = run_with_results("Send Slack notification (success)", {
                    "comparison.json": json.dumps(comparison),
                    "baseline/report.json": json.dumps(traced_report(baseline)),
                    "feature/report.json": json.dumps(traced_report(feature))}, env=env)
                [call] = result["calls"]
                message = json.loads(call["body"])
                self.assertEqual(message["channel"] == "CHANNEL", destination == "CHANNEL")
                self.assertIn(verdict, message["blocks"][0]["text"]["text"])
                table = [[cell["text"] for cell in row] for row in message["blocks"][2]["rows"]]
                self.assertEqual(table[0], ["Latency (s)", "base (p50)", "feat (p50)", "change", "base (p95)", "feat (p95)", "change"])
                self.assertEqual(table[3], ["Full private journey", "7.121", "7.121", "+0.0%", "7.121", "7.121", "+0.0%"])

    def test_missing_traces_dm_without_a_verdict(self):
        actor = next(key for key in json.loads((ROOT / ".github/scripts/bench-slack-users.json").read_text())
                     if not key.startswith("_"))
        env = {"SLACK_BENCH_BOT_TOKEN": "token", "SLACK_BENCH_CHANNEL": "CHANNEL", "BENCH_ACTOR": actor,
               "GITHUB_WORKSPACE": str(ROOT)}
        metadata = {"baseline": OTHER_SHA, "feature": SHA, "prover": True, "preset": "full-journey",
                    "tempoHardfork": "t13", "count": 20, "tps": 5, "region": "us-east-1"}
        comparison = {"metadata": metadata, "rows": ROWS, "latencies": {
            "baseline": {row["key"]: {"p50_ms": 100.0, "p95_ms": 100.0} for row in ROWS},
            "feature": {row["key"]: {"p50_ms": 50.0, "p95_ms": 50.0} for row in ROWS}}}
        result = run_with_results("Send Slack notification (success)", {"comparison.json": json.dumps(comparison)}, env=env)
        [call] = result["calls"]
        message = json.loads(call["body"])
        self.assertNotEqual(message["channel"], "CHANNEL")
        self.assertIn("No Significant Change", message["blocks"][0]["text"]["text"])
        self.assertEqual(len(result["warnings"]), 1)
        self.assertIn("Could not classify Zones latency", result["warnings"][0])
        result = run_with_results("Send Slack notification (success)", {}, env=env)
        self.assertEqual((result["calls"], result["warnings"]),
                         ([], ["Could not read comparison.json for Zones Slack notification"]))


if __name__ == "__main__":
    unittest.main()
