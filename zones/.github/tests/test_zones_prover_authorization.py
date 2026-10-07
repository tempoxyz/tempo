"""Run with python3 -m unittest discover -s .github/tests (requires PyYAML and Node)."""

import json
from pathlib import Path
import subprocess
import unittest

import yaml

WORKFLOW = yaml.safe_load(
    (Path(__file__).parents[1] / "workflows/zones-prover-benchmark.yml").read_text()
)
SHA = "a" * 40
OTHER_SHA = "b" * 40


def run_step(job, name, *, actor="member", triggering_actor="member", members=None,
             body=None, head=SHA, repo="tempoxyz/zones", event="issue_comment", feature_sha=""):
    step = next(s for s in WORKFLOW["jobs"][job]["steps"] if s.get("name") == name)
    payload = {
        "script": step["with"]["script"],
        "context": {"actor": actor, "eventName": event,
                    "payload": {"comment": {"body": body if body is not None else f"derek bench {SHA}"}},
                    "issue": {"number": 1507}, "repo": {"owner": "tempoxyz", "repo": "zones"}},
        "members": members if members is not None else ["member", "other-member"],
        "head": {"sha": head, "repo": {"full_name": repo} if repo else None},
        "env": {"TRIGGERING_ACTOR": triggering_actor, "FEATURE_SHA": feature_sha},
    }
    result = subprocess.run(["node", "-e", """
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
Object.assign(process.env, input.env);
const result = {failures: [], outputs: {}, checked: []};
const core = {
  setFailed: message => result.failures.push(message),
  setOutput: (key, value) => result.outputs[key] = value,
};
const github = {rest: {
  orgs: {checkMembershipForUser: async ({username}) => {
    result.checked.push(username);
    if (!input.members.includes(username)) throw new Error('Not a member');
  }},
  pulls: {get: async () => ({data: {head: input.head}})},
}};
const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
new AsyncFunction('github', 'core', 'context', input.script)(github, core, input.context)
  .then(() => console.log(JSON.stringify(result)))
  .catch(error => { console.error(error); process.exit(1); });
"""], input=json.dumps(payload), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


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

    def test_dispatch(self):
        for sha, allowed in ((SHA, True), ("main", False), ("", False)):
            result = run_step("authorize", "Resolve PR SHA", event="workflow_dispatch", feature_sha=sha)
            self.assertEqual(not result["failures"], allowed)
            self.assertEqual(result["outputs"], {"feature-sha": SHA} if allowed else {})

    def test_benchmark_checks_before_feature_execution(self):
        steps = WORKFLOW["jobs"]["benchmark"]["steps"]
        names = [step.get("name") for step in steps]
        check = names.index("Check org membership")
        for name in ("Mint Earn read token", "Check out feature Zones", "Configure AWS benchmark role"):
            self.assertLess(check, names.index(name))
        checkout = steps[names.index("Check out feature Zones")]
        self.assertEqual(checkout["with"]["ref"], "${{ needs.authorize.outputs.feature-sha }}")
