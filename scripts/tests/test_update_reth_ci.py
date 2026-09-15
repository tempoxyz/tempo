"""Exercise the real update-reth polling step without GitHub writes or an agent."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
HEAD = "a" * 40
OLD_HEAD = "b" * 40

MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ["CI_FIXTURE"])
args = sys.argv[1:]
name = pathlib.Path(sys.argv[0]).name
with (root / "calls").open("a") as calls:
    calls.write(json.dumps([name, *args]) + "\n")
counter = root / "poll"
poll = int(counter.read_text()) if counter.exists() else 0
if name == "sleep":
    if poll >= 5:
        sys.exit(92)
    counter.write_text(str(poll + 1))
    sys.exit(0)
if name == "amp-run":
    sys.stdin.read()
    sys.exit(73)
if name == "git":
    if args == ["rev-parse", "HEAD"]:
        print("a" * 40)
        sys.exit(0)
    sys.exit(91)
if args[:2] == ["pr", "checks"]:
    # Immediately after a push, the PR rollup still describes the previous head.
    print(json.dumps([{"name": "test success", "state": "FAILURE", "bucket": "fail"}]))
    sys.exit(1)
if args[:2] == ["pr", "view"]:
    print("b" * 40 if "headRefOid" in args else "7554")
    sys.exit(0)
if args[:2] == ["pr", "comment"]:
    sys.exit(0)
if args[:2] == ["run", "list"]:
    print("99")
    sys.exit(0)
if args[:2] == ["run", "view"]:
    print("fixture failure log")
    sys.exit(0)
if args[0] == "api":
    endpoint = next((arg for arg in args if arg.startswith("repos/")), "")
    if "/issues/" in endpoint:
        print("12345")
        sys.exit(0)
    assert "/commits/" + "a" * 40 + "/" in endpoint, endpoint
    assert "--paginate" in args and "--slurp" in args, args
    states = json.loads((root / "states.json").read_text())
    state = states[min(poll, len(states) - 1)]
    if state.get("api_error"):
        print("fixture API unavailable", file=sys.stderr)
        sys.exit(1)
    if "/check-runs?" in endpoint:
        print(json.dumps(state["checks"]))
        sys.exit(0)
    if "/status?" in endpoint:
        print(json.dumps(state["statuses"]))
        sys.exit(0)
sys.exit(90)
'''


def snapshot(conclusion="success", status="completed", *, legacy=None):
    checks = [{"name": "test success", "status": status, "conclusion": conclusion}]
    return {"checks": [{"check_runs": checks}], "statuses": [{"statuses": legacy or []}]}


class PollingTests(unittest.TestCase):
    def run_poll(self, states, *, expired=False, expire_on_wait=False):
        workflow = (ROOT / ".github/workflows/update-reth.yml").read_text()
        step = workflow.split("- name: Wait for CI and fix failures\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1].split(
            "      # ── Slack notification", 1
        )[0]).replace("${{ github.repository }}", "tempoxyz/tempo")
        if expired:
            script = script.replace("CI_FIX_DEADLINE=$((SECONDS + 3600))", "CI_FIX_DEADLINE=0")
        if expire_on_wait:
            script = 'sleep() { SECONDS=$CI_FIX_DEADLINE; }\n' + script
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            (fixture / "states.json").write_text(json.dumps(states))
            # Separate executable files ensure argv[0] identifies each mocked command.
            for name in ["gh", "git", "sleep", "amp-run"]:
                executable = fixture / name
                executable.write_text(MOCK.replace("#!/usr/bin/env python3", f"#!{shutil.which('python3')}"))
                executable.chmod(0o755)
            env = dict(os.environ, CI_FIXTURE=directory, GITHUB_REPOSITORY="tempoxyz/tempo",
                       PATH=directory + os.pathsep + os.environ["PATH"])
            # Keep the workflow's scratch prompt inside the fixture as well.
            script = script.replace("/tmp/amp-prompt.txt", str(fixture / "prompt.txt"))
            result = subprocess.run(["bash", "-eo", "pipefail", "-c", script],
                                    cwd=ROOT, env=env, text=True, capture_output=True, timeout=10)
            calls_path = fixture / "calls"
            calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
            return result, calls

    def test_stale_pr_failure_is_not_sent_to_agent(self):
        result, calls = self.run_poll([snapshot()])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(any(call[0] == "amp-run" for call in calls))

    def test_no_checks_waits_for_current_commit(self):
        empty = {"checks": [{"check_runs": []}], "statuses": [{"statuses": []}]}
        result, calls = self.run_poll([empty, snapshot()])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sum(call[0] == "sleep" for call in calls), 1)

    def test_pending_checks_wait(self):
        result, calls = self.run_poll([snapshot(None, "in_progress"), snapshot()])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sum(call[0] == "sleep" for call in calls), 1)

    def test_api_failure_waits_instead_of_passing(self):
        result, calls = self.run_poll([{"api_error": True}, snapshot()])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sum(call[0] == "sleep" for call in calls), 1)

    def test_current_failure_collects_current_commit_logs(self):
        result, calls = self.run_poll([snapshot("failure")])
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        run_calls = [call for call in calls if call[:3] == ["gh", "run", "list"]]
        self.assertTrue(run_calls)
        self.assertTrue(all(HEAD in call and OLD_HEAD not in call for call in run_calls))

    def test_legacy_failure_is_preserved(self):
        state = snapshot(legacy=[{"context": "external test", "state": "failure"}])
        result, _ = self.run_poll([state])
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)
        self.assertIn("external test", result.stdout)

    def test_second_page_failure_is_not_ignored(self):
        state = snapshot()
        state["checks"].extend(snapshot("failure")["checks"])
        result, _ = self.run_poll([state])
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)

    def test_pending_audits_do_not_block(self):
        state = snapshot(legacy=[{"context": "Cyclops audit run", "state": "pending"}])
        state["checks"][0]["check_runs"].append(
            {"name": "Review", "status": "in_progress", "conclusion": None})
        result, _ = self.run_poll([state])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_expired_deadline_stops_polling(self):
        result, calls = self.run_poll([snapshot()], expired=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(calls)

    def test_missing_checks_cannot_wait_forever(self):
        empty = {"checks": [{"check_runs": []}], "statuses": [{"statuses": []}]}
        result, _ = self.run_poll([empty], expire_on_wait=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Timed out waiting for CI on " + HEAD, result.stdout)


if __name__ == "__main__":
    unittest.main()
