"""Exercise the updater's real shell loop with mocked GitHub responses."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 40
REQUIRED = ["lint success", "specs success", "test success"]


def check(name, conclusion="success", check_id=1):
    return {"name": name, "status": "completed", "conclusion": conclusion, "id": check_id}


class RethCiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.events = self.path / "events"
        self.checks = [{"check_runs": [check(name) for name in REQUIRED]}]
        self.statuses = [[{"context": "Tempo Network E2E", "state": "success", "id": 1}]]
        self.env = dict(os.environ, PATH=f"{self.path}:{os.environ['PATH']}",
                        FIXTURES=str(self.path), GITHUB_REPOSITORY="tempoxyz/tempo")
        self.command("gh", """
            echo "$*" >> "$FIXTURES/events"
            case "$*" in
              *check-runs*) cat "$FIXTURES/checks.json" ;;
              *statuses*) cat "$FIXTURES/statuses.json" ;;
              *"pr view"*) echo 8355 ;;
              *"issues/8355/comments"*) echo existing-comment ;;
              *"run list"*) : ;;
              *"pr comment"*) : ;;
              *) echo "Unexpected gh call: $*" >&2; exit 1 ;;
            esac
        """)
        self.command("git", f'echo "git $*" >> "$FIXTURES/events"\n'
                            f'case "$*" in "rev-parse HEAD") echo {SHA} ;; "status --porcelain") : ;; *) exit 1 ;; esac')
        self.command("amp-run", 'echo amp >> "$FIXTURES/events"\ncat >/dev/null')
        self.command("sleep", """
            echo sleep >> "$FIXTURES/events"
            if [ -f "$FIXTURES/next-statuses.json" ]; then
              mv "$FIXTURES/next-statuses.json" "$FIXTURES/statuses.json"
            fi
        """)

    def command(self, name, body):
        path = self.path / name
        path.write_text("#!/usr/bin/env bash\nset -eu\n" + textwrap.dedent(body))
        path.chmod(0o755)

    def write_fixtures(self):
        (self.path / "checks.json").write_text(json.dumps(self.checks))
        (self.path / "statuses.json").write_text(json.dumps(self.statuses))

    def snapshot(self):
        self.write_fixtures()
        result = subprocess.run(
            ["bash", ".github/scripts/reth-ci-status.sh", "tempoxyz/tempo", SHA],
            cwd=ROOT, env=self.env, text=True, capture_output=True, check=True,
        )
        return json.loads(result.stdout)

    def loop(self, external_timeout=90, deadline=10800):
        self.write_fixtures()
        workflow = (ROOT / ".github/workflows/update-reth.yml").read_text()
        step = workflow.split("      - name: Wait for CI and fix failures\n", 1)[1]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n      # ── Slack", 1)[0])
        script = script.replace("CI_TIMEOUT_MINUTES=30", "CI_TIMEOUT_MINUTES=0")
        script = script.replace("EXTERNAL_CI_TIMEOUT_MINUTES=90", f"EXTERNAL_CI_TIMEOUT_MINUTES={external_timeout}")
        script = script.replace("SECONDS + 10800", f"SECONDS + {deadline}")
        if deadline == 0:
            # Exercise the inner deadline, independently of the outer attempt guard.
            script = script.replace('[ "$SECONDS" -ge "$CI_FIX_DEADLINE" ]', '[ 0 -ge 1 ]', 1)
        return subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=ROOT,
                              env=self.env, text=True, capture_output=True, timeout=5)

    def test_queries_pushed_sha_and_waits_for_missing_gates(self):
        self.checks = [{"check_runs": []}]
        self.statuses = [[]]
        result = self.snapshot()
        self.assertEqual({item["name"] for item in result}, {*REQUIRED, "Tempo Network E2E"})
        self.assertTrue(all(item["state"] == "PENDING" for item in result))
        calls = self.events.read_text().splitlines()
        self.assertEqual(calls, [
            f"api --paginate --slurp repos/tempoxyz/tempo/commits/{SHA}/check-runs?per_page=100",
            f"api --paginate --slurp repos/tempoxyz/tempo/commits/{SHA}/statuses?per_page=100",
        ])

    def test_latest_attempt_wins_across_pages(self):
        self.checks.append({"check_runs": [check("test success", "failure", 0)]})
        self.statuses.append([{"context": "Tempo Network E2E", "state": "failure", "id": 0}])
        self.assertTrue(all(item["state"] == "SUCCESS" for item in self.snapshot()))

    def test_large_api_payload_does_not_exceed_shell_argument_limit(self):
        self.checks[0]["check_runs"][0]["output"] = {"text": "x" * 200_000}
        self.assertTrue(all(item["state"] == "SUCCESS" for item in self.snapshot()))

    def test_cancelled_timed_out_and_action_required_checks_fail(self):
        for conclusion in ("cancelled", "timed_out", "action_required"):
            with self.subTest(conclusion=conclusion):
                self.checks = [{"check_runs": [check("test success", conclusion)]}]
                result = {item["name"]: item["state"] for item in self.snapshot()}
                self.assertEqual(result["test success"], "FAILURE")

    def test_external_pending_survives_local_timeout_then_passes(self):
        (self.path / "next-statuses.json").write_text(json.dumps(self.statuses))
        self.statuses[0][0]["state"] = "pending"
        self.checks[0]["check_runs"].append({"name": "Review", "status": "in_progress", "id": 2})
        result = self.loop()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = self.events.read_text().splitlines()
        self.assertIn("sleep", events)
        self.assertNotIn("amp", events)
        self.assertIn("All CI checks passed!", result.stdout)

    def test_external_timeout_is_reported_without_source_edits(self):
        self.statuses[0][0]["state"] = "pending"
        result = self.loop(external_timeout=0)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("External CI did not finish", result.stdout)
        self.assertNotIn("amp", self.events.read_text().splitlines())

    def test_fix_repolls_new_commit_instead_of_old_failed_checks(self):
        next_sha = "b" * 40
        self.command("git", f"""
            echo "git $*" >> "$FIXTURES/events"
            case "$*" in
              "rev-parse HEAD") cat "$FIXTURES/head" ;;
              "status --porcelain") : ;;
              *) exit 1 ;;
            esac
        """)
        (self.path / "head").write_text(SHA)
        (self.path / "fixed-checks.json").write_text(json.dumps(self.checks))
        self.checks[0]["check_runs"][2]["conclusion"] = "failure"
        gh = self.path / "gh"
        gh.write_text(gh.read_text().replace(
            '*check-runs*) cat "$FIXTURES/checks.json" ;;',
            f'*{next_sha}/check-runs*) cat "$FIXTURES/fixed-checks.json" ;;\n'
            '  *check-runs*) cat "$FIXTURES/checks.json" ;;',
        ))
        self.command("amp-run", f'echo amp >> "$FIXTURES/events"\ncat >/dev/null\necho {next_sha} > "$FIXTURES/head"')
        result = self.loop()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        events = self.events.read_text().splitlines()
        self.assertEqual(events.count("amp"), 1)
        self.assertTrue(any(f"commits/{next_sha}/check-runs" in event for event in events))

    def test_real_external_failure_still_blocks(self):
        self.statuses[0][0]["state"] = "failure"
        result = self.loop()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Failed checks: Tempo Network E2E", result.stdout)
        self.assertNotIn("All CI checks passed!", result.stdout)

    def test_api_failure_cannot_look_green(self):
        self.command("gh", "exit 1")
        self.write_fixtures()
        result = subprocess.run(["bash", ".github/scripts/reth-ci-status.sh", "tempoxyz/tempo", SHA],
                                cwd=ROOT, env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_deadline_bounds_polling_before_checks_appear(self):
        self.checks = [{"check_runs": []}]
        self.statuses = [[]]
        result = self.loop(deadline=0)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("fix-cycle deadline", result.stdout)


if __name__ == "__main__":
    unittest.main()
