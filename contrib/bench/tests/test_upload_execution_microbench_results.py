import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
UPLOADER = REPOSITORY_ROOT / "contrib/bench/upload-execution-microbench-results.sh"


class UploadExecutionMicrobenchResultsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.rows = self.root / "rows.jsonl"
        self.curl_log = self.root / "curl-args.jsonl"
        self.write_rows()

        fake_curl = self.root / "curl"
        fake_curl.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys

with open(os.environ["CURL_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({
        "argv": sys.argv[1:],
        "has_password": "CLICKHOUSE_PASSWORD" in os.environ,
        "has_user": "CLICKHOUSE_USER" in os.environ,
    }) + "\\n")
if "--get" in sys.argv:
    print(os.environ.get("FAKE_CLICKHOUSE_COUNT", "1"))
""",
            encoding="utf-8",
        )
        fake_curl.chmod(0o755)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write_rows(
        self,
        *,
        cpu_set: str | None = "2",
        governors: str | None = "performance",
        turbo: str | None = None,
    ) -> None:
        row = {
            "schema_version": 1,
            "run_id": "test-run-1",
            "case_id": "identity/empty",
            "measurement_mode": "wall_time",
            "machine_id": "test-runner",
            "cpu_set": cpu_set,
            "cpu_governors": governors,
            "turbo_control_json": turbo,
        }
        self.rows.write_text(json.dumps(row) + "\n", encoding="utf-8")

    def run_uploader(self, **environment: str) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "PATH": f"{self.root}:{os.environ['PATH']}",
            "CURL_LOG": str(self.curl_log),
            "FAKE_CLICKHOUSE_COUNT": "1",
            "CLICKHOUSE_URL": "https://clickhouse.invalid",
            "CLICKHOUSE_USER": "benchmark-user",
            "CLICKHOUSE_PASSWORD": "secret-password",
            "CLICKHOUSE_DATABASE": "bench",
            **environment,
        }
        return subprocess.run(
            ["bash", str(UPLOADER), str(self.rows)],
            cwd=REPOSITORY_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

    def test_inserts_and_verifies_without_credentials_in_argv(self) -> None:
        result = self.run_uploader()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Uploaded and verified 1 result(s)", result.stdout)

        calls = [json.loads(line) for line in self.curl_log.read_text().splitlines()]
        self.assertEqual(len(calls), 2)
        self.assertTrue(any("--data-binary" in call["argv"] for call in calls))
        self.assertTrue(any("--get" in call["argv"] for call in calls))
        self.assertTrue(all(not call["has_password"] for call in calls))
        self.assertTrue(all(not call["has_user"] for call in calls))
        self.assertNotIn("secret-password", json.dumps(calls))

    def test_rejects_unpinned_publication(self) -> None:
        self.write_rows(cpu_set=None)
        result = self.run_uploader()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-empty cpu_set", result.stderr)
        self.assertFalse(self.curl_log.exists())

    def test_rejects_partially_configured_credentials(self) -> None:
        result = self.run_uploader(CLICKHOUSE_PASSWORD="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("partially configured", result.stderr)
        self.assertFalse(self.curl_log.exists())

    def test_rejects_non_loopback_http(self) -> None:
        result = self.run_uploader(CLICKHOUSE_URL="http://clickhouse.invalid")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must use HTTPS", result.stderr)
        self.assertFalse(self.curl_log.exists())

    def test_rejects_non_performance_governor(self) -> None:
        self.write_rows(governors="performance,powersave")
        result = self.run_uploader()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("governor must be performance", result.stderr)

    def test_validates_detected_turbo_control(self) -> None:
        self.write_rows(
            turbo=json.dumps(
                {
                    "path": "/sys/devices/system/cpu/cpufreq/boost",
                    "value": "1",
                },
                separators=(",", ":"),
            )
        )
        result = self.run_uploader()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("turbo boost is enabled", result.stderr)


if __name__ == "__main__":
    unittest.main()
