"""Keep image acquisition outside the fixture execution timeout."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "smoke.sh"
ROOT = SOURCE.parents[4]


class SmokePreflight(unittest.TestCase):
    def test_cold_pull_cached_image_and_pull_failure(self):
        for cached, pull_status in ((False, 0), (True, 0), (False, 9)):
            with self.subTest(cached=cached, pull_status=pull_status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                docker = root / "docker"
                docker.write_text('''#!/usr/bin/env python3
import json,os,sys
with open(os.environ["CALLS"], "a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
if sys.argv[1:3] == ["image", "inspect"]:
    sys.exit(int(os.environ["INSPECT_STATUS"]))
if sys.argv[1] == "pull":
    sys.exit(int(os.environ["PULL_STATUS"]))
sys.exit(7)  # Stop at the fixture execution; never start a real cluster.
''')
                timeout = root / "timeout"
                timeout.write_text('''#!/usr/bin/env python3
import json,os,subprocess,sys
with open(os.environ["LIMITS"], "a") as output:
    output.write(json.dumps(sys.argv[1:4]) + "\\n")
sys.exit(subprocess.run(sys.argv[2:]).returncode)
''')
                docker.chmod(0o755)
                timeout.chmod(0o755)
                calls, limits = root / "calls", root / "limits"
                result = subprocess.run(["bash", str(SOURCE)], cwd=ROOT,
                    env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                         "TEMPO_IMAGE": "fixture@sha256:test", "SMOKE_ARTIFACT_DIR": str(root / "artifacts"),
                         "INSPECT_STATUS": "0" if cached else "1", "PULL_STATUS": str(pull_status),
                         "CALLS": str(calls), "LIMITS": str(limits)},
                    capture_output=True, text=True, timeout=5)
                recorded = [json.loads(line) for line in calls.read_text().splitlines()]
                deadlines = [json.loads(line)[0] for line in limits.read_text().splitlines()]
                self.assertEqual(recorded[0], ["image", "inspect", "fixture@sha256:test"])
                if not cached:
                    self.assertEqual(recorded[1], ["pull", "fixture@sha256:test"])
                if pull_status:
                    self.assertEqual(result.returncode, pull_status, result.stderr)
                    self.assertEqual(deadlines, ["300s"])
                    self.assertEqual(len(recorded), 2)
                else:
                    self.assertEqual(result.returncode, 7, result.stderr)
                    self.assertEqual(deadlines, ["30s"] if cached else ["300s", "30s"])
                    self.assertEqual(recorded[-1][:2], ["run", "--pull=never"])
