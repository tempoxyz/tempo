"""Exercise prover provenance validation without GitHub or Docker access."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("verify-zone-verifier-pcrs.sh")


class ProverProvenanceTests(unittest.TestCase):
    def run_entry(self, repo, image_source=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = "a" * 40
            pcrs = {str(index): "11" * 48 for index in range(3)}
            entry = {
                "commit": f"https://github.com/{repo}/commit/{sha}",
                "image": "ghcr.io/tempoxyz/tempo-zone-prover@sha256:" + "b" * 64,
                "pcrs": pcrs,
            }
            (root / "pcrs.json").write_text(json.dumps({"T13": entry}))
            labels = {
                "org.opencontainers.image.revision": sha,
                "org.opencontainers.image.source": f"https://github.com/{image_source or repo}",
                **{f"xyz.tempo.zone-prover.nitro.pcr{i}": value for i, value in pcrs.items()},
            }
            for name, body in {
                "gh": 'printf "%s\\n" "$*" >> "$PCR_TEST_LOG"\nprintf "identical\\n"\n',
                "docker": '''case "$1 $2" in
  "pull --quiet") ;;
  "image inspect") printf '%s\\n' "$PCR_TEST_LABELS" ;;
  "run --rm") printf '%s\\n' "$PCR_TEST_MEASUREMENTS" ;;
  *) exit 1 ;;
esac
''',
            }.items():
                command = root / name
                command.write_text("#!/usr/bin/env bash\nset -eu\n" + body)
                command.chmod(0o755)
            result = subprocess.run(
                ["bash", str(SCRIPT), str(root / "pcrs.json")],
                env={
                    **os.environ,
                    "PATH": f"{root}:{os.environ['PATH']}",
                    "PCR_TEST_LOG": str(root / "calls"),
                    "PCR_TEST_LABELS": json.dumps(labels),
                    "PCR_TEST_MEASUREMENTS": json.dumps(
                        {"Measurements": {f"PCR{i}": value for i, value in pcrs.items()}}
                    ),
                },
                text=True,
                capture_output=True,
                timeout=10,
            )
            calls = (root / "calls").read_text() if (root / "calls").exists() else ""
            return result, calls

    def test_accepts_tempo_and_legacy_zones_releases(self):
        for repo in ["tempoxyz/tempo", "tempoxyz/zones"]:
            with self.subTest(repo=repo):
                result, calls = self.run_entry(repo)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"repos/{repo}/compare/main...{'a' * 40}", calls)

    def test_rejects_unapproved_source_repositories_before_api_access(self):
        result, calls = self.run_entry("other/tempo")
        self.assertEqual(result.returncode, 1)
        self.assertIn("unsupported prover source commit", result.stdout)
        self.assertEqual(calls, "")

    def test_requires_the_image_source_to_match_the_commit_repository(self):
        result, _ = self.run_entry("tempoxyz/tempo", image_source="tempoxyz/zones")
        self.assertEqual(result.returncode, 1)
        self.assertIn("expected https://github.com/tempoxyz/tempo", result.stdout)


if __name__ == "__main__":
    unittest.main()
