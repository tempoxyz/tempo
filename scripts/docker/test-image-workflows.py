# /// script
# dependencies = ["pyyaml"]
# ///
"""Regression checks for published image identity; no registry or GitHub writes.

Run with: uv run scripts/docker/test-image-workflows.py
"""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
OTHER_DIGEST = "sha256:" + "c" * 64


def steps(workflow):
    document = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())
    return next(iter(document["jobs"].values()))["steps"]


def step(workflow, name):
    return next(item for item in steps(workflow) if item.get("name") == name)


class ImageWorkflows(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.output = self.directory / "output"
        self.env = {
            **os.environ,
            "RUNNER_TEMP": str(self.directory),
            "GITHUB_OUTPUT": str(self.output),
            "GITHUB_SHA": SHA,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2",
        }

    def metadata(self, target):
        metadata = {}
        for name in [target, "tempo-localnet", "tempo-sidecar", "tempo-xtask"]:
            image = "tempo" if name == target else name
            tags = ["nightly"] if name == "tempo-nightly" else ["edge", "sha-aaaaaaa"]
            metadata[name] = {
                "containerimage.digest": DIGEST if name == target else OTHER_DIGEST,
                "image.name": ",".join(
                    f"{registry}/tempoxyz/{image}:{tag}"
                    for registry in ["ghcr.io", "docker.io"] for tag in tags
                ),
            }
        return metadata

    def resolve(self, target, metadata):
        return subprocess.run(
            ["bash", "scripts/docker/resolve-images.sh"], cwd=ROOT,
            env={**self.env, "TEMPO_TARGET": target, "BUILD_METADATA": json.dumps(metadata)},
            capture_output=True, text=True,
        )

    def test_signing_uses_published_digests_for_both_build_modes(self):
        for target in ["tempo", "tempo-nightly"]:
            with self.subTest(target=target):
                result = self.resolve(target, self.metadata(target))
                self.assertEqual(result.returncode, 0, result.stderr)
                refs = (self.directory / "docker-signing-refs.txt").read_text().splitlines()
                self.assertEqual(len(refs), 8)  # four images in two registries, deduplicated
                self.assertIn(f"ghcr.io/tempoxyz/tempo@{DIGEST}", refs)
                self.assertTrue(all("@sha256:" in ref for ref in refs))
                record = json.loads((self.directory / "tempo-image.json").read_text())
                self.assertEqual(record, dict(digest=DIGEST, target=target, commit=SHA,
                                              run_id="123", run_attempt="2"))

    def test_incomplete_build_metadata_is_rejected(self):
        for field in ["containerimage.digest", "image.name"]:
            for value in [None, "", "invalid"]:
                with self.subTest(field=field, value=value):
                    metadata = self.metadata("tempo-nightly")
                    metadata["tempo-nightly"][field] = value
                    self.assertNotEqual(self.resolve("tempo-nightly", metadata).returncode, 0)
        metadata = self.metadata("tempo-nightly")
        del metadata["tempo-xtask"]
        self.assertNotEqual(self.resolve("tempo-nightly", metadata).returncode, 0)

    def test_sign_step_consumes_only_resolved_references(self):
        result = self.resolve("tempo-nightly", self.metadata("tempo-nightly"))
        self.assertEqual(result.returncode, 0, result.stderr)
        refs = (self.directory / "docker-signing-refs.txt").read_text().splitlines()
        script = 'cosign() { printf "%s\\n" "$*"; }\n' + step("docker.yml", "Sign Docker images")["run"]
        result = subprocess.run(["bash", "-c", script], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [f"sign --yes --recursive {ref}" for ref in refs])

    def promote(self, record_changes=None, *, missing=False, inspection_changes=None,
                digest_override="", soak_override=""):
        record = dict(digest=DIGEST, target="tempo-nightly", commit=SHA, run_id="123", run_attempt="2")
        record.update(record_changes or {})
        (self.directory / "record.json").write_text(json.dumps(record))
        inspection = {"manifest": {"digest": DIGEST}, "image": {
            "linux/amd64": {"config": {"Labels": {"org.opencontainers.image.revision": SHA}}},
        }}
        inspection.update(inspection_changes or {})
        run = dict(databaseId=123, attempt=2, headSha=SHA, updatedAt="2026-09-01T00:00:00Z",
                   url="https://github.com/tempoxyz/tempo/actions/runs/123")
        mocks = r'''
gh() {
  case "$1 $2" in
    'run list') printf '%s\n' "$TEST_RUN" ;;
    'run download')
      printf '%s\n' "$*" >> "$TEST_DIR/gh-trace"
      [ "$TEST_MISSING" = 0 ] || return 1
      cp "$TEST_DIR/record.json" "${@: -1}/tempo-image.json"
      ;;
    *) echo "Unexpected gh call: $*" >&2; return 1 ;;
  esac
}
docker() {
  printf '%s\n' "$*" >> "$TEST_DIR/docker-trace"
  printf '%s\n' "$TEST_INSPECTION"
}
'''
        self.output.unlink(missing_ok=True)
        (self.directory / "docker-trace").unlink(missing_ok=True)
        return subprocess.run(
            ["bash", "-c", mocks + step("promote-canary.yml", "Resolve image digest")["run"]],
            env={**self.env, "GH_REPO": "tempoxyz/tempo", "IMAGE": "ghcr.io/tempoxyz/tempo",
                 "DEFAULT_SOAK_DAYS": "1", "DIGEST_OVERRIDE": digest_override,
                 "SOAK_DAYS_OVERRIDE": soak_override, "TEST_DIR": str(self.directory),
                 "TEST_MISSING": str(int(missing)), "TEST_RUN": json.dumps(run),
                 "TEST_INSPECTION": json.dumps(inspection)},
            capture_output=True, text=True,
        )

    def test_promotion_uses_attempt_record_and_inspects_by_digest(self):
        result = self.promote()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--name tempo-image-2", (self.directory / "gh-trace").read_text())
        trace = (self.directory / "docker-trace").read_text()
        self.assertIn(f"ghcr.io/tempoxyz/tempo@{DIGEST}", trace)
        self.assertNotIn(":sha-", trace)
        self.assertIn(f"digest={DIGEST}", self.output.read_text())

    def test_missing_record_never_falls_back_to_sha_tag(self):
        result = self.promote(missing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no digest record", result.stderr)
        self.assertFalse((self.directory / "docker-trace").exists())

    def test_wrong_record_identity_or_digest_is_rejected(self):
        for changes in [{"commit": "d" * 40}, {"run_id": "456"}, {"run_attempt": "1"},
                        {"target": "tempo"}, {"digest": "invalid"}, {"digest": None}]:
            with self.subTest(changes=changes):
                self.assertNotEqual(self.promote(changes).returncode, 0)
                self.assertFalse((self.directory / "docker-trace").exists())

    def test_registry_digest_or_revision_mismatch_is_rejected(self):
        for changes in [{"manifest": {"digest": OTHER_DIGEST}}, {"image": {}},
                        {"image": {"linux/amd64": {"config": {"Labels": {
                            "org.opencontainers.image.revision": "d" * 40}}}}}]:
            with self.subTest(changes=changes):
                self.assertNotEqual(self.promote(inspection_changes=changes).returncode, 0)

    def test_manual_digest_override_remains_available(self):
        result = self.promote(digest_override=DIGEST)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"digest={DIGEST}", self.output.read_text())
        self.assertFalse((self.directory / "docker-trace").exists())
        self.assertNotEqual(self.promote(digest_override="invalid").returncode, 0)
        self.assertNotEqual(self.promote(digest_override=DIGEST, soak_override="1").returncode, 0)

    def test_event_and_artifact_routing(self):
        workflow = "docker.yml"
        for event, nightly, expected_nightly, expected_sha in [
            ("schedule", "", True, False), ("workflow_dispatch", "true", True, False),
            ("workflow_dispatch", "false", False, True), ("push", "", False, True),
            ("merge_group", "", False, False),
        ]:
            with self.subTest(event=event, nightly=nightly):
                context = {"github.repository": "tempoxyz/tempo", "github.event_name": event,
                           "github.event.inputs.nightly": nightly}

                def evaluate(expression):
                    expression = expression.removeprefix("${{").removesuffix("}}")
                    expression = re.sub(r"github\.[a-z_.]+", lambda m: repr(context[m[0]]), expression)
                    return eval(expression.replace("&&", " and ").replace("||", " or "),
                                {"__builtins__": {}}, {})

                for name in ["Publish event (nightly tag)", "Record nightly image digest"]:
                    self.assertEqual(bool(evaluate(step(workflow, name)["if"])), expected_nightly)
                self.assertEqual(bool(evaluate(step(workflow, "Publish event (sha tag)")["if"])), expected_sha)
                target = evaluate(step(workflow, "Resolve published images")["env"]["TEMPO_TARGET"])
                self.assertEqual(target, "tempo-nightly" if expected_nightly else "tempo")


if __name__ == "__main__":
    unittest.main()
