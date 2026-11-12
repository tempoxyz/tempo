#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/../../../.." && pwd)
python3 - "$root" <<'PY'
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap

root = Path(sys.argv[1])
workflow = (root / ".github/workflows/antithesis-zones.yml").read_text()
step = workflow.split("      - name: Build and push the config image\n", 1)[1]
script = textwrap.dedent(step.split("        run: |\n", 1)[1].split("\n  validate-config:", 1)[0])
image = "example.invalid/tempo-zones-antithesis-config"
digest = "sha256:" + "a" * 64
with tempfile.TemporaryDirectory() as directory:
    tmp = Path(directory)
    docker = tmp / "docker"
    docker.write_text("""#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$DOCKER_CALLS"
if [[ "$1" == image && "$2" == inspect ]]; then
    printf '%s\\n' "$FIXTURE_CONFIG_REF"
fi
""")
    docker.chmod(0o755)
    for mode, suffix in (("false", ""), ("true", "-direct")):
        case = tmp / mode
        case.mkdir()
        calls = case / "calls"
        summary = case / "summary"
        env = dict(os.environ, PATH=str(tmp) + os.pathsep + os.environ["PATH"],
                   DOCKER_CALLS=str(calls), FIXTURE_CONFIG_REF=image + "@" + digest,
                   RUNNER_TEMP=str(case), GITHUB_STEP_SUMMARY=str(summary),
                   REGISTRY="example.invalid", TAG="branch-123456789", BRANCH="branch",
                   DIGEST="sha256:" + "b" * 64, WORKLOAD_DIGEST="sha256:" + "c" * 64,
                   DIRECT_HANDOFFS=mode)
        result = subprocess.run(["bash", "-euo", "pipefail", "-c", script],
                                cwd=root, env=env, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        commands = calls.read_text().splitlines()
        assert commands[0] == (
            f"build --platform linux/amd64 -t {image}:branch-123456789{suffix} "
            f"-t {image}:branch{suffix} {case}/antithesis-config"), commands
        assert commands[1:3] == [
            f"push {image}:branch-123456789{suffix}", f"push {image}:branch{suffix}"], commands
        assert image + "@" + digest in result.stdout
        assert f"| Config image | " + chr(96) + image + "@" + digest + chr(96) in summary.read_text()
        assert f"| Direct handoffs | " + chr(96) + mode + chr(96) in summary.read_text()
        assert f"ZONE_HANDOFF_DIRECT_ONLY={mode}\n" in (case / "antithesis-config/.env").read_text()

        summary.unlink()
        env["FIXTURE_CONFIG_REF"] = image + "@invalid"
        invalid = subprocess.run(["bash", "-euo", "pipefail", "-c", script],
                                 cwd=root, env=env, capture_output=True, text=True, timeout=10)
        assert invalid.returncode != 0, "accepted malformed config digest"
        assert not summary.exists(), "published an invalid digest in the summary"
print("config profile and digest fixtures passed (no service contacted)")
PY
