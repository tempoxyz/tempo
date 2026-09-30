"""Exercise the experiment's actual send pipeline against the pinned runner source.

Run with: uv run --with pyyaml python contrib/bench/test_split_pending_harness.py RUNNER_CHECKOUT
No network or cloud resources are used.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


root = Path(__file__).resolve().parents[2]
workflow = yaml.safe_load((root / ".github/workflows/bench-e2e-multi-region.yml").read_text())
steps = workflow["jobs"]["bench-e2e-multi-region"]["steps"]
step = next(s for s in steps if s.get("name") == "Configure matched split-pending experiment")
runner = Path(sys.argv[1]).resolve()
pin = next(s for s in steps if s.get("name") == "Checkout benchmark repo")["with"]["ref"]
source = subprocess.check_output(
    ["git", "show", f"{pin}:scripts/txgen_workload.sh"], cwd=runner, text=True
)
with tempfile.TemporaryDirectory(prefix="split-pending-preflight-") as directory:
    scratch = Path(directory)
    (scratch / "scripts").mkdir()
    target = scratch / "scripts/txgen_workload.sh"
    target.write_text(source)
    subprocess.run(["bash", "-eu", "-c", step["run"]], cwd=scratch, check=True)
    patched = target.read_text()
    block = patched.split("  local -a pending_args\n", 1)[1].split("  if ! IFS=", 1)[0]
    block = "  local -a pending_args\n" + block
    # Use the unchanged pipeline and report guard, mocking only its external commands.
    variables = sorted(set(re.findall(r"\$(?:\{)?([A-Za-z_][A-Za-z_0-9]*)", block)))
    initialize = "\n".join(f"  local {name}=fixture" for name in variables)
    arrays = ["BENCH_GENERATE_ARGS", "workload_generate_args", "bench_setup_args",
              "warmup_args", "metrics_args", "report_args", "github_metadata_args",
              "fixture_metadata_args", "TXGEN_RECIPIENT_METADATA_ARGS"]
    script = r'''
set -euo pipefail
txgen-tempo() { printf '{}\n'; }
bench() {
  printf '%s\n' "$@" > "$DEST/received-args.txt"
  local shared=50000 payments='' general=''
  while (($#)); do
    case "$1" in
      --max-pending) shared="$2"; shift ;;
      --max-pending-payments) payments="$2"; shared=0; shift ;;
      --max-pending-general) general="$2"; shift ;;
    esac
    shift
  done
  cat >/dev/null
  jq -n --arg shared "$shared" --arg payments "$payments" --arg general "$general" '
    {metadata: ({max_pending:$shared} +
      (if $payments != "" then {max_pending_payments:$payments,max_pending_general:$general} else {} end))}
  ' > "$txgen_report"
}
check_pipeline() {
''' + initialize + "\n" + "\n".join(f"  local -a {name}=()" for name in arrays) + r'''
  phase_label="$1"
  DEST="$2"
  txgen_report="$DEST/report.json"
  txgen_out="$DEST/stdout"
  txgen_generate_err="$DEST/generate.err"
  txgen_send_err="$DEST/send.err"
  BENCH_WARMUP_TIMEOUT_SECONDS=1
  BENCH_TPS=50000
  max_tx=10
  load_duration=90
''' + block + "\n}\ncheck_pipeline \"$@\"\n"
    for phase, expected in [
        ("baseline-1", ["--max-pending", "50000"]),
        ("feature-1", ["--max-pending-payments", "40000", "--max-pending-general", "10000"]),
    ]:
        output = scratch / phase
        output.mkdir()
        subprocess.run(["bash", "-c", script, "preflight", phase, str(output)], check=True)
        received = (output / "received-args.txt").read_text().splitlines()
        limits = [item for index, item in enumerate(received)
                  if item.startswith("--max-pending") or (index and received[index - 1].startswith("--max-pending"))]
        assert limits == expected, (phase, limits)
        print(f"PASS {phase}: bench send received {limits}")
    broken = script.replace('      "${pending_args[@]}" \\\n', '')
    assert broken != script
    result = subprocess.run(["bash", "-c", broken, "preflight", "feature-1", str(scratch / "feature-1")], capture_output=True)
    assert result.returncode != 0
    assert b"Experiment pending limits did not reach bench send" in result.stderr
    print("PASS regression: omitted sender flags fail the report guard")
