"""Compatibility entrypoint for the canonical Node report-consistency gate.

Use node contrib/bench/gas-study-audit.mjs RESULTS_DIRECTORY in CI.
Existing uv run python commands and Python audit(directory) callers remain supported.
A pass checks consistency only and never establishes pricing readiness.
"""

import argparse
import json
from pathlib import Path
import subprocess


def audit(directory):
    result = subprocess.run(
        ["node", str(Path(__file__).with_suffix(".mjs")), str(directory)],
        check=False, text=True, capture_output=True,
    )
    if result.returncode not in (0, 1) or not result.stdout.strip():
        raise RuntimeError(result.stderr or "Node audit returned no result")
    return json.loads(result.stdout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    result = audit(args.directory)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ordinary_workload_data_valid"] else 1)
