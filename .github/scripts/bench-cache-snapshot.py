#!/usr/bin/env python3
"""Capture cache residency and cgroup counters outside the timed E2E workload.

Run as root so mincore's permission-based all-resident fallback cannot mask real
residency. fincore inspects residency without reading file contents into cache.
Errors remain explicit in the artifact instead of being reported as zero usage.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def read_text(path):
    try:
        return {"text": path.read_text()}
    except OSError as error:
        return {"error": str(error)}


def file_cache(paths):
    paths = list(paths)
    files = sorted(str(path) for path in paths if path.is_file())
    rows = []
    errors = [f"missing file: {path}" for path in paths if not path.exists()]
    for start in range(0, len(files), 64):
        try:
            result = subprocess.run(
                ["fincore", "--json", "--bytes", "--output", "FILE,SIZE,RES", "--",
                 *files[start:start + 64]],
                capture_output=True, text=True, timeout=30, check=False,
            )
            if result.returncode:
                errors.append(result.stderr.strip() or f"fincore exited {result.returncode}")
            rows.extend(json.loads(result.stdout).get("fincore", []))
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            errors.append(str(error))
    complete = not errors and len(rows) == len(files)
    return {
        "files_requested": len(files),
        "complete": complete,
        "size_bytes": sum(int(row["size"]) for row in rows) if complete else None,
        "resident_bytes": sum(int(row["res"]) for row in rows) if complete else None,
        "files": rows,
        "errors": errors,
    }


def validator(datadir, role, phase):
    unit_phase = phase.replace("_", "-").replace(".", "-")
    unit = f"tempo-e2e-{role}-{unit_phase}.scope"
    result = subprocess.run(
        ["systemctl", "show", unit, "--property=ControlGroup", "--value"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    control_group = result.stdout.strip()
    counters = {}
    if result.returncode == 0 and control_group.startswith("/") and control_group != "/":
        root = Path("/sys/fs/cgroup") / control_group.lstrip("/")
        for name in ["memory.current", "memory.peak", "memory.max", "memory.stat",
                     "memory.events", "memory.pressure", "io.stat", "io.pressure"]:
            counters[name] = read_text(root / name)
    else:
        counters["error"] = result.stderr.strip() or f"missing cgroup for {unit}"
    return {
        "datadir": str(datadir), "unit": unit, "control_group": control_group,
        "cgroup": counters,
        "mdbx": file_cache([datadir / "db/mdbx.dat"]),
        "static_files": file_cache((datadir / "static_files").rglob("*")),
        "rocksdb": file_cache((datadir / "rocksdb").rglob("*")),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--point", choices=["before", "after"], required=True)
    parser.add_argument("--a", type=Path, required=True)
    parser.add_argument("--b", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root to obtain reliable file residency")
    started = time.time()
    snapshot = {
        "phase": args.phase, "point": args.point, "started_unix": started,
        "meminfo": read_text(Path("/proc/meminfo")),
        "memory_pressure": read_text(Path("/proc/pressure/memory")),
        "io_pressure": read_text(Path("/proc/pressure/io")),
        "validators": {},
    }
    for role, datadir in [("a", args.a), ("b", args.b)]:
        try:
            snapshot["validators"][role] = validator(datadir, role, args.phase)
        except (OSError, subprocess.TimeoutExpired) as error:
            snapshot["validators"][role] = {"error": str(error)}
    snapshot["finished_unix"] = time.time()
    args.output.write_text(json.dumps(snapshot, indent=2) + "\n")


if __name__ == "__main__":
    main()
