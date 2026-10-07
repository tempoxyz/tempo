#!/usr/bin/env python3
"""Record validator resource pressure and persistence worker waits during a bench."""
import gzip
import json
import signal
import sys
import time
from pathlib import Path


def read(path):
    try:
        return path.read_text().strip()
    except OSError:
        return None


running = True


def stop(*_):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
Path(sys.argv[1]).parent.mkdir(parents=True, exist_ok=True)
with gzip.open(sys.argv[1], "wt") as output:
    while running:
        for proc in Path("/proc").glob("[0-9]*"):
            try:
                if proc.joinpath("exe").resolve().name != "tempo":
                    continue
                cgroup = read(proc / "cgroup")
                record = {"time": time.time(), "pid": int(proc.name), "cgroup": cgroup}
                record["process"] = {name: read(proc / name) for name in ("stat", "status", "io")}
                if cgroup and cgroup.startswith("0::"):
                    scope = Path("/sys/fs/cgroup") / cgroup[3:].lstrip("/")
                    record["scope"] = {
                        name: read(scope / name)
                        for name in ("memory.current", "memory.stat", "memory.events", "memory.pressure", "io.pressure", "io.stat", "cpu.stat")
                    }
                record["threads"] = []
                for task in proc.joinpath("task").glob("[0-9]*"):
                    name = read(task / "comm") or ""
                    if any(part in name for part in ("persist", "prun", "nonce", "root", "engine")):
                        record["threads"].append({"tid": int(task.name), "name": name, **{
                            field: read(task / field) for field in ("stat", "io", "wchan", "schedstat", "stack")
                        }})
                output.write(json.dumps(record) + "\n")
            except (OSError, ValueError):
                continue
        output.flush()
        time.sleep(1)
