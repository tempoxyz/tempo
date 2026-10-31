"""Run bounded TLC checks and validate measured implementation observations."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def literal(value):
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int) and value >= 0:
        return str(value)
    if isinstance(value, list):
        return "<<" + ", ".join(map(literal, value)) + ">>"
    if isinstance(value, dict) and value:
        if not all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key) for key in value):
            raise ValueError("Invalid TLA+ record key")
        return "[" + ", ".join(f"{key} |-> {literal(val)}" for key, val in value.items()) + "]"
    raise ValueError(f"Unsupported observation: {value!r}")


def run_tlc(java, jar, directory, module, expect_failure=False):
    result = subprocess.run(
        [java, "-XX:+UseParallelGC", "-Xmx4g", "-cp", str(jar), "tlc2.TLC",
         "-workers", "1", "-metadir", str(directory / "states"), module],
        cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=180,
    )
    print(result.stdout, end="")
    if expect_failure:
        if result.returncode == 0 or "Error: Deadlock reached." not in result.stdout:
            raise RuntimeError("Corrupted trace was not rejected by a replay deadlock")
    elif result.returncode != 0 or "No error has been found" not in result.stdout:
        raise RuntimeError(f"TLC check failed ({result.returncode})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", type=Path, default=os.environ.get("TLA2TOOLS_JAR"), required=False)
    parser.add_argument("--java", default=os.environ.get("JAVA", "java"))
    parser.add_argument("--trace", type=Path, action="append", default=[])
    parser.add_argument("--negative-control", action="store_true")
    args = parser.parse_args()
    if args.jar is None or not args.jar.is_file():
        parser.error("Pass --jar or set TLA2TOOLS_JAR to tla2tools.jar")
    source = Path(__file__).resolve().parent
    jar = args.jar.resolve()
    with tempfile.TemporaryDirectory(prefix="zones-tla-") as temp:
        directory = Path(temp)
        shutil.copy(source / "Zones.tla", directory)
        shutil.copy(source / "Zones.cfg", directory)
        run_tlc(args.java, jar, directory, "Zones")
        traces = {}
        for path in args.trace:
            for line in path.read_text().splitlines():
                marker = line.find("ZONES_TLA ")
                if marker >= 0:
                    event = json.loads(line[marker + len("ZONES_TLA "):])
                    traces.setdefault(event["scenario"], []).append(
                        {"action": event["action"], "state": event["state"]}
                    )
        if args.trace and not traces:
            raise ValueError("No ZONES_TLA implementation observations found")
        shutil.copy(source / "Replay.tla", directory)
        config = (source / "Zones.cfg").read_text().replace(
            "SPECIFICATION Spec", "SPECIFICATION ReplaySpec"
        ).replace("CHECK_DEADLOCK FALSE", "CHECK_DEADLOCK TRUE")
        (directory / "Replay.cfg").write_text(config)
        for name, trace in traces.items():
            if (len(trace) < 3 or trace[0]["action"] != "init"
                    or trace[-1]["action"] != "complete"
                    or any(event["action"] in {"init", "complete"} for event in trace[1:-1])):
                raise ValueError(f"Incomplete trace: {name}")
            print(f"Checking {name}: {len(trace)} observations", flush=True)
            (directory / "Observations.tla").write_text(
                "---- MODULE Observations ----\nTrace == " + literal(trace) + "\n====\n"
            )
            run_tlc(args.java, jar, directory, "Replay")
            if args.negative_control:
                corrupted = json.loads(json.dumps(trace))
                key = next(iter(corrupted[-1]["state"]))
                corrupted[-1]["state"][key] += 1
                (directory / "Observations.tla").write_text(
                    "---- MODULE Observations ----\nTrace == " + literal(corrupted) + "\n====\n"
                )
                print(f"Negative control: corrupt {name}.{key}", flush=True)
                run_tlc(args.java, jar, directory, "Replay", expect_failure=True)
        print(f"PASS: bounded model and {len(traces)} implementation traces")


if __name__ == "__main__":
    main()
