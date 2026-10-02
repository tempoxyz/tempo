#!/usr/bin/env python3
"""Summarize pidstat CPU samples wholly within each trial's send window.

CPU percentages use one logical core = 100%. Both processes share the host.
Payload timing deltas span the whole trial, including setup and empty blocks;
they are nested measurements, not additive CPU times or per-transaction latency.
"""

import argparse
import collections
import datetime
import json
import pathlib
import re


def payload_metric_deltas(directory):
    readings = []
    for suffix in ("before", "after"):
        path = directory / f"metrics-{suffix}.prom"
        if not path.exists():
            return {}
        values = {}
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0].startswith("reth_tempo_payload_builder_"):
                values[fields[0]] = float(fields[1])
        readings.append(values)
    return {key: value - readings[0].get(key, 0) for key, value in readings[1].items()}


def payload_timings(directory):
    names = {
        "successful_transaction_execution": "transaction_execution",
        "execution_loop": "total_transaction_execution",
        "pool_snapshot": "pool_fetch",
        "finalization": "payload_finalization",
        "state_root": "state_root_with_updates",
        "background_state_root_wait": "background_state_root_wait",
        "hashed_post_state": "hashed_post_state",
        "payload_build": "payload_build",
    }
    deltas = payload_metric_deltas(directory)
    result = {}
    for label, name in names.items():
        key = f"reth_tempo_payload_builder_{name}_duration_seconds_sum"
        if key in deltas:
            result[label] = round(deltas[key], 6)
    return result


def execution_counts(directory):
    # Counts span all recorded payload attempts, including cancelled work. They
    # describe scheduler activity, not distinct committed transactions.
    names = {
        "speculated": "speculated_transactions",
        "reused": "reused_transactions",
        "bodies_reused": "reused_call_bodies",
        "fees_rebased": "rebased_fee_transactions",
        "conflicts": "conflicting_transactions",
        "retries": "speculative_retries",
        "backoff": "speculative_backoff",
    }
    deltas = payload_metric_deltas(directory)
    return {label: int(deltas.get(f"reth_tempo_payload_builder_{name}_total", 0))
            for label, name in names.items()}


def summarize(directory):
    log = re.sub(r"\x1b\[[0-9;]*m", "", (directory / "bench.log").read_text())
    window = []
    for marker in ("Generating and sending transactions", "Finished sending transactions"):
        line = next(line for line in log.splitlines() if marker in line)
        window.append(datetime.datetime.fromisoformat(line.split()[0]).timestamp())
    processes = json.loads((directory / "processes.json").read_text())
    roles = {str(processes[role]): role for role in ("node", "bench")}
    samples = collections.defaultdict(dict)
    groups = collections.defaultdict(lambda: collections.defaultdict(float))
    role = None
    for line in (directory / "cpu.log").read_text().splitlines():
        fields = line.split()
        if len(fields) < 11 or not fields[0].isdigit():
            continue
        # pidstat -u -t -h -H: Time UID TGID TID usr system guest wait CPU cpu Command.
        timestamp = int(fields[0])
        if fields[2] != "-":
            role = roles.get(fields[2])
            if role == "bench":
                role = "client"
        if role is None or not (timestamp - 1 >= window[0] and timestamp <= window[1]):
            continue
        cpu = float(fields[8])
        if fields[2] != "-":
            samples[timestamp][role] = {"total": cpu, "system": float(fields[5])}
        else:
            groups[(role, fields[10])][timestamp] += cpu
    if not samples:
        raise ValueError(f"{directory}: no full CPU sample intervals in send window")
    result = {"trial": directory.name, "active_samples": len(samples),
              "process_cpu_percent": {}, "thread_groups_cpu_percent": {}}
    for role in ("node", "client"):
        rows = [sample[role] for sample in samples.values() if role in sample]
        if not rows:
            raise ValueError(f"{directory}: no CPU samples for {role}")
        result["process_cpu_percent"][role] = {
            "mean": round(sum(row["total"] for row in rows) / len(rows), 1),
            "peak": max(row["total"] for row in rows),
            "mean_system": round(sum(row["system"] for row in rows) / len(rows), 1),
        }
    result["thread_groups_cpu_percent"] = {
        f"{role}:{name}": round(sum(values.values()) / len(samples), 1)
        for (role, name), values in sorted(groups.items())
        if sum(values.values()) / len(samples) >= 2
    }
    report = json.loads((directory / "report.json").read_text())
    result["sending"] = report["sending"]
    result["accepted_tps"] = round(report["sending"]["accepted"] /
                                   report["sending"]["send_duration_secs"])
    result["payload_timing_seconds"] = payload_timings(directory)
    result["speculative_execution_counts"] = execution_counts(directory)
    # These isolated dev trials contain one system transaction per block. Check
    # all accepted user transactions before deriving the canonical completion rate.
    included = sum(block["tx_count"] - 1 for block in report["blocks"])
    if report["sending"]["unconfirmed"] == 0 and included == report["sending"]["accepted"]:
        last_busy = max(block["number"] for block in report["blocks"] if block["tx_count"] > 1)
        node_log = re.sub(r"\x1b\[[0-9;]*m", "", (directory / "node.log").read_text())
        line = next(line for line in node_log.splitlines()
                    if "Block added to canonical chain" in line and f"number={last_busy} " in line)
        completed = datetime.datetime.fromisoformat(line.split()[0]).timestamp()
        elapsed = completed - window[0]
        result["confirmation"] = {
            "user_transactions": included,
            "execution_failures": sum(block["err_count"] for block in report["blocks"]),
            "last_busy_block": last_busy,
            "send_start_to_last_canonical_seconds": round(elapsed, 6),
            "confirmed_tps_including_backlog": round(included / elapsed),
        }
        rejections = {"timestamp_through_last_busy_block": 0,
                      "timestamp_after_last_busy_block": 0, "other": []}
        for line in node_log.splitlines():
            if "Invalid block error on new payload" not in line:
                continue
            if "validation_err=block timestamp " in line:
                number = int(re.search(r"invalid_number=(\d+)", line)[1])
                key = ("timestamp_through_last_busy_block" if number <= last_busy
                       else "timestamp_after_last_busy_block")
                rejections[key] += 1
            else:
                rejections["other"].append(line)
        result["rejected_dev_payloads"] = rejections
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path, help="run_node.py output directory")
    args = parser.parse_args()
    results = [summarize(path) for path in sorted(args.directory.glob("workers-*"))
               if (path / "report.json").exists()]
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
