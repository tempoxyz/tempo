#!/usr/bin/env python3
"""Summarize complete CPU profiles inside a profile_node.py submission window.

Reads the built-in profiler's pprof protobufs without external Python packages.
Percentages describe sampled user-space CPU, not kernel CPU or blocked time.
Profiling changes throughput; these records are diagnostic evidence only.
"""

import argparse
from collections import Counter, defaultdict
import datetime
import hashlib
import json
from pathlib import Path
import re

from summarize_cpu import payload_metric_deltas


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("invalid protobuf varint")


def message(data):
    fields = defaultdict(list)
    offset = 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        wire = tag & 7
        if wire == 0:
            value, offset = varint(data, offset)
        else:
            if wire == 2:
                size, offset = varint(data, offset)
            elif wire in (1, 5):
                size = 8 if wire == 1 else 4
            else:
                raise ValueError(f"unsupported protobuf wire type {wire}")
            if offset + size > len(data):
                raise ValueError("truncated protobuf field")
            value = data[offset:offset + size]
            offset += size
        fields[tag >> 3].append(value)
    return fields


def integers(fields):
    for field in fields:
        if isinstance(field, int):
            yield field
        else:
            offset = 0
            while offset < len(field):
                value, offset = varint(field, offset)
                yield value


def decode(path):
    profile = message(path.read_bytes())
    strings = [value.decode() for value in profile[6]]
    sample_types = [message(value) for value in profile[1]]
    types = [(strings[value[1][0]], strings[value[2][0]]) for value in sample_types]
    cpu_index = types.index(("cpu", "nanoseconds"))
    functions = {}
    for value in profile[5]:
        function = message(value)
        functions[function[1][0]] = strings[function[2][0]]
    locations = {}
    for value in profile[4]:
        location = message(value)
        locations[location[1][0]] = [
            functions[message(line)[1][0]] for line in location[4]
        ]
    samples = []
    for value in profile[2]:
        sample = message(value)
        stack = [function for ident in integers(sample[1]) for function in locations[ident]]
        values = list(integers(sample[2]))
        if len(values) != len(types) or values[cpu_index] >= 2**63:
            raise ValueError("invalid CPU sample values")
        samples.append((stack, values[cpu_index]))
    return profile[9][0] / 1e9, profile[10][0] / 1e9, samples


def summarize(directory):
    trials = list((directory / "trial").glob("workers-*"))
    if len(trials) != 1:
        raise ValueError("expected one captured node trial")
    trial = trials[0]
    log = re.sub(r"\x1b\[[0-9;]*m", "", (trial / "bench.log").read_text())
    window = []
    for marker in ("Generating and sending transactions", "Finished sending transactions"):
        line = next(line for line in log.splitlines() if marker in line)
        window.append(datetime.datetime.fromisoformat(line.split()[0]).timestamp())
    profiles = []
    node_flat, builder_flat, builder_inclusive = Counter(), Counter(), Counter()
    total = builder_total = 0
    for path in sorted((directory / "profiles").glob("*.pb")):
        start, duration, samples = decode(path)
        if not (window[0] <= start and start + duration <= window[1]):
            continue
        profiles.append({"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                         "start": start, "duration": duration, "samples": len(samples)})
        for stack, weight in samples:
            total += weight
            if stack:
                node_flat[stack[0]] += weight
            if any("TempoPayloadBuilder" in frame and "build_payload" in frame for frame in stack):
                builder_total += weight
                builder_flat[stack[0]] += weight
                for frame in set(stack):
                    builder_inclusive[frame] += weight
    if not profiles or not total or not builder_total:
        raise ValueError("no complete CPU profile with builder symbols inside the send window")

    def table(counter, denominator):
        return [{"function": name, "sample_weight_ns": value,
                 "percent": round(100 * value / denominator, 3)}
                for name, value in counter.most_common(40)]

    return {
        "raw_directory": str(directory),
        "host": json.loads((directory / "trial/host.json").read_text()),
        "limitations": __doc__,
        "sending": json.loads((trial / "report.json").read_text())["sending"],
        "send_window": window, "profiles": profiles,
        "sample_weight_ns": total, "builder_sample_weight_ns": builder_total,
        "whole_trial_skip_counters": {
            key: int(value) for key, value in payload_metric_deltas(trial).items()
            if "pool_transactions_skipped_total" in key and value
        },
        "node_flat": table(node_flat, total),
        "builder_flat": table(builder_flat, builder_total),
        "builder_inclusive": table(builder_inclusive, builder_total),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize(args.directory.resolve()), indent=2))
