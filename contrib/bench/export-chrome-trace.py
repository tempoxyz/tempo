#!/usr/bin/env python3
"""Export Tempo OTLP spans as Chrome trace JSON for Perfetto."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
import urllib.request


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def normalize_tempo_base(url: str) -> str:
    url = url.rstrip("/")
    for suffix in ("/opentelemetry/v1/traces", "/v1/traces"):
        if url.endswith(suffix):
            return url[: -len(suffix)]
    return url


def tempo_url(base: str, path: str, params: dict[str, str]) -> str:
    base = base.rstrip("/")
    if params:
        return f"{base}{path}?{urllib.parse.urlencode(params)}"
    return f"{base}{path}"


def attr_map(attrs: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for attr in attrs:
        key = attr.get("key")
        value = attr.get("value", {})
        if not key:
            continue
        if "stringValue" in value:
            out[key] = value["stringValue"]
        elif "intValue" in value:
            out[key] = str(value["intValue"])
        elif "boolValue" in value:
            out[key] = str(value["boolValue"])
    return out


def value_for_attr(value: dict) -> object:
    for key in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if key in value:
            return value[key]
    if "arrayValue" in value:
        return value["arrayValue"]
    if "kvlistValue" in value:
        return value["kvlistValue"]
    return value


def span_events(trace: dict) -> list[dict]:
    events: list[dict] = []
    process_names: dict[int, str] = {}
    thread_names: set[tuple[int, int, str]] = set()

    for resource_span in trace.get("resourceSpans", []):
        resource_attrs = attr_map(resource_span.get("resource", {}).get("attributes", []))
        service = resource_attrs.get("service.name", "tempo")
        run = resource_attrs.get("benchmark_run", resource_attrs.get("benchmark_id", "bench"))
        pid = abs(hash(service)) % 100000
        tid = abs(hash(run)) % 100000
        process_names[pid] = service
        thread_names.add((pid, tid, run))

        for scope_span in resource_span.get("scopeSpans", []):
            for span in scope_span.get("spans", []):
                start = int(span.get("startTimeUnixNano", "0"))
                end = int(span.get("endTimeUnixNano", "0"))
                if start <= 0 or end <= start:
                    continue
                args = resource_attrs.copy()
                args.update(
                    {
                        attr["key"]: value_for_attr(attr.get("value", {}))
                        for attr in span.get("attributes", [])
                        if "key" in attr
                    }
                )
                events.append(
                    {
                        "name": span.get("name", "span"),
                        "cat": scope_span.get("scope", {}).get("name", "tracing"),
                        "ph": "X",
                        "ts": start / 1000,
                        "dur": (end - start) / 1000,
                        "pid": pid,
                        "tid": tid,
                        "args": args,
                    }
                )

    for pid, name in process_names.items():
        events.append({"name": "process_name", "ph": "M", "pid": pid, "args": {"name": name}})
    for pid, tid, name in thread_names:
        events.append({"name": "thread_name", "ph": "M", "pid": pid, "tid": tid, "args": {"name": name}})

    return events


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tempo-url", required=True)
    parser.add_argument("--benchmark-id", required=True)
    parser.add_argument("--run-label", required=True)
    parser.add_argument("--start", type=int, required=True, help="Unix seconds")
    parser.add_argument("--end", type=int, required=True, help="Unix seconds")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    query = f'{{resource.benchmark_id="{args.benchmark_id}" && resource.benchmark_run="{args.run_label}"}}'
    tempo_base = normalize_tempo_base(args.tempo_url)
    search_url = tempo_url(
        tempo_base,
        "/api/search",
        {"q": query, "start": str(args.start), "end": str(args.end), "limit": "100"},
    )
    search = get_json(search_url)
    traces = search.get("traces", [])
    if not traces:
        print(f"no traces found for {args.benchmark_id}/{args.run_label}", file=sys.stderr)
        return 2

    events: list[dict] = []
    for trace in traces:
        trace_id = trace.get("traceID") or trace.get("traceId")
        if not trace_id:
            continue
        trace_url = tempo_url(tempo_base, f"/api/traces/{trace_id}", {})
        events.extend(span_events(get_json(trace_url)))

    if not events:
        print(f"no span events found for {args.benchmark_id}/{args.run_label}", file=sys.stderr)
        return 3

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"traceEvents": events, "displayTimeUnit": "ns"}, f)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
