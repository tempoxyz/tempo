"""Reconcile per-build lane diagnostics with measured benchmark blocks."""
import argparse
import collections
import csv
import json
import pathlib
import re

parser = argparse.ArgumentParser()
parser.add_argument("root", type=pathlib.Path)
parser.add_argument("--phase", default="feature-1")
parser.add_argument("--output", type=pathlib.Path, required=True)
args = parser.parse_args()
report = json.loads((args.root / args.phase / "txgen-report.json").read_text())
blocks = report["blocks"]
hashes = {b.get("hash", b.get("block_hash")) for b in blocks} - {None, ""}
numbers = {int(b["number"]): b for b in blocks}
ansi = re.compile(r"\x1b\[[0-9;]*m")
fields = re.compile(r'(\w+)=("[^"\n]*"|[^\s]+)')
events = collections.defaultdict(lambda: {"lanes": []})
seen = set()
canonical = set()
log_files = list(args.root.rglob("tempo-node.log"))
for path in log_files:
    node = re.search(r"validator-\d+", str(path))
    node = node.group() if node else str(path.relative_to(args.root))
    for line in path.open(errors="replace"):
        if "Block added to canonical chain" in line:
            canonical_line = ansi.sub("", line)
            canonical_match = re.search(r"Block added to canonical chain number=(\d+) hash=(0x[0-9a-f]+)", canonical_line)
            if canonical_match:
                canonical.add((int(canonical_match[1]), canonical_match[2]))
        if "prewarm_" not in line:
            continue
        line = ansi.sub("", line)
        event_match = re.search(r"\b(prewarm_cutoff|prewarm_payload|prewarm_build|prewarm_lane)\b", line)
        if not event_match:
            continue
        event = event_match.group()
        parsed = {}
        for key, value in fields.findall(line[event_match.end():]):
            value = value.strip('"')
            parsed[key] = int(value) if value.isdigit() else value
        if "build_id" not in parsed:
            raise ValueError(f"unparsed diagnostic: {line[:500]}")
        identity = (node, event, tuple(sorted(parsed.items())))
        if identity in seen:
            continue
        seen.add(identity)
        key = (node, parsed["build_id"])
        if event == "prewarm_lane":
            events[key]["lanes"].append(parsed)
        else:
            if event in events[key] and events[key][event] != parsed:
                raise ValueError(f"process restart or conflicting build ID: {key}")
            events[key][event] = parsed

chosen = []
missing_summaries = []
for (node, build_id), entry in events.items():
    payload = entry.get("prewarm_payload")
    if not payload:
        continue
    if hashes:
        measured = payload["hash"] in hashes
    else:
        block = numbers.get(payload["block"])
        measured = block is not None and int(block["timestamp_ms"]) == payload["timestamp_ms"]
    if not measured:
        continue
    if "prewarm_build" not in entry or "prewarm_cutoff" not in entry:
        missing_summaries.append((node, build_id, payload["block"]))
        continue
    included = sum(r["count"] for r in entry["lanes"] if r["outcome"] in (1, 2))
    if included != entry["prewarm_cutoff"]["included"]:
        raise ValueError(f"included count mismatch: {(node, build_id)} {included} {entry['prewarm_cutoff']}")
    report_block = numbers[payload["block"]]
    if "tx_count" in report_block and included != report_block["tx_count"]:
        raise ValueError(f"report transaction count mismatch: {(node, build_id)}")
    if "gas_used" in report_block and entry["prewarm_cutoff"]["total_gas"] != report_block["gas_used"]:
        raise ValueError(f"report gas mismatch: {(node, build_id)}")
    for r in entry["lanes"]:
        if r["count"] != r["worker_finished"]:
            raise ValueError(f"unfinished prewarm records: {(node, build_id)} {r}")
    chosen.append((node, build_id, entry))

rows = [{"node": node, **row} for node, _, e in chosen for row in e["lanes"]]
def total(name, predicate=lambda r: True):
    return sum(r[name] for r in rows if predicate(r))

def payment(r):
    return r["payment"] == "true"

def included_payment(r):
    return payment(r) and r["outcome"] in (1, 2)

def ratio(a, b):
    return 100 * a / b if b else None

worker = total("worker_before_cutoff_ns")
worker_after_cap = total("worker_after_cap_ns")
worker_capacity = sum(e["prewarm_build"]["cutoff_ns"] * e["prewarm_build"]["worker_threads"] for _, _, e in chosen)
payments = total("count", included_payment)
execution_groups = {}
for readiness in range(1, 7):
    pred = lambda r: included_payment(r) and r["readiness"] == readiness
    count = total("count", pred)
    execution_groups[readiness] = {
        "count": count,
        "mean_payload_execution_us": total("execution_ns", pred) / count / 1000 if count else None,
        "successful_count": total("count", lambda r: pred(r) and r["outcome"] == 1),
    }
summary = {
    "phase": args.phase,
    "matching": "block hash" if hashes else "block number and exact timestamp",
    "log_files": len(log_files),
    "report_blocks": len(blocks),
    "matched_builds": len(chosen),
    "matched_heights": len({e["prewarm_payload"]["block"] for _, _, e in chosen}),
    "canonical_hashes_verified": sum((e["prewarm_payload"]["block"], e["prewarm_payload"]["hash"]) in canonical for _, _, e in chosen),
    "missing_summaries": missing_summaries,
    "parallel_modes": sorted({e["prewarm_build"]["parallel"] for _, _, e in chosen}),
    "worker_counts": sorted({e["prewarm_build"]["worker_threads"] for _, _, e in chosen}),
    "scheduled": total("count"),
    "included_payments": payments,
    "included_general": total("count", lambda r: not payment(r) and r["outcome"] in (1, 2)),
    "included_payment_before_prewarm_finished_pct": ratio(total("count", lambda r: included_payment(r) and r["readiness"] in (1, 2)), payments),
    "included_payment_successfully_prewarmed_pct": ratio(total("count", lambda r: included_payment(r) and r["readiness"] == 3), payments),
    "general_worker_share_pct": ratio(total("worker_before_cutoff_ns", lambda r: not payment(r)), worker),
    "nonfitting_general_worker_share_pct": ratio(total("worker_before_cutoff_ns", lambda r: r["nonfitting_at_start"] == 1), worker),
    "general_cap_rejected_worker_share_pct": ratio(total("worker_before_cutoff_ns", lambda r: r["outcome"] == 3), worker),
    "general_worker_share_after_first_cap_rejection_pct": ratio(total("worker_after_cap_ns", lambda r: not payment(r)), worker_after_cap),
    "worker_time_ms": worker / 1e6,
    "worker_full_time_ms": total("worker_ns") / 1e6,
    "worker_after_cutoff_ms": (total("worker_ns") - worker) / 1e6,
    "general_worker_after_cutoff_ms": (total("worker_ns", lambda r: not payment(r)) - total("worker_before_cutoff_ns", lambda r: not payment(r))) / 1e6,
    "average_prewarm_worker_occupancy_pct": ratio(worker, worker_capacity),
    "nonfitting_general_worker_capacity_pct": ratio(total("worker_before_cutoff_ns", lambda r: r["nonfitting_at_start"] == 1), worker_capacity),
    "mean_included_payment_queue_us": total("queue_ns", included_payment) / payments / 1000 if payments else None,
    "worker_after_first_cap_ms": worker_after_cap / 1e6,
    "builder_next_ms": sum(e["prewarm_build"]["next_ns"] for _, _, e in chosen) / 1e6,
    "coordinator_invalidation_ms_including_after_cutoff": sum(e["prewarm_build"]["invalidation_ns"] for _, _, e in chosen) / 1e6,
    "coordinator_invalidations": sum(e["prewarm_build"]["invalidations"] for _, _, e in chosen),
    "buffer_items_scanned": sum(e["prewarm_build"]["drained"] for _, _, e in chosen),
    "fill_ms": sum(e["prewarm_cutoff"]["fill_ns"] for _, _, e in chosen) / 1e6,
    "payload_execution_ms": total("execution_ns") / 1e6,
    "payments_by_readiness": execution_groups,
    "outcome_counts": {i: total("count", lambda r: r["outcome"] == i) for i in range(6)},
    "prewarm_success": total("worker_success"),
    "prewarm_revert": total("worker_revert"),
    "prewarm_error": total("worker_error"),
}
blocks_out = []
for node, build_id, e in chosen:
    lane_rows = e["lanes"]
    def block_total(field, pred=lambda r: True):
        return sum(r[field] for r in lane_rows if pred(r))
    pay_count = block_total("count", included_payment)
    worker_time = block_total("worker_before_cutoff_ns")
    cutoff = e["prewarm_cutoff"]
    build = e["prewarm_build"]
    if build["next_ns"] + block_total("execution_ns") > cutoff["fill_ns"]:
        raise ValueError(f"non-overlapping builder timers exceed fill time: {node} {build_id}")
    blocks_out.append({
        "node": node, **build, **cutoff, **e["prewarm_payload"],
        "included_payments": pay_count,
        "included_general": block_total("count", lambda r: not payment(r) and r["outcome"] in (1, 2)),
        "general_cap_rejections": block_total("count", lambda r: r["outcome"] == 3),
        "payments_prewarm_incomplete": block_total("count", lambda r: included_payment(r) and r["readiness"] in (1, 2)),
        "payment_prewarm_incomplete_pct": ratio(block_total("count", lambda r: included_payment(r) and r["readiness"] in (1, 2)), pay_count),
        "worker_occupancy_pct": ratio(worker_time, build["cutoff_ns"] * build["worker_threads"]),
        "general_worker_share_pct": ratio(block_total("worker_before_cutoff_ns", lambda r: not payment(r)), worker_time),
        "nonfitting_worker_share_pct": ratio(block_total("worker_before_cutoff_ns", lambda r: r["nonfitting_at_start"] == 1), worker_time),
        "builder_next_fill_pct": ratio(build["next_ns"], cutoff["fill_ns"]),
        "execution_ns": block_total("execution_ns"),
        "payment_execution_ns": block_total("execution_ns", included_payment),
        "general_execution_ns": block_total("execution_ns", lambda r: not payment(r) and r["outcome"] in (1, 2)),
    })

def quantiles(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return {}
    return {str(p): values[round((len(values) - 1) * p / 100)] for p in (0, 50, 90, 95, 99, 100)}

summary["per_block_quantiles"] = {
    field: quantiles(b[field] for b in blocks_out)
    for field in ("included_payments", "included_general", "general_cap_rejections",
                  "payment_prewarm_incomplete_pct", "worker_occupancy_pct",
                  "general_worker_share_pct", "nonfitting_worker_share_pct",
                  "builder_next_fill_pct", "fill_ns", "next_ns", "execution_ns")
}
summary["stop_reasons"] = dict(collections.Counter(b["stop"] for b in blocks_out))
summary["builds_by_node"] = dict(collections.Counter(b["node"] for b in blocks_out))
summary["included_execution_by_lane"] = {}
for is_payment, label in ((True, "payment"), (False, "general")):
    pred = lambda r: payment(r) == is_payment and r["outcome"] in (1, 2)
    count = total("count", pred)
    successful = lambda r: pred(r) and r["outcome"] == 1
    success_count = total("count", successful)
    summary["included_execution_by_lane"][label] = {
        "count": count,
        "successful_count": success_count,
        "mean_us": total("execution_ns", pred) / count / 1000 if count else None,
        "successful_mean_us": total("execution_ns", successful) / success_count / 1000 if success_count else None,
    }
if not chosen:
    raise ValueError(f"no measured complete builds found: {len(log_files)} log files, {len(events)} builds")
args.output.mkdir(parents=True, exist_ok=True)
(args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
with (args.output / "lane-observations.csv").open("w") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
with (args.output / "block-observations.csv").open("w") as f:
    writer = csv.DictWriter(f, fieldnames=list(blocks_out[0]))
    writer.writeheader()
    writer.writerows(blocks_out)
print(json.dumps(summary, indent=2))
