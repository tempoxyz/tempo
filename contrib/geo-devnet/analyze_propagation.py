#!/usr/bin/env python3
from __future__ import annotations

"""Analyze block propagation delays across geo-distributed validators.

Parses docker logs from eu-val-0, eu-val-1, us-val-2, us-val-3 and computes
receive delays using a receiver-side marker after the block is available locally.
By default it uses ``sending block to execution layer for verification``. It
also correlates each view with the proposer's ``Built payload`` log so large
blocks can be filtered by transaction count.

Usage:
    python3 contrib/geo-devnet/analyze_propagation.py [--min-view N]

Important:
    The default receiver-side marker is an INFO log emitted by Tempo right
    before handing the block to the execution layer. For older runs, you can
    fall back to the earlier DEBUG marker from commonware-consensus with
    ``--receiver-marker requested_verify``.
"""

import argparse
from dataclasses import dataclass, field
import re
import statistics
import subprocess
import sys
from datetime import datetime, timezone

CONTAINERS = ["eu-val-0", "eu-val-1", "us-val-2", "us-val-3"]

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
TIMESTAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)")

PROPOSAL_RE = re.compile(
    r"view=(\d+).*?constructed proposal.*?"
    r"proposal\.digest=(0x[0-9a-f]+).*?proposal\.height=(\d+)"
)
BUILT_PAYLOAD_RE = re.compile(
    r"Built payload.*?"
    r"number=(\d+).*?"
    r"hash=(0x[0-9a-f]+).*?"
    r"gas_used=(\d+).*?"
    r"payment_transactions=(\d+).*?"
    r"total_transactions=(\d+)"
)
VIEW_EQUALS_RE = re.compile(r"view=(\d+)")
VIEW_DEBUG_RE = re.compile(r"view: View\((\d+)\)")
BLOCK_DIGEST_RE = re.compile(r"block\.digest=(0x[0-9a-f]+)")
BLOCK_HEIGHT_RE = re.compile(r"block\.height=(\d+)")

SENDER_MARKERS = {
    "marshal_request": {
        "needle": "requesting marshal to broadcast proposed block body",
        "digest_re": BLOCK_DIGEST_RE,
        "height_re": BLOCK_HEIGHT_RE,
        "view_required": True,
    },
    "marshal_accepted": {
        "needle": "marshal accepted proposed block body for broadcast",
        "digest_re": BLOCK_DIGEST_RE,
        "height_re": BLOCK_HEIGHT_RE,
        "view_required": True,
    },
    "buffer_handoff": {
        "needle": "handing proposed block body to buffered broadcast",
        "digest_re": BLOCK_DIGEST_RE,
        "height_re": BLOCK_HEIGHT_RE,
        "view_required": True,
    },
    "buffer_sent": {
        "needle": "buffered broadcast handed proposed block body to network",
        "digest_re": BLOCK_DIGEST_RE,
        "height_re": BLOCK_HEIGHT_RE,
        "view_required": True,
    },
}

RECEIVER_MARKERS = {
    "broadcast_received": {
        "needle": "received block body on broadcast channel",
        "digest_re": BLOCK_DIGEST_RE,
        "height_re": BLOCK_HEIGHT_RE,
    },
    "execution_layer": {
        "needle": "sending block to execution layer for verification",
        "digest_re": BLOCK_DIGEST_RE,
        "height_re": BLOCK_HEIGHT_RE,
    },
    "requested_verify": {
        "needle": "requested proposal verification",
        "digest_re": re.compile(r"payload: Digest\((0x[0-9a-f]+)\)"),
        "view_required": True,
    },
    "marshal_wait": {
        "needle": "waiting for block digest to resolve from marshal for verification",
        "digest_re": BLOCK_DIGEST_RE,
    },
    "buffer_wait": {
        "needle": "waiting for block digest from buffered broadcast cache",
        "digest_re": BLOCK_DIGEST_RE,
    },
    "buffer_resolved": {
        "needle": "resolved block digest from buffered broadcast cache",
        "digest_re": BLOCK_DIGEST_RE,
        "height_re": BLOCK_HEIGHT_RE,
    },
    "marshal_resolved": {
        "needle": "resolved block digest for verification",
        "digest_re": BLOCK_DIGEST_RE,
        "height_re": BLOCK_HEIGHT_RE,
    },
}


@dataclass(frozen=True)
class ProposalInfo:
    ts: datetime
    digest: str
    height: int


@dataclass(frozen=True)
class StageHit:
    ts: datetime
    digest: str
    height: int | None = None
    view: int | None = None


@dataclass
class StageIndex:
    by_view: dict[int, StageHit] = field(default_factory=dict)
    by_digest: dict[str, StageHit] = field(default_factory=dict)


@dataclass(frozen=True)
class PayloadInfo:
    number: int
    digest: str
    gas_used: int
    payment_transactions: int
    total_transactions: int


def region_of(container: str) -> str:
    return container.split("-", 1)[0]


def fmt_ms(value: float | None) -> str:
    return f"{value:.1f}" if value is not None else "N/A"


def parse_timestamp(ts_str: str) -> datetime:
    # Handle variable-length fractional seconds
    ts_str = ts_str.rstrip("Z")
    if "." in ts_str:
        base, frac = ts_str.split(".")
        frac = frac[:6].ljust(6, "0")
        ts_str = f"{base}.{frac}"
    return datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc)


def parse_view(line: str) -> int | None:
    for regex in (VIEW_EQUALS_RE, VIEW_DEBUG_RE):
        match = regex.search(line)
        if match:
            return int(match.group(1))
    return None


def record_stage_hit(index: StageIndex, hit: StageHit):
    if hit.view is not None and hit.view not in index.by_view:
        index.by_view[hit.view] = hit
    index.by_digest.setdefault(hit.digest, hit)


def get_stage_hit(stage_index: StageIndex, view: int, digest: str) -> StageHit | None:
    hit = stage_index.by_view.get(view)
    if hit is not None and hit.digest == digest:
        return hit
    return stage_index.by_digest.get(digest)


def fetch_logs(container: str) -> list[str]:
    result = subprocess.run(
        ["docker", "logs", container],
        capture_output=True,
        text=True,
    )
    # Logs may be on stdout or stderr depending on the logging driver
    lines = (result.stdout + result.stderr).splitlines()
    return [ANSI_RE.sub("", line) for line in lines]


def parse_container_logs(lines: list[str]):
    """Return proposals, stage hits, and built-payload metadata."""
    proposals = {}          # view -> ProposalInfo
    sender_hits = {name: StageIndex() for name in SENDER_MARKERS}
    marker_hits = {name: StageIndex() for name in RECEIVER_MARKERS}
    payloads_by_hash = {}   # digest -> PayloadInfo
    payloads_by_height = {} # height -> PayloadInfo

    for line in lines:
        ts_match = TIMESTAMP_RE.search(line)
        if not ts_match:
            continue
        ts = parse_timestamp(ts_match.group(1))

        m = PROPOSAL_RE.search(line)
        if m:
            view = int(m.group(1))
            digest = m.group(2).lower()
            height = int(m.group(3))
            proposals[view] = ProposalInfo(ts=ts, digest=digest, height=height)
            continue

        for marker_name, marker in SENDER_MARKERS.items():
            if marker["needle"] not in line:
                continue
            view = parse_view(line)
            if marker.get("view_required") and view is None:
                continue
            digest_match = marker["digest_re"].search(line)
            if not digest_match:
                continue
            digest = digest_match.group(1).lower()
            height = None
            if "height_re" in marker:
                height_match = marker["height_re"].search(line)
                if height_match:
                    height = int(height_match.group(1))
            record_stage_hit(
                sender_hits[marker_name],
                StageHit(ts=ts, digest=digest, height=height, view=view),
            )
            break

        for marker_name, marker in RECEIVER_MARKERS.items():
            if marker["needle"] not in line:
                continue
            view = parse_view(line)
            if marker.get("view_required") and view is None:
                continue
            digest_match = marker["digest_re"].search(line)
            if not digest_match:
                continue
            digest = digest_match.group(1).lower()
            height = None
            if "height_re" in marker:
                height_match = marker["height_re"].search(line)
                if height_match:
                    height = int(height_match.group(1))
            record_stage_hit(
                marker_hits[marker_name],
                StageHit(ts=ts, digest=digest, height=height, view=view),
            )
            break

        m = BUILT_PAYLOAD_RE.search(line)
        if m:
            payload = PayloadInfo(
                number=int(m.group(1)),
                digest=m.group(2).lower(),
                gas_used=int(m.group(3)),
                payment_transactions=int(m.group(4)),
                total_transactions=int(m.group(5)),
            )
            payloads_by_hash[payload.digest] = payload
            payloads_by_height[payload.number] = payload

    return proposals, sender_hits, marker_hits, payloads_by_hash, payloads_by_height


def main():
    parser = argparse.ArgumentParser(description="Analyze block propagation delays")
    parser.add_argument(
        "--min-view", type=int, default=0,
        help="Only analyze views above this number",
    )
    parser.add_argument(
        "--max-view", type=int,
        help="Only analyze views at or below this number",
    )
    parser.add_argument(
        "--min-total-transactions", type=int, default=0,
        help="Only show views whose built payload has at least this many transactions",
    )
    parser.add_argument(
        "--max-total-transactions", type=int,
        help="Only show views whose built payload has at most this many transactions",
    )
    parser.add_argument(
        "--min-gas-used", type=int, default=0,
        help="Only show views whose built payload has at least this much gas used",
    )
    parser.add_argument(
        "--max-gas-used", type=int,
        help="Only show views whose built payload has at most this much gas used",
    )
    parser.add_argument(
        "--proposer-region", choices=["all", "eu", "us"], default="all",
        help="Only show views proposed by validators in this region",
    )
    parser.add_argument(
        "--sender-marker",
        choices=["constructed_proposal", *SENDER_MARKERS],
        default="constructed_proposal",
        help=(
            "Proposer-side timestamp to use as the baseline. constructed_proposal uses "
            "Tempo's proposal-construction log; marshal_request, marshal_accepted, "
            "buffer_handoff, and buffer_sent isolate later sender-side stages."
        ),
    )
    parser.add_argument(
        "--receiver-marker",
        choices=list(RECEIVER_MARKERS),
        default="execution_layer",
        help=(
            "Receiver-side timestamp to use. execution_layer is the default and uses "
            "Tempo's INFO log just before verify_block(...). New upstream options include "
            "broadcast_received, marshal_wait, buffer_wait, buffer_resolved, and marshal_resolved."
        ),
    )
    args = parser.parse_args()

    # Collect data from all containers
    container_data = {}
    for c in CONTAINERS:
        print(f"Fetching logs from {c}...", file=sys.stderr)
        lines = fetch_logs(c)
        proposals, sender_hits, marker_hits, payloads_by_hash, payloads_by_height = parse_container_logs(lines)
        container_data[c] = {
            "proposals": proposals,
            "sender_hits": sender_hits,
            "marker_hits": marker_hits,
            "payloads_by_hash": payloads_by_hash,
            "payloads_by_height": payloads_by_height,
        }

    # Build a map: view -> proposer container
    view_proposer = {}
    for c in CONTAINERS:
        for view in container_data[c]["proposals"]:
            view_proposer[view] = c

    if not any(
        container_data[c]["marker_hits"][args.receiver_marker].by_view
        or container_data[c]["marker_hits"][args.receiver_marker].by_digest
        for c in CONTAINERS
    ):
        print(
            "No receiver-side markers found for the selected marker. For older runs, "
            "try --receiver-marker requested_verify with "
            "RUST_LOG=info,commonware_consensus=debug.",
            file=sys.stderr,
        )
        sys.exit(1)

    # For each view, compute receive delays for non-proposer validators.
    rows = []
    all_views = sorted(view_proposer.keys())

    for view in all_views:
        if view < args.min_view:
            continue
        if args.max_view is not None and view > args.max_view:
            continue

        proposer = view_proposer[view]
        proposer_region = region_of(proposer)
        if args.proposer_region != "all" and proposer_region != args.proposer_region:
            continue

        proposal = container_data[proposer]["proposals"][view]
        if args.sender_marker == "constructed_proposal":
            sender_hit = StageHit(
                ts=proposal.ts,
                digest=proposal.digest,
                height=proposal.height,
                view=view,
            )
        else:
            sender_hit = get_stage_hit(
                container_data[proposer]["sender_hits"][args.sender_marker],
                view,
                proposal.digest,
            )
            if sender_hit is None:
                continue
        t0 = sender_hit.ts

        payload = container_data[proposer]["payloads_by_hash"].get(proposal.digest)
        if payload is None:
            payload = container_data[proposer]["payloads_by_height"].get(proposal.height)
        if payload is None:
            continue
        if payload.total_transactions < args.min_total_transactions:
            continue
        if args.max_total_transactions is not None and payload.total_transactions > args.max_total_transactions:
            continue
        if payload.gas_used < args.min_gas_used:
            continue
        if args.max_gas_used is not None and payload.gas_used > args.max_gas_used:
            continue

        # Compute delays per non-proposer
        delays = {}
        for c in CONTAINERS:
            if c == proposer:
                continue
            hit = get_stage_hit(
                container_data[c]["marker_hits"][args.receiver_marker],
                view,
                proposal.digest,
            )
            if hit is None:
                continue
            t_recv = hit.ts
            delay_ms = (t_recv - t0).total_seconds() * 1000
            delays[c] = delay_ms

        same_region_delays = [
            delay for c, delay in delays.items() if region_of(c) == proposer_region
        ]
        cross_region_delays = [
            delay for c, delay in delays.items() if region_of(c) != proposer_region
        ]

        if same_region_delays or cross_region_delays:
            same_region_ms = (
                statistics.median(same_region_delays) if same_region_delays else None
            )
            cross_region_ms = (
                statistics.median(cross_region_delays) if cross_region_delays else None
            )
            diff = None
            if same_region_ms is not None and cross_region_ms is not None:
                diff = cross_region_ms - same_region_ms
            rows.append(
                {
                    "view": view,
                    "height": proposal.height,
                    "proposer": proposer,
                    "proposer_region": proposer_region,
                    "digest": proposal.digest,
                    "payment_transactions": payload.payment_transactions,
                    "total_transactions": payload.total_transactions,
                    "gas_used": payload.gas_used,
                    "same_region_ms": same_region_ms,
                    "cross_region_ms": cross_region_ms,
                    "diff_ms": diff,
                    "receiver_delays": delays,
                }
            )

    if not rows:
        print("No matching views found.", file=sys.stderr)
        sys.exit(0)

    # Print table
    hdr = (
        f"{'View':>6}  {'Hgt':>5}  {'Prop':<10}  {'Txs':>6}  {'PayTx':>6}  "
        f"{'GasUsed':>10}  {'Same (ms)':>10}  {'Cross (ms)':>11}  {'Diff (ms)':>10}"
    )
    print(f"Sender marker:   {args.sender_marker}")
    print(f"Receiver marker: {args.receiver_marker}")
    print(hdr)
    print("-" * len(hdr))

    same_delays = []
    cross_delays = []
    diffs = []
    same_details = {"eu": [], "us": []}
    cross_details = {"eu": [], "us": []}

    for row in rows:
        print(
            f"{row['view']:6d}  {row['height']:5d}  {row['proposer']:<10}  "
            f"{row['total_transactions']:6d}  {row['payment_transactions']:6d}  "
            f"{row['gas_used']:10d}  {fmt_ms(row['same_region_ms']):>10}  "
            f"{fmt_ms(row['cross_region_ms']):>11}  {fmt_ms(row['diff_ms']):>10}"
        )

        if row["same_region_ms"] is not None:
            same_delays.append(row["same_region_ms"])
            same_details[row["proposer_region"]].append(row["same_region_ms"])
        if row["cross_region_ms"] is not None:
            cross_delays.append(row["cross_region_ms"])
            cross_details[row["proposer_region"]].append(row["cross_region_ms"])
        if row["diff_ms"] is not None:
            diffs.append(row["diff_ms"])

    # Summary stats
    print()
    print("Summary")
    print("-------")
    if same_delays:
        print(f"  Median same-region delay:   {statistics.median(same_delays):.1f} ms")
    if cross_delays:
        print(f"  Median cross-region delay:  {statistics.median(cross_delays):.1f} ms")
    if diffs:
        print(f"  Median cross-same diff:     {statistics.median(diffs):.1f} ms")

    for region in ("eu", "us"):
        if same_details[region] or cross_details[region]:
            if same_details[region]:
                print(
                    f"  {region.upper()} proposer median same-region:  "
                    f"{statistics.median(same_details[region]):.1f} ms"
                )
            if cross_details[region]:
                print(
                    f"  {region.upper()} proposer median cross-region: "
                    f"{statistics.median(cross_details[region]):.1f} ms"
                )

    print(f"  Rows shown:                  {len(rows)}")


if __name__ == "__main__":
    main()
