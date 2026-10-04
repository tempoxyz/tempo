#!/usr/bin/env python3
"""Select a completed snapshot whose entire replay window exists on the source."""

import argparse
import json
import re
import sys


def select_snapshot(listing, prefix, source_response, blocks, warmup, requested=None):
    if blocks < 0 or warmup < 0:
        raise ValueError("Replay block and warmup counts must be non-negative")
    try:
        response = json.loads(source_response)
    except (TypeError, ValueError) as error:
        raise ValueError("Replay source returned invalid JSON for eth_blockNumber") from error
    if not isinstance(response, dict) or response.get("error") is not None:
        raise ValueError("Replay source returned an error for eth_blockNumber")
    head = response.get("result")
    if not isinstance(head, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", head):
        raise ValueError("Replay source returned an invalid eth_blockNumber result")
    head = int(head, 16)

    pattern = re.compile(re.escape(prefix) + r"([0-9]+)-([0-9]+)")
    snapshots = set()
    for line in listing.splitlines():
        fields = line.split()
        if not fields:
            continue
        name = fields[-1].rstrip("/")
        if match := pattern.fullmatch(name):
            snapshots.add((int(match[1]), int(match[2]), name))
    snapshots = sorted(snapshots)
    if len(snapshots) < 2:
        raise ValueError(f"Need at least 2 snapshots matching {prefix}*, found {len(snapshots)}")

    if requested:
        # A pin must still satisfy the chain, completed-listing, newest-exclusion,
        # and source-range checks. Never interpret an arbitrary input as a path.
        candidates = [item for item in snapshots[:-1] if item[2] == requested]
        if not candidates:
            raise ValueError("Requested snapshot must be listed for this chain and cannot be the newest")
        height, _, name = candidates[0]
        end = height + warmup + blocks
        if end > head:
            raise ValueError("Requested snapshot replay window exceeds the source head")
        return name, head, height + 1, end

    # Preserve the existing policy of excluding the newest snapshot. If the
    # second-newest is too recent, use an older one instead of replaying past head.
    for height, _, name in reversed(snapshots[:-1]):
        end = height + warmup + blocks
        if end <= head:
            return name, head, height + 1, end
    raise ValueError(
        f"No snapshot excluding the newest can provide {warmup} warmup + {blocks} "
        f"measured blocks at source head {head}; oldest snapshot is {snapshots[0][0]}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--source-head", required=True, help="eth_blockNumber JSON-RPC response")
    parser.add_argument("--blocks", required=True, type=int)
    parser.add_argument("--warmup", required=True, type=int)
    parser.add_argument("--snapshot", help="Pin a listed snapshot while retaining all eligibility checks")
    args = parser.parse_args()
    try:
        name, head, start, end = select_snapshot(
            sys.stdin.read(), args.prefix, args.source_head, args.blocks, args.warmup, args.snapshot
        )
    except ValueError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(f"Replay source head: {head}; available requested range: {start}..{end}", file=sys.stderr)
    print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
