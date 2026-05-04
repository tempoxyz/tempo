#!/usr/bin/env python3

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: txgen-report-adapter.py <txgen-report.json> <tempo-report.json>", file=sys.stderr)
        return 1

    source_path = Path(sys.argv[1])
    dest_path = Path(sys.argv[2])

    with source_path.open() as f:
        report = json.load(f)

    metadata = dict(report.get("metadata") or {})
    run_stats = report.get("run_stats") or {}
    blocks = report.get("blocks") or []

    adapted_blocks = []
    for block in blocks:
        tx_count = int(block.get("tx_count", 0))
        adapted_blocks.append(
            {
                "number": int(block.get("number", 0)),
                "timestamp": int(block.get("timestamp_ms", 0)),
                "tx_count": tx_count,
                "ok_count": tx_count,
                "err_count": 0,
                "gas_used": int(block.get("gas_used", 0)),
                # txgen does not currently expose per-block end-to-end latency in
                # Tempo's report shape. Use block time as the closest proxy so the
                # existing summary pipeline still has a non-null latency series.
                "latency_ms": block.get("block_time_ms"),
            }
        )

    adapted = {
        "metadata": {
            "chain_id": int(metadata.get("chain_id", 0)),
            "start_block": int(run_stats.get("start_block", 0)),
            "end_block": int(run_stats.get("end_block", 0)),
            "target_tps": int(metadata.get("target_tps", 0)),
            "run_duration_secs": int(metadata.get("run_duration_secs", 0)),
            "accounts": int(metadata.get("accounts", 0)),
            "total_connections": int(metadata.get("total_connections", 0)),
            "tip20_weight": float(metadata.get("tip20_weight", 0.0)),
            "place_order_weight": float(metadata.get("place_order_weight", 0.0)),
            "swap_weight": float(metadata.get("swap_weight", 0.0)),
            "erc20_weight": float(metadata.get("erc20_weight", 0.0)),
            "node_commit_sha": metadata.get("node_commit_sha", ""),
            "build_profile": metadata.get("build_profile", ""),
            "mode": metadata.get("mode", ""),
        },
        "blocks": adapted_blocks,
        "txgen": {
            "sent": int(report.get("sent", 0)),
            "success": int(report.get("success", 0)),
            "failed": int(report.get("failed", 0)),
            "elapsed_secs": float(report.get("elapsed_secs", 0.0)),
            "tps": float(report.get("tps", 0.0)),
            "success_rate": float(report.get("success_rate", 0.0)),
            "latency": report.get("latency") or {},
        },
    }

    with dest_path.open("w") as f:
        json.dump(adapted, f, indent=2)
        f.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
