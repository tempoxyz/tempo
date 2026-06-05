#!/usr/bin/env python
"""Generate scatter plots for tempo e2e benchmark sample distributions."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def number(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def values(run: dict[str, Any], key: str) -> list[float]:
    raw = run.get(key) or []
    if not isinstance(raw, list):
        return []
    parsed = [number(value) for value in raw]
    return [value for value in parsed if value is not None]


def group_name(label: str) -> str:
    if label.startswith("baseline"):
        return "baseline"
    if label.startswith("feature"):
        return "feature"
    return "other"


def scatter_builder_latency(
    per_run: list[dict[str, Any]],
    output: Path,
    baseline_name: str,
    feature_name: str,
) -> None:
    rng = random.Random(1337)
    colors = {
        "baseline": "#4c78a8",
        "feature": "#f58518",
        "other": "#777777",
    }
    display_names = {
        "baseline": baseline_name or "baseline",
        "feature": feature_name or "feature",
        "other": "other",
    }

    fig, ax = plt.subplots(figsize=(14, 7), constrained_layout=True)
    seen_groups: set[str] = set()
    tick_positions: list[int] = []
    tick_labels: list[str] = []

    for idx, run in enumerate(per_run, start=1):
        label = str(run.get("label") or f"run-{idx}")
        samples = values(run, "builder_latency_ms")
        if not samples:
            continue

        group = group_name(label)
        xs = [idx + rng.uniform(-0.18, 0.18) for _ in samples]
        plot_label = display_names[group] if group not in seen_groups else None
        ax.scatter(xs, samples, s=13, alpha=0.42, color=colors[group], label=plot_label)
        seen_groups.add(group)
        tick_positions.append(idx)
        tick_labels.append(label)

    if not tick_positions:
        raise SystemExit("summary.json has no builder_latency_ms samples")

    ax.set_title("Builder latency samples")
    ax.set_xlabel("Run")
    ax.set_ylabel("Builder latency (ms)")
    ax.set_xticks(tick_positions)
    ax.set_xticklabels(tick_labels, rotation=30, ha="right")
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend()
    fig.savefig(output, dpi=160)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--baseline-name", default="baseline")
    parser.add_argument("--feature-name", default="feature")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with (results_dir / "summary.json").open() as f:
        summary = json.load(f)

    per_run = summary.get("per_run") or []
    if not per_run:
        raise SystemExit("summary.json has no per_run data")

    scatter_builder_latency(
        per_run,
        output_dir / "builder_latency_scatter.png",
        args.baseline_name,
        args.feature_name,
    )
    print(f"Charts written to {output_dir}")


if __name__ == "__main__":
    main()
