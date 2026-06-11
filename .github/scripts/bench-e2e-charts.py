#!/usr/bin/env python
"""Generate plots for tempo e2e benchmark sample distributions."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


CHARTS = [
    {
        "file": "block_time_scatter.png",
        "sample_key": "block_time_ms",
        "label": "Block Time Scatter",
        "title": "Block time samples",
        "ylabel": "Block time (ms)",
    },
    {
        "file": "serialized_block_size_per_tx_scatter.png",
        "sample_key": "serialized_block_size_per_tx_bytes",
        "label": "Serialized Block Size per Transaction Scatter",
        "title": "Serialized block size per transaction samples",
        "ylabel": "Serialized bytes per transaction",
    },
    {
        "file": "builder_latency_scatter.png",
        "sample_key": "builder_latency_ms",
        "label": "Builder Latency Scatter",
        "title": "Builder latency samples",
        "ylabel": "Builder latency (ms)",
    },
    {
        "file": "builder_finish_scatter.png",
        "sample_key": "builder_finish_ms",
        "label": "Builder Finish Scatter",
        "title": "Builder finish samples",
        "ylabel": "Builder finish (ms)",
    },
    {
        "file": "builder_pool_fetch_scatter.png",
        "sample_key": "builder_pool_fetch_ms",
        "label": "Builder Pool Fetch Scatter",
        "title": "Builder pool fetch samples",
        "ylabel": "Builder pool fetch (ms)",
    },
    {
        "file": "builder_invalid_tx_execution_attempts_scatter.png",
        "sample_key": "builder_invalid_tx_execution_attempts",
        "label": "Builder Invalid Tx Attempts Scatter",
        "title": "Builder invalid transaction attempts samples",
        "ylabel": "Invalid transaction attempts",
    },
    {
        "file": "serialized_block_size_scatter.png",
        "sample_key": "serialized_block_size_bytes",
        "label": "Serialized Block Size Scatter",
        "title": "Serialized block size samples",
        "ylabel": "Serialized block size (bytes)",
    },
    {
        "file": "builder_fill_idle_scatter.png",
        "sample_key": "builder_fill_idle_ms",
        "label": "Builder Fill Idle Scatter",
        "title": "Builder fill idle samples",
        "ylabel": "Builder fill idle (ms)",
    },
    {
        "file": "validation_latency_scatter.png",
        "sample_key": "validation_latency_ms",
        "label": "Validation Latency Scatter",
        "title": "Validation latency samples",
        "ylabel": "Validation latency (ms)",
    },
]


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


def group_values(per_run: list[dict[str, Any]], sample_key: str, group: str) -> list[float]:
    samples: list[float] = []
    for run in per_run:
        label = str(run.get("label") or "")
        if group_name(label) == group:
            samples.extend(values(run, sample_key))
    return samples


def scatter_samples(
    per_run: list[dict[str, Any]],
    output: Path,
    baseline_name: str,
    feature_name: str,
    *,
    sample_key: str,
    title: str,
    ylabel: str,
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
        samples = values(run, sample_key)
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
        raise ValueError(f"summary.json has no {sample_key} samples")

    ax.set_title(title)
    ax.set_xlabel("Run")
    ax.set_ylabel(ylabel)
    ax.set_xticks(tick_positions)
    ax.set_xticklabels(tick_labels, rotation=30, ha="right")
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend()
    fig.savefig(output, dpi=160)
    plt.close(fig)


def distribution_samples(
    per_run: list[dict[str, Any]],
    output: Path,
    display_name: str,
    *,
    sample_key: str,
    group: str,
    title: str,
    xlabel: str,
) -> None:
    samples = group_values(per_run, sample_key, group)
    if not samples:
        raise ValueError(f"summary.json has no {group} {sample_key} samples")

    color = "#4c78a8" if group == "baseline" else "#f58518"
    bins = min(60, max(10, int(len(samples) ** 0.5)))
    fig, ax = plt.subplots(figsize=(10, 6), constrained_layout=True)
    ax.hist(samples, bins=bins, density=True, alpha=0.72, color=color, edgecolor="white")
    ax.set_title(f"{display_name}: {title}")
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Density")
    ax.grid(True, axis="y", alpha=0.25)
    fig.savefig(output, dpi=160)
    plt.close(fig)


def maybe_scatter_samples(
    per_run: list[dict[str, Any]],
    output: Path,
    baseline_name: str,
    feature_name: str,
    *,
    sample_key: str,
    title: str,
    ylabel: str,
) -> bool:
    try:
        scatter_samples(
            per_run,
            output,
            baseline_name,
            feature_name,
            sample_key=sample_key,
            title=title,
            ylabel=ylabel,
        )
    except ValueError as error:
        print(f"Skipping {output.name}: {error}")
        return False
    return True


def maybe_distribution_samples(
    per_run: list[dict[str, Any]],
    output: Path,
    display_name: str,
    *,
    sample_key: str,
    group: str,
    title: str,
    xlabel: str,
) -> bool:
    try:
        distribution_samples(
            per_run,
            output,
            display_name,
            sample_key=sample_key,
            group=group,
            title=title,
            xlabel=xlabel,
        )
    except ValueError as error:
        print(f"Skipping {output.name}: {error}")
        return False
    return True


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

    written: list[dict[str, str]] = []
    for chart in CHARTS:
        if maybe_scatter_samples(
            per_run,
            output_dir / chart["file"],
            args.baseline_name,
            args.feature_name,
            sample_key=chart["sample_key"],
            title=chart["title"],
            ylabel=chart["ylabel"],
        ):
            written.append({"file": chart["file"], "label": chart["label"]})

        stem = chart["file"].removesuffix("_scatter.png")
        for group, display_name in [
            ("baseline", args.baseline_name or "baseline"),
            ("feature", args.feature_name or "feature"),
        ]:
            file_name = f"{stem}_{group}_distribution.png"
            label = f"{chart['label'].removesuffix(' Scatter')} {group.title()} Distribution"
            if maybe_distribution_samples(
                per_run,
                output_dir / file_name,
                display_name,
                sample_key=chart["sample_key"],
                group=group,
                title=chart["title"],
                xlabel=chart["ylabel"],
            ):
                written.append({"file": file_name, "label": label})

    if not written:
        raise SystemExit("summary.json has no chartable samples")
    with (output_dir / "charts.json").open("w") as f:
        json.dump(written, f, indent=2)
    print(f"Charts written to {output_dir}")


if __name__ == "__main__":
    main()
