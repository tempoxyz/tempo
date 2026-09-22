#!/usr/bin/env python3
"""Run-level inference companion for the standard bench-e2e summary."""

from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path
from typing import Any

BOOTSTRAP_ITERATIONS = 10_000
BOOTSTRAP_SEED = 42
PAIR_COUNT = 6
EXPECTED_RUN_ORDER = [
    "feature-1",
    "baseline-1",
    "baseline-2",
    "feature-2",
    "feature-3",
    "baseline-3",
    "baseline-4",
    "feature-4",
    "feature-5",
    "baseline-5",
    "baseline-6",
    "feature-6",
]

# Keep this vocabulary aligned with .github/scripts/bench-e2e-classify.js. Unknown summary fields
# are deliberately ignored so the companion cannot widen the public report by accident.
AXES = {
    "builder_latency_p50": {"floor_percent": 0.45, "lower_is_better": True, "unit": "ms"},
    "builder_latency_p90": {"floor_percent": 0.90, "lower_is_better": True, "unit": "ms"},
    "builder_latency_p99": {"floor_percent": 1.25, "lower_is_better": True, "unit": "ms"},
    "builder_gas_s": {"floor_percent": 0.95, "lower_is_better": False, "unit": "Mgas/s", "display_scale": 1e-6},
    "tps": {"floor_percent": 0.55, "lower_is_better": False, "unit": "tx/s"},
    "mgas_s": {"floor_percent": 0.50, "lower_is_better": False, "unit": "Mgas/s"},
    "block_time_mean": {"floor_percent": 0.40, "lower_is_better": True, "unit": "ms"},
    "block_time_p50": {"floor_percent": 0.70, "lower_is_better": True, "unit": "ms"},
    "block_time_p90": {"floor_percent": 0.70, "lower_is_better": True, "unit": "ms"},
    "block_time_p99": {"floor_percent": 1.60, "lower_is_better": True, "unit": "ms"},
    "validation_latency_p50": {"floor_percent": 1.55, "lower_is_better": True, "unit": "ms"},
    "validation_latency_p90": {"floor_percent": 1.55, "lower_is_better": True, "unit": "ms"},
    "validation_latency_p99": {"floor_percent": 2.05, "lower_is_better": True, "unit": "ms"},
    "validation_gas_s": {"floor_percent": 0.65, "lower_is_better": False, "unit": "Mgas/s", "display_scale": 1e-6},
}


class InvalidSummary(ValueError):
    """The sanitized standard summary is not sufficient for inference."""


def _number(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidSummary(f"{context} must be numeric")
    value = float(value)
    if not math.isfinite(value):
        raise InvalidSummary(f"{context} must be finite")
    return value


def _mean(values: list[float]) -> float:
    return sum(values) / len(values)


def _percentile(sorted_values: list[float], quantile: float) -> float:
    position = (len(sorted_values) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    weight = position - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def _bootstrap_delta(
    baseline: list[float], feature: list[float], *, seed: int
) -> tuple[float, float]:
    rng = random.Random(seed)
    deltas = []
    for _ in range(BOOTSTRAP_ITERATIONS):
        baseline_mean = sum(rng.choice(baseline) for _ in baseline) / len(baseline)
        feature_mean = sum(rng.choice(feature) for _ in feature) / len(feature)
        deltas.append(feature_mean - baseline_mean)
    deltas.sort()
    return _percentile(deltas, 0.025), _percentile(deltas, 0.975)


def _assessment(
    low_percent: float, high_percent: float, *, floor_percent: float, lower_is_better: bool
) -> str:
    if lower_is_better:
        if high_percent < -floor_percent:
            return "improvement"
        if low_percent > floor_percent:
            return "regression"
    else:
        if low_percent > floor_percent:
            return "improvement"
        if high_percent < -floor_percent:
            return "regression"
    return "no_clear_difference"


def analyze(summary: dict[str, Any]) -> dict[str, Any]:
    runs = summary.get("per_run")
    if not isinstance(runs, list):
        raise InvalidSummary("per_run must be a list")

    expected_labels = {
        *(f"baseline-{index}" for index in range(1, PAIR_COUNT + 1)),
        *(f"feature-{index}" for index in range(1, PAIR_COUNT + 1)),
    }
    by_label: dict[str, dict[str, Any]] = {}
    for index, run in enumerate(runs):
        if not isinstance(run, dict) or not isinstance(run.get("label"), str):
            raise InvalidSummary(f"per_run[{index}] has no string label")
        label = run["label"]
        if label in by_label:
            raise InvalidSummary("duplicate run label")
        by_label[label] = run
    labels = set(by_label)
    if labels != expected_labels:
        raise InvalidSummary("run labels must be exactly six pairs")
    run_order = [run["label"] for run in runs]
    if run_order != EXPECTED_RUN_ORDER:
        raise InvalidSummary("unexpected run order")

    axes: dict[str, Any] = {}
    for axis_index, (axis, metadata) in enumerate(AXES.items()):
        baseline = [
            _number(by_label[f"baseline-{pair}"] .get(axis), f"baseline-{pair}.{axis}")
            for pair in range(1, PAIR_COUNT + 1)
        ]
        feature = [
            _number(by_label[f"feature-{pair}"].get(axis), f"feature-{pair}.{axis}")
            for pair in range(1, PAIR_COUNT + 1)
        ]
        if any(value <= 0 for value in baseline + feature):
            raise InvalidSummary(f"all run-level {axis} values must be positive")
        baseline_mean = _mean(baseline)
        feature_mean = _mean(feature)
        delta = feature_mean - baseline_mean
        delta_percent = delta / baseline_mean * 100.0
        low, high = _bootstrap_delta(
            baseline, feature, seed=BOOTSTRAP_SEED + axis_index
        )
        low_percent = low / baseline_mean * 100.0
        high_percent = high / baseline_mean * 100.0

        pairs = []
        directions = {"improvement": 0, "regression": 0, "tie": 0}
        for pair, (baseline_value, feature_value) in enumerate(zip(baseline, feature), 1):
            pair_delta = feature_value - baseline_value
            pair_delta_percent = pair_delta / baseline_value * 100.0 if baseline_value > 0 else None
            if pair_delta == 0:
                direction = "tie"
            elif (pair_delta < 0) == metadata["lower_is_better"]:
                direction = "improvement"
            else:
                direction = "regression"
            directions[direction] += 1
            pairs.append(
                {
                    "pair": pair,
                    "baseline": baseline_value,
                    "feature": feature_value,
                    "delta": pair_delta,
                    "delta_percent": pair_delta_percent,
                    "direction": direction,
                }
            )

        axes[axis] = {
            "baseline_mean_of_runs": baseline_mean,
            "feature_mean_of_runs": feature_mean,
            "delta": delta,
            "delta_percent": delta_percent,
            "bootstrap_95_ci_delta": {"low": low, "high": high},
            "bootstrap_95_ci_delta_percent": {"low": low_percent, "high": high_percent},
            "practical_floor_percent": metadata["floor_percent"],
            "floor_source": ".github/scripts/bench-e2e-classify.js AXES",
            "lower_is_better": metadata["lower_is_better"],
            "assessment": _assessment(
                low_percent,
                high_percent,
                floor_percent=metadata["floor_percent"],
                lower_is_better=metadata["lower_is_better"],
            ),
            "paired_descriptive": {"directions": directions, "pairs": pairs},
        }

    return {
        "schema": 1,
        "valid": True,
        "run_count": {"baseline": PAIR_COUNT, "feature": PAIR_COUNT, "pairs": PAIR_COUNT},
        "run_order": EXPECTED_RUN_ORDER,
        "method": {
            "point_estimate": "difference of arithmetic means of run-level scalar metrics",
            "bootstrap": "independent within-arm run resampling with replacement",
            "confidence": 0.95,
            "iterations": BOOTSTRAP_ITERATIONS,
            "seed": BOOTSTRAP_SEED,
            "axis_seed": "base seed plus zero-based axis position in the fixed vocabulary",
            "rng": "Python random.Random; no identity with the JavaScript classifier RNG is claimed",
            "percent_scaling": "absolute delta and interval divided by the baseline mean-of-runs",
            "paired_results": "descriptive matched-label deltas; not the bootstrap sampling design",
        },
        "limitations": [
            "Standard pooled percentile point estimates are not reused: this report averages each phase's p50/p90/p99 scalar so its point estimate matches the run-level bootstrap unit.",
            "Builder and validator latency phase quantiles are derived upstream from scrape-interval sum/count means, not raw event latencies.",
            "Block-time phase quantiles originate from raw block intervals, but this report estimates the mean of six phase-level quantiles rather than a pooled block percentile.",
            "TPS and Mgas/s use sanitized upstream run scalars; an interval-aligned sensitivity analysis requires retained per-phase timestamp spans and first-block contributions.",
            "Six pairs give bounded run-level screening evidence; paired direction counts are descriptive and the confidence interval uses independent arm resampling.",
            "Each interval is a nominal per-axis 95% interval with no multiple-comparison adjustment across the 14 axes.",
            "The percent interval scales the absolute-delta interval by the observed baseline mean; it is not a separately bootstrapped ratio interval.",
            "All runs come from one runner and one workflow execution, which limits generalization beyond this environment.",
        ],
        "axes": axes,
    }


def markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Run-level inference companion",
        "",
        "Six baseline and six feature runs are summarized as means of run-level scalars. The 95% intervals independently resample runs within each arm; matched pair directions are descriptive.",
        "Builder and validator gas/s values are converted to Mgas/s for display; JSON inference values retain their upstream units.",
        "",
        "| Axis | Baseline mean | Feature mean | Delta | Delta % (95% CI) | Floor | Assessment | Pair directions I/R/T |",
        "|---|---:|---:|---:|---:|---:|---|---:|",
    ]
    for axis, values in result["axes"].items():
        metadata = AXES[axis]
        scale = metadata.get("display_scale", 1.0)
        interval = values["bootstrap_95_ci_delta_percent"]
        directions = values["paired_descriptive"]["directions"]
        lines.append(
            f"| `{axis}` ({metadata['unit']}) | {values['baseline_mean_of_runs'] * scale:.6g} | "
            f"{values['feature_mean_of_runs'] * scale:.6g} | {values['delta'] * scale:.6g} | "
            f"{values['delta_percent']:+.3f}% [{interval['low']:+.3f}%, {interval['high']:+.3f}%] | "
            f"{values['practical_floor_percent']:.2f}% | {values['assessment']} | "
            f"{directions['improvement']}/{directions['regression']}/{directions['tie']} |"
        )
    lines.extend(
        [
            "",
            "## Individual run values",
            "",
            "Values follow pair labels 1 through 6 within each arm.",
            "",
            "| Axis | Baseline runs 1–6 | Feature runs 1–6 |",
            "|---|---|---|",
        ]
    )
    for axis, values in result["axes"].items():
        metadata = AXES[axis]
        scale = metadata.get("display_scale", 1.0)
        pairs = values["paired_descriptive"]["pairs"]
        baseline = ", ".join(f"{pair['baseline'] * scale:.6g}" for pair in pairs)
        feature = ", ".join(f"{pair['feature'] * scale:.6g}" for pair in pairs)
        lines.append(f"| `{axis}` ({metadata['unit']}) | {baseline} | {feature} |")
    lines.extend(["", "## Interpretation limits", ""])
    lines.extend(f"- {item}" for item in result["limitations"])
    return "\n".join(lines) + "\n"


def write_outputs(summary_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text())
    if not isinstance(summary, dict):
        raise InvalidSummary("summary root must be an object")
    result = analyze(summary)
    destination = output_dir or summary_path.parent
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "run-inference.json").write_text(json.dumps(result, indent=2) + "\n")
    (destination / "run-inference.md").write_text(markdown(result))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "source",
        type=Path,
        help="bench results directory, or a summary.json path",
    )
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        if args.source.is_dir():
            summary_path = args.source / "summary.json"
            output_dir = args.output_dir or args.source / "lifecycle"
        else:
            summary_path = args.source
            output_dir = args.output_dir
        write_outputs(summary_path, output_dir)
    except (InvalidSummary, json.JSONDecodeError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
