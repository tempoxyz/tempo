#!/usr/bin/env python3
"""Export native Criterion measurements using Tempo's benchmark report schema.

The benchmark target owns case semantics and writes a manifest. This exporter owns
the result envelope and joins that manifest to Criterion's native wall-time output
by the full Criterion benchmark ID. It deliberately does not infer case metadata
from Criterion directory names.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # pragma: no cover - the benchmark runner uses Python 3.11+
    tomllib = None


SCHEMA_VERSION = 1


class ExportError(RuntimeError):
    """A benchmark result cannot be exported without losing integrity."""


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ExportError(f"missing required file: {path}") from error
    except json.JSONDecodeError as error:
        raise ExportError(f"invalid JSON in {path}: {error}") from error


def command_output(*command: str) -> str | None:
    try:
        return subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None


def env_or_command(name: str, *command: str) -> str | None:
    value = os.environ.get(name)
    return value or command_output(*command)


def first_prefixed_line(text: str | None, prefix: str) -> str | None:
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix).strip()
    return None


def first_file_entry(paths: list[Path]) -> dict[str, str] | None:
    for path in paths:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return {"path": str(path), "value": value}
    return None


def cpu_info() -> tuple[str | None, str | None]:
    model = None
    microcode = None
    try:
        lines = Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines()
    except OSError:
        return model, microcode

    for line in lines:
        key, separator, value = line.partition(":")
        if not separator:
            continue
        if model is None and key.strip() in {"model name", "Hardware"}:
            model = value.strip()
        elif microcode is None and key.strip() == "microcode":
            microcode = value.strip()
        if model is not None and microcode is not None:
            break
    return model, microcode


def os_release() -> str | None:
    try:
        values = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value.strip().strip('"')
        return values.get("PRETTY_NAME")
    except OSError:
        return None


def host_metadata(machine_id: str | None, cpu_set: str | None) -> dict[str, Any]:
    cpu_model, microcode = cpu_info()
    governors = []
    for path in sorted(Path("/sys/devices/system/cpu").glob("cpu*/cpufreq/scaling_governor")):
        try:
            governors.append(path.read_text(encoding="utf-8").strip())
        except OSError:
            pass

    turbo = first_file_entry(
        [
            Path("/sys/devices/system/cpu/intel_pstate/no_turbo"),
            Path("/sys/devices/system/cpu/cpufreq/boost"),
        ]
    )
    return without_none(
        {
            "machine_id": machine_id,
            "runner_name": os.environ.get("RUNNER_NAME"),
            "os": os_release() or platform.platform(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "cpu_model": cpu_model or platform.processor() or None,
            "microcode": microcode,
            "logical_cpu_count": os.cpu_count(),
            "cpu_set": cpu_set,
            "cpu_governors": sorted(set(governors)) or None,
            "turbo_control": turbo,
        }
    )


def without_none(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item is not None}


def integer_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def dependency_versions(lockfile: Path = Path("Cargo.lock")) -> dict[str, dict[str, str]] | None:
    if tomllib is None:
        return None
    try:
        cargo_lock = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None

    wanted = {"codspeed-criterion-compat", "revm", "revm-precompile", "tikv-jemallocator"}
    versions = {}
    for package in cargo_lock.get("package", []):
        name = package.get("name")
        if name in wanted:
            versions[name] = without_none(
                {
                    "version": package.get("version"),
                    "source": package.get("source"),
                }
            )
    return versions or None


def validate_manifest(manifest: Any, path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(manifest, dict):
        raise ExportError(f"manifest root must be an object: {path}")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ExportError(
            f"unsupported manifest schema_version {manifest.get('schema_version')!r}; "
            f"expected {SCHEMA_VERSION}"
        )
    suite = manifest.get("suite")
    if not isinstance(suite, dict) or not isinstance(suite.get("id"), str):
        raise ExportError("manifest suite must be an object with a string id")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ExportError("manifest cases must be a non-empty array")

    case_ids: set[str] = set()
    criterion_ids: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ExportError(f"manifest case {index} must be an object")
        case_id = case.get("case_id")
        criterion_id = case.get("criterion_id")
        if not isinstance(case_id, str) or not case_id:
            raise ExportError(f"manifest case {index} has no case_id")
        if not isinstance(criterion_id, str) or not criterion_id:
            raise ExportError(f"manifest case {case_id!r} has no criterion_id")
        if case_id in case_ids:
            raise ExportError(f"duplicate case_id in manifest: {case_id}")
        if criterion_id in criterion_ids:
            raise ExportError(f"duplicate criterion_id in manifest: {criterion_id}")
        if not isinstance(case.get("gas_used"), int) or case["gas_used"] < 0:
            raise ExportError(f"manifest case {case_id!r} has invalid gas_used")
        case_ids.add(case_id)
        criterion_ids.add(criterion_id)

    return suite, cases


def load_criterion_results(root: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for benchmark_path in sorted(root.glob("**/new/benchmark.json")):
        benchmark = read_json(benchmark_path)
        if not isinstance(benchmark, dict):
            raise ExportError(f"Criterion benchmark metadata must be an object: {benchmark_path}")
        criterion_id = benchmark.get("full_id")
        if not isinstance(criterion_id, str) or not criterion_id:
            raise ExportError(f"Criterion benchmark has no full_id: {benchmark_path}")
        if criterion_id in results:
            raise ExportError(f"duplicate Criterion benchmark ID: {criterion_id}")

        directory = benchmark_path.parent
        estimates = read_json(directory / "estimates.json")
        sample = read_json(directory / "sample.json")
        if not isinstance(estimates, dict) or not isinstance(sample, dict):
            raise ExportError(f"invalid Criterion result for {criterion_id}")
        results[criterion_id] = {
            "benchmark": benchmark,
            "estimates": estimates,
            "sample": sample,
        }

    if not results:
        raise ExportError(f"no Criterion native results found below {root}")
    return results


def normalized_estimate(estimate: Any, name: str, criterion_id: str) -> dict[str, Any]:
    if not isinstance(estimate, dict):
        raise ExportError(f"Criterion {name} estimate missing for {criterion_id}")
    interval = estimate.get("confidence_interval")
    if not isinstance(interval, dict):
        raise ExportError(f"Criterion {name} confidence interval missing for {criterion_id}")
    try:
        return {
            "point_estimate_ns": float(estimate["point_estimate"]),
            "standard_error_ns": float(estimate["standard_error"]),
            "confidence_interval": {
                "confidence_level": float(interval["confidence_level"]),
                "lower_bound_ns": float(interval["lower_bound"]),
                "upper_bound_ns": float(interval["upper_bound"]),
            },
        }
    except (KeyError, TypeError, ValueError) as error:
        raise ExportError(f"invalid Criterion {name} estimate for {criterion_id}") from error


def measurement_for(result: dict[str, Any], criterion_id: str) -> dict[str, Any]:
    estimates = result["estimates"]
    typical_name = "slope" if estimates.get("slope") is not None else "mean"
    typical = normalized_estimate(estimates.get(typical_name), typical_name, criterion_id)
    median = normalized_estimate(estimates.get("median"), "median", criterion_id)
    std_dev = normalized_estimate(estimates.get("std_dev"), "std_dev", criterion_id)
    sample = result["sample"]
    iterations = sample.get("iters")
    times = sample.get("times")
    if not isinstance(iterations, list) or not isinstance(times, list) or len(iterations) != len(times):
        raise ExportError(f"invalid Criterion samples for {criterion_id}")

    return {
        "unit": "nanoseconds",
        "typical_statistic": typical_name,
        "typical": typical,
        "median": median,
        "std_dev": std_dev,
        "sample_count": len(iterations),
        "sampling_mode": sample.get("sampling_mode"),
    }


def metrics_for(case: dict[str, Any], measurement: dict[str, Any]) -> dict[str, float]:
    gas_used = case["gas_used"]
    estimate_ns = measurement["typical"]["point_estimate_ns"]
    upper_bound_ns = measurement["typical"]["confidence_interval"]["upper_bound_ns"]
    if estimate_ns <= 0 or upper_bound_ns <= 0:
        raise ExportError(f"non-positive timing estimate for {case['case_id']}")

    metrics = {
        "mgas_per_second": gas_used * 1_000.0 / estimate_ns,
        "conservative_mgas_per_second": gas_used * 1_000.0 / upper_bound_ns,
        "nanoseconds_per_gas": estimate_ns / gas_used if gas_used else 0.0,
    }
    input_length = case.get("input", {}).get("length")
    if isinstance(input_length, int) and input_length >= 0:
        metrics["gibibytes_per_second"] = input_length / estimate_ns * (1e9 / 2**30)
    return metrics


def build_metadata(args: argparse.Namespace) -> dict[str, Any]:
    rustc_verbose = command_output("rustc", "-Vv")
    workflow_url = args.workflow_url
    if workflow_url is None and os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID"):
        workflow_url = (
            f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}"
            f"/actions/runs/{os.environ['GITHUB_RUN_ID']}"
        )

    return {
        "run": without_none(
            {
                "id": args.run_id or os.environ.get("TEMPO_BENCH_RUN_ID") or str(uuid.uuid4()),
                "started_at": args.started_at
                or os.environ.get("TEMPO_BENCH_STARTED_AT")
                or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "repository": args.repository or os.environ.get("GITHUB_REPOSITORY"),
                "git_sha": args.git_sha or env_or_command("GITHUB_SHA", "git", "rev-parse", "HEAD"),
                "git_ref": args.git_ref
                or os.environ.get("GITHUB_REF_NAME")
                or os.environ.get("GITHUB_REF"),
                "workflow_url": workflow_url,
                "workflow_run_attempt": integer_or_none(os.environ.get("GITHUB_RUN_ATTEMPT")),
            }
        ),
        "build": without_none(
            {
                "profile": args.profile,
                "features": sorted(args.features),
                "allocator": args.allocator,
                "rustc": first_prefixed_line(rustc_verbose, "release: ")
                or first_prefixed_line(rustc_verbose, "rustc ")
                or command_output("rustc", "--version"),
                "rustc_verbose": rustc_verbose,
                "cargo": command_output("cargo", "--version"),
                "target": first_prefixed_line(rustc_verbose, "host: "),
                "rustflags": os.environ.get("RUSTFLAGS"),
                "rustc_wrapper": os.environ.get("RUSTC_WRAPPER"),
                "dependencies": dependency_versions(),
            }
        ),
        "host": host_metadata(
            args.machine_id or os.environ.get("TEMPO_BENCH_MACHINE_ID"),
            args.cpu_set or os.environ.get("TEMPO_BENCH_CPU_SET"),
        ),
        "configuration": {
            "measurement_mode": "wall_time",
            "warmup_seconds": args.warmup_seconds,
            "measurement_seconds": args.measurement_seconds,
            "requested_sample_size": args.sample_size,
        },
    }


def build_report(
    manifest: dict[str, Any],
    criterion_results: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    suite, cases = validate_manifest(manifest, Path("<manifest>"))
    results = []
    for case in cases:
        criterion_id = case["criterion_id"]
        criterion_result = criterion_results.get(criterion_id)
        if criterion_result is None:
            raise ExportError(f"missing Criterion result for manifest case {criterion_id}")
        measurement = measurement_for(criterion_result, criterion_id)
        results.append(
            {
                "case": case,
                "measurement": measurement,
                "metrics": metrics_for(case, measurement),
            }
        )

    manifest_ids = {case["criterion_id"] for case in cases}
    unexpected = sorted(set(criterion_results) - manifest_ids)
    if unexpected:
        raise ExportError(
            "Criterion emitted results absent from the benchmark manifest: " + ", ".join(unexpected)
        )

    return {
        "schema_version": SCHEMA_VERSION,
        **metadata,
        "suite": suite,
        "results": results,
    }


def row_for(report: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    run = report["run"]
    build = report["build"]
    host = report["host"]
    suite = report["suite"]
    configuration = report["configuration"]
    case = result["case"]
    measurement = result["measurement"]
    typical = measurement["typical"]
    interval = typical["confidence_interval"]
    precompile = case.get("precompile", {})
    protocol = case.get("protocol", {})
    input_spec = case.get("input", {})
    expected = case.get("expected", {})
    provenance = case.get("provenance") or {}
    dependencies = build.get("dependencies", {})

    # Keep the row shape stable. Optional values are represented as null rather
    # than omitted so a JSONEachRow consumer can validate one explicit schema.
    return {
        "schema_version": report["schema_version"],
        "run_id": run.get("id"),
        "started_at": run.get("started_at"),
        "repository": run.get("repository"),
        "git_sha": run.get("git_sha"),
        "git_ref": run.get("git_ref"),
        "workflow_url": run.get("workflow_url"),
        "workflow_run_attempt": run.get("workflow_run_attempt"),
        "suite_id": suite.get("id"),
        "suite_version": suite.get("version"),
        "benchmark_layer": suite.get("benchmark_layer"),
        "measurement_mode": configuration.get("measurement_mode"),
        "warmup_seconds": configuration.get("warmup_seconds"),
        "measurement_seconds": configuration.get("measurement_seconds"),
        "requested_sample_size": configuration.get("requested_sample_size"),
        "case_id": case.get("case_id"),
        "criterion_id": case.get("criterion_id"),
        "precompile": precompile.get("name"),
        "precompile_address": precompile.get("address"),
        "precompile_registry_id": precompile.get("registry_id"),
        "tempo_hardfork": protocol.get("hardfork"),
        "precompile_spec": protocol.get("precompile_spec"),
        "input_kind": input_spec.get("kind"),
        "input_length": input_spec.get("length"),
        "state_gas_reservoir": case.get("state_gas_reservoir"),
        "gas_limit": case.get("gas_limit"),
        "gas_used": case.get("gas_used"),
        "state_gas_used": case.get("state_gas_used"),
        "gas_refunded": case.get("gas_refunded"),
        "expected_status": expected.get("status"),
        "expected_output_length": expected.get("output_length"),
        "state_gas_reservoir_remaining": expected.get("state_gas_reservoir_remaining"),
        "provenance_source": provenance.get("source"),
        "provenance_reference": provenance.get("reference"),
        "typical_statistic": measurement.get("typical_statistic"),
        "estimate_ns": typical.get("point_estimate_ns"),
        "estimate_standard_error_ns": typical.get("standard_error_ns"),
        "estimate_confidence_level": interval.get("confidence_level"),
        "estimate_lower_bound_ns": interval.get("lower_bound_ns"),
        "estimate_upper_bound_ns": interval.get("upper_bound_ns"),
        "median_ns": measurement.get("median", {}).get("point_estimate_ns"),
        "std_dev_ns": measurement.get("std_dev", {}).get("point_estimate_ns"),
        "sample_count": measurement.get("sample_count"),
        "sampling_mode": measurement.get("sampling_mode"),
        "mgas_per_second": result["metrics"].get("mgas_per_second"),
        "conservative_mgas_per_second": result["metrics"].get(
            "conservative_mgas_per_second"
        ),
        "nanoseconds_per_gas": result["metrics"].get("nanoseconds_per_gas"),
        "gibibytes_per_second": result["metrics"].get("gibibytes_per_second"),
        "profile": build.get("profile"),
        "features": ",".join(build.get("features", [])),
        "allocator": build.get("allocator"),
        "rustc": build.get("rustc"),
        "cargo": build.get("cargo"),
        "target": build.get("target"),
        "rustflags": build.get("rustflags"),
        "revm_version": dependencies.get("revm", {}).get("version"),
        "revm_precompile_version": dependencies.get("revm-precompile", {}).get("version"),
        "criterion_compat_version": dependencies.get("codspeed-criterion-compat", {}).get(
            "version"
        ),
        "machine_id": host.get("machine_id"),
        "runner_name": host.get("runner_name"),
        "os": host.get("os"),
        "architecture": host.get("architecture"),
        "cpu_model": host.get("cpu_model"),
        "microcode": host.get("microcode"),
        "logical_cpu_count": host.get("logical_cpu_count"),
        "cpu_set": host.get("cpu_set"),
        "kernel": host.get("kernel"),
        "cpu_governors": ",".join(host["cpu_governors"])
        if host.get("cpu_governors")
        else None,
        "turbo_control_json": json.dumps(
            host.get("turbo_control"), sort_keys=True, separators=(",", ":")
        )
        if host.get("turbo_control")
        else None,
        "case_metadata_json": json.dumps(case, sort_keys=True, separators=(",", ":")),
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_rows(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [row_for(report, result) for result in report["results"]]
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--criterion-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows-output", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--started-at")
    parser.add_argument("--repository")
    parser.add_argument("--git-sha")
    parser.add_argument("--git-ref")
    parser.add_argument("--workflow-url")
    parser.add_argument("--machine-id")
    parser.add_argument("--cpu-set")
    parser.add_argument("--profile", default="bench")
    parser.add_argument("--features", action="append", default=[])
    parser.add_argument("--allocator", required=True)
    parser.add_argument("--warmup-seconds", type=float, required=True)
    parser.add_argument("--measurement-seconds", type=float, required=True)
    parser.add_argument("--sample-size", type=int, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.warmup_seconds <= 0 or args.measurement_seconds <= 0:
            raise ExportError("warm-up and measurement times must be positive")
        if args.sample_size < 10:
            raise ExportError("sample size must be at least 10")
        manifest = read_json(args.manifest)
        # Validate with the real filename before collecting other metadata.
        validate_manifest(manifest, args.manifest)
        criterion_results = load_criterion_results(args.criterion_dir)
        report = build_report(manifest, criterion_results, build_metadata(args))
        write_json(args.output, report)
        if args.rows_output:
            write_rows(args.rows_output, report)
    except ExportError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"Wrote {len(report['results'])} benchmark result(s) to {args.output}")
    if args.rows_output:
        print(f"Wrote ClickHouse JSONEachRow data to {args.rows_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
