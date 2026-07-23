import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EXPORTER = REPOSITORY_ROOT / "contrib/bench/export-stateless-precompiles.py"
CLICKHOUSE_DDL = (
    REPOSITORY_ROOT / "contrib/bench/clickhouse/001_execution_microbench_results.sql"
)


def estimate(point: float, lower: float, upper: float) -> dict:
    return {
        "confidence_interval": {
            "confidence_level": 0.95,
            "lower_bound": lower,
            "upper_bound": upper,
        },
        "point_estimate": point,
        "standard_error": 1.25,
    }


class ExportStatelessPrecompilesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.manifest_path = self.root / "cases.json"
        self.criterion_dir = self.root / "criterion"
        self.output = self.root / "report.json"
        self.rows_output = self.root / "rows.jsonl"
        self.case = {
            "case_id": "identity/32-bytes",
            "criterion_id": "stateless_precompiles/direct/identity/32-bytes",
            "precompile": {
                "name": "identity",
                "address": "0x0000000000000000000000000000000000000004",
                "registry_id": "ID",
            },
            "protocol": {"hardfork": "T7", "precompile_spec": "OSAKA"},
            "input": {"kind": "repeat", "length": 32, "byte": 0},
            "state_gas_reservoir": 1000,
            "gas_limit": 18,
            "gas_used": 18,
            "state_gas_used": 0,
            "gas_refunded": 0,
            "expected": {
                "status": "success",
                "output_length": 32,
                "state_gas_reservoir_remaining": 1000,
            },
        }
        self.write_manifest([self.case])
        self.write_criterion_result(self.case["criterion_id"])

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write_manifest(self, cases: list[dict]) -> None:
        self.manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "suite": {
                        "id": "stateless-precompiles",
                        "version": 1,
                        "benchmark_layer": "direct",
                    },
                    "cases": cases,
                }
            ),
            encoding="utf-8",
        )

    def write_criterion_result(self, criterion_id: str, directory: str = "sanitized-name") -> None:
        result_dir = self.criterion_dir / directory / "new"
        result_dir.mkdir(parents=True, exist_ok=True)
        (result_dir / "benchmark.json").write_text(
            json.dumps(
                {
                    "group_id": "stateless_precompiles",
                    "function_id": "direct/identity",
                    "value_str": "32-bytes",
                    "throughput": {"Bytes": 32},
                    "full_id": criterion_id,
                    "directory_name": "sanitized-name",
                    "title": criterion_id,
                }
            ),
            encoding="utf-8",
        )
        (result_dir / "estimates.json").write_text(
            json.dumps(
                {
                    "mean": estimate(102.0, 100.0, 105.0),
                    "median": estimate(101.0, 99.0, 104.0),
                    "median_abs_dev": estimate(2.0, 1.0, 3.0),
                    "slope": estimate(100.0, 98.0, 103.0),
                    "std_dev": estimate(4.0, 3.0, 5.0),
                }
            ),
            encoding="utf-8",
        )
        (result_dir / "sample.json").write_text(
            json.dumps(
                {
                    "sampling_mode": "Linear",
                    "iters": [1.0, 2.0, 3.0],
                    "times": [100.0, 200.0, 300.0],
                }
            ),
            encoding="utf-8",
        )

    def run_exporter(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(EXPORTER),
                "--manifest",
                str(self.manifest_path),
                "--criterion-dir",
                str(self.criterion_dir),
                "--output",
                str(self.output),
                "--rows-output",
                str(self.rows_output),
                "--run-id",
                "test-run",
                "--started-at",
                "2026-07-13T00:00:00Z",
                "--git-sha",
                "abc123",
                "--machine-id",
                "test-machine",
                "--features",
                "tempo-precompiles/test-utils",
                "--allocator",
                "system",
                "--warmup-seconds",
                "1",
                "--measurement-seconds",
                "2",
                "--sample-size",
                "10",
            ],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
        )

    def test_exports_report_and_clickhouse_row(self) -> None:
        result = self.run_exporter()
        self.assertEqual(result.returncode, 0, result.stderr)

        report = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["run"]["id"], "test-run")
        self.assertEqual(report["suite"]["benchmark_layer"], "direct")
        self.assertEqual(report["build"]["allocator"], "system")
        self.assertEqual(report["configuration"]["measurement_seconds"], 2.0)
        self.assertEqual(report["configuration"]["measurement_mode"], "wall_time")
        self.assertEqual(len(report["results"]), 1)
        exported = report["results"][0]
        self.assertEqual(exported["case"]["case_id"], "identity/32-bytes")
        self.assertEqual(exported["measurement"]["typical_statistic"], "slope")
        self.assertEqual(exported["measurement"]["sample_count"], 3)
        self.assertAlmostEqual(exported["metrics"]["mgas_per_second"], 180.0)
        self.assertAlmostEqual(
            exported["metrics"]["conservative_mgas_per_second"],
            18_000.0 / 103.0,
        )

        rows = [json.loads(line) for line in self.rows_output.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["case_id"], "identity/32-bytes")
        self.assertEqual(rows[0]["precompile_registry_id"], "ID")
        self.assertEqual(rows[0]["machine_id"], "test-machine")
        self.assertEqual(rows[0]["estimate_ns"], 100.0)
        self.assertEqual(rows[0]["measurement_mode"], "wall_time")
        self.assertEqual(rows[0]["gas_refunded"], 0)
        self.assertEqual(rows[0]["state_gas_reservoir"], 1000)
        self.assertEqual(rows[0]["state_gas_reservoir_remaining"], 1000)
        self.assertNotIn("hostname", rows[0])
        self.assertIsInstance(rows[0]["case_metadata_json"], str)

        ddl_columns = {
            match.group(1)
            for line in CLICKHOUSE_DDL.read_text(encoding="utf-8").splitlines()
            if (match := re.match(r"^    ([a-z][a-z0-9_]*)\s+", line))
        }
        ddl_columns.remove("ingested_at")
        self.assertEqual(set(rows[0]), ddl_columns)

    def test_rejects_missing_criterion_case(self) -> None:
        missing = {**self.case, "case_id": "identity/missing", "criterion_id": "missing/id"}
        self.write_manifest([self.case, missing])
        result = self.run_exporter()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing Criterion result for manifest case missing/id", result.stderr)

    def test_rejects_unmanifested_criterion_result(self) -> None:
        self.write_criterion_result(
            "stateless_precompiles/direct/identity/extra",
            directory="extra-sanitized-name",
        )
        result = self.run_exporter()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absent from the benchmark manifest", result.stderr)

    def test_rejects_duplicate_case_ids(self) -> None:
        duplicate = {**self.case, "criterion_id": "different/criterion/id"}
        self.write_manifest([self.case, duplicate])
        result = self.run_exporter()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate case_id", result.stderr)

    def test_uses_mean_when_slope_is_absent(self) -> None:
        estimates_path = self.criterion_dir / "sanitized-name/new/estimates.json"
        estimates = json.loads(estimates_path.read_text(encoding="utf-8"))
        estimates["slope"] = None
        estimates_path.write_text(json.dumps(estimates), encoding="utf-8")

        result = self.run_exporter()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(self.output.read_text(encoding="utf-8"))
        measurement = report["results"][0]["measurement"]
        self.assertEqual(measurement["typical_statistic"], "mean")
        self.assertEqual(measurement["typical"]["point_estimate_ns"], 102.0)

    def test_rejects_unsupported_manifest_schema(self) -> None:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        manifest["schema_version"] = 2
        self.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = self.run_exporter()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported manifest schema_version", result.stderr)


if __name__ == "__main__":
    unittest.main()
