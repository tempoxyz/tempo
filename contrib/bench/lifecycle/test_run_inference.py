import json
import math
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from run_inference import AXES, InvalidSummary, analyze, markdown, write_outputs


def summary(mutator=None):
    runs = []
    by_label = {}
    for pair in range(1, 7):
        baseline = {"label": f"baseline-{pair}", "private": 999}
        feature = {"label": f"feature-{pair}", "private": 999}
        for index, axis in enumerate(AXES, 1):
            baseline[axis] = float(100 + index + pair)
            feature[axis] = baseline[axis] * (0.95 if AXES[axis]["lower_is_better"] else 1.05)
        by_label[baseline["label"]] = baseline
        by_label[feature["label"]] = feature
    for label in [
        "feature-1", "baseline-1", "baseline-2", "feature-2",
        "feature-3", "baseline-3", "baseline-4", "feature-4",
        "feature-5", "baseline-5", "baseline-6", "feature-6",
    ]:
        runs.append(by_label[label])
    value = {"per_run": runs, "private": {"secret": 999}}
    if mutator:
        mutator(value)
    return value


class RunInferenceTests(unittest.TestCase):
    def test_exact_pairs_bootstrap_and_privacy(self):
        result = analyze(summary())
        self.assertTrue(result["valid"])
        self.assertEqual(result["run_count"], {"baseline": 6, "feature": 6, "pairs": 6})
        self.assertEqual(set(result["axes"]), set(AXES))
        for axis, values in result["axes"].items():
            expected = "improvement"
            self.assertEqual(values["assessment"], expected, axis)
            self.assertEqual(
                values["paired_descriptive"]["directions"],
                {"improvement": 6, "regression": 0, "tie": 0},
            )
            interval = values["bootstrap_95_ci_delta_percent"]
            self.assertLess(interval["low"], interval["high"])
            self.assertTrue(math.isfinite(interval["low"]))
        encoded = json.dumps(result)
        self.assertNotIn("private", encoded)
        self.assertNotIn("secret", encoded)

    def test_output_is_deterministic_and_documents_estimands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "summary.json"
            source.write_text(json.dumps(summary()))
            first = write_outputs(source)
            first_json = (root / "run-inference.json").read_text()
            second = write_outputs(source)
            self.assertEqual(first, second)
            self.assertEqual(first_json, (root / "run-inference.json").read_text())
            text = (root / "run-inference.md").read_text()
            self.assertIn("independently resample runs", text)
            self.assertIn("scrape-interval", text)
            self.assertIn("## Individual run values", text)
            self.assertIn("`tps` (tx/s)", text)
            self.assertIn("`builder_gas_s` (Mgas/s)", text)
            self.assertIn(
                "| `builder_gas_s` (Mgas/s) | 0.000105, 0.000106, 0.000107, 0.000108, 0.000109, 0.00011 |",
                text,
            )
            self.assertIn("`validation_latency_p99` (ms)", text)
            self.assertIn("Baseline runs 1–6", text)
            self.assertEqual(text, markdown(second))

    def test_rejects_missing_duplicate_extra_and_nonfinite_inputs(self):
        cases = [
            lambda value: value["per_run"].pop(),
            lambda value: value["per_run"].append(dict(value["per_run"][0])),
            lambda value: value["per_run"].__setitem__(0, {**value["per_run"][0], "label": "baseline-7"}),
            lambda value: value["per_run"][0].pop("tps"),
            lambda value: value["per_run"][0].__setitem__("tps", float("nan")),
            lambda value: value["per_run"][0].__setitem__("tps", True),
            lambda value: value["per_run"][0].__setitem__("tps", 0),
            lambda value: value["per_run"].reverse(),
        ]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                with self.assertRaises(InvalidSummary):
                    analyze(summary(mutate))

        private_label = "private-run-label"
        with self.assertRaises(InvalidSummary) as rejected:
            analyze(summary(lambda value: value["per_run"][0].__setitem__("label", private_label)))
        self.assertNotIn(private_label, str(rejected.exception))

    def test_rejects_zero_baseline_percent_denominator(self):
        def mutate(value):
            for run in value["per_run"]:
                if run["label"].startswith("baseline"):
                    run["tps"] = 0

        with self.assertRaises(InvalidSummary):
            analyze(summary(mutate))


if __name__ == "__main__":
    unittest.main()
