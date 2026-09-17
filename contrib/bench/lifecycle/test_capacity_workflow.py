"""Fail closed if a later workflow edit lets a nonselected slot run a step."""
from pathlib import Path
import re
import unittest


class CapacityWorkflowTests(unittest.TestCase):
    def test_every_benchmark_step_requires_selection(self):
        workflow = (Path(__file__).resolve().parents[3] /
                    '.github/workflows/bench-e2e.yml').read_text()
        steps = re.split(r'^      - ', workflow, flags=re.MULTILINE)[1:]
        self.assertGreater(len(steps), 3)
        self.assertIn('id: capacity-probe', steps[0])
        self.assertIn('actions/upload-artifact@', steps[1])
        self.assertIn('id: capacity-election', steps[2])
        gate = "steps.capacity-election.outputs.selected == 'true'"
        for step in steps[3:]:
            with self.subTest(step=step.splitlines()[0]):
                conditions = re.findall(r'^        if: (.+)$', step, re.MULTILINE)
                self.assertEqual(len(conditions), 1)
                condition = conditions[0]
                if condition.startswith('${{'):
                    self.assertTrue(condition.endswith(' }}'))
                    condition = condition[3:-2].strip()
                self.assertTrue(condition == gate or
                                (condition.startswith(gate + ' && (') and
                                 condition.endswith(')')))

    def test_admission_fetches_pinned_source_before_checkout(self):
        workflow = (Path(__file__).resolve().parents[3] /
                    '.github/workflows/bench-e2e.yml').read_text()
        steps = re.split(r'^      - ', workflow, flags=re.MULTILINE)[1:]
        for step in (steps[0], steps[2]):
            self.assertIn('ref: context.sha', step)
            self.assertIn('debug: false', step)
            self.assertIn('retries: 0', step)
            self.assertIn('signal: AbortSignal.timeout(10000)', step)
            self.assertNotIn('require(process.cwd()', step)
        self.assertIn('max-parallel: 3', workflow)
        self.assertIn('slot: [1, 2, 3]', workflow)
        self.assertIn('fail-fast: false', workflow)
        self.assertIn('BENCH_CAPACITY_SLOTS: "3"', workflow)


if __name__ == '__main__':
    unittest.main()
