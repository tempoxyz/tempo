"""Fail closed if a later workflow edit lets a nonselected slot run a step."""
from pathlib import Path
import re
import hashlib
import unittest


class CapacityWorkflowTests(unittest.TestCase):
    def test_only_matrix_size_changes_from_reviewed_three_slot_workflow(self):
        workflow = (Path(__file__).resolve().parents[3] /
                    '.github/workflows/bench-e2e.yml').read_text()
        self.assertEqual(workflow.count('      BENCH_CAPACITY_POLICY: "setup_failure_v2"\n'), 1)
        workflow = workflow.replace('      BENCH_CAPACITY_POLICY: "setup_failure_v2"\n', '')
        workflow, count = re.subn(r'      - name: Publish capacity admission receipt\n.*?(?=      - name: Reset workspace directory)', '', workflow, flags=re.DOTALL)
        self.assertEqual(count, 1)
        for old, new in [('max-parallel: 3', 'max-parallel: 4'),
                         ('slot: [1, 2, 3]', 'slot: [1, 2, 3, 4]'),
                         ('BENCH_CAPACITY_SLOTS: "3"', 'BENCH_CAPACITY_SLOTS: "4"')]:
            self.assertEqual(workflow.count(new), 1)
            workflow = workflow.replace(new, old)
        # Frozen ecb workflow: all 38 original steps and their exact gates,
        # permissions, runner labels and benchmark arguments remain unchanged.
        self.assertEqual(hashlib.sha256(workflow.encode()).hexdigest(),
                         '8dee2903c5a843d4d755b4e2762fbb13278a7b2eb37e31d6b4200a1ca9c434b8')

    def test_setup_policy_receipt_is_uploaded_before_workspace_reset(self):
        workflow = (Path(__file__).resolve().parents[3] /
                    '.github/workflows/bench-e2e.yml').read_text()
        self.assertLess(workflow.index('- name: Publish capacity admission receipt'),
                        workflow.index('- name: Reset workspace directory'))
        step = workflow.split('- name: Publish capacity admission receipt', 1)[1].split('\n      - ', 1)[0]
        self.assertIn("env.BENCH_CAPACITY_POLICY == 'setup_failure_v2'", step)
        self.assertIn('steps.capacity-election.outputs.admission-name', step)
        self.assertIn('steps.capacity-election.outputs.admission-path', step)
        self.assertIn('if-no-files-found: error', step)

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
        self.assertIn('max-parallel: 4', workflow)
        self.assertIn('slot: [1, 2, 3, 4]', workflow)
        self.assertIn('fail-fast: false', workflow)
        self.assertIn('BENCH_CAPACITY_SLOTS: "4"', workflow)


if __name__ == '__main__':
    unittest.main()
