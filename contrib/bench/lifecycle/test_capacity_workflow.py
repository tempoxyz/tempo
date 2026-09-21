"""Fail closed if a later workflow edit lets a nonselected slot run a step."""
from pathlib import Path
import re
import hashlib
import unittest
from test_prebuilt_workflow import without_prebuilt, without_workspace_guard


def without_fault_scheduler(workflow):
    """Reverse only explicit opt-ins, preserving historical capacity hashes."""
    workflow=without_prebuilt(workflow)
    # Reverse only the separately reviewed cleanup follow-up; retain original capacity hashes.
    for name in ('Prepare runner cleanup', 'Prepare owned benchmark scratch'):
        workflow,count=re.subn(r'      - name: '+name+r'\n.*?(?=      - (?:name:|uses:))','',workflow,flags=re.DOTALL)
        assert count==1
    marker='\n      # Run after artifact upload/reporting even when the benchmark failed or was cancelled.\n'
    assert workflow.count(marker)==1
    workflow=workflow.split(marker,1)[0]
    assert workflow.count('        id: workspace-reset\n')==1
    workflow=workflow.replace('        id: workspace-reset\n','')
    workflow = without_workspace_guard(workflow)
    workflow,count=re.subn(r"          python3 - <<'PYOWNER'\n.*?          PYOWNER\n",'',workflow,flags=re.DOTALL)
    assert count==1
    workflow=workflow.replace('          - lifecycle-kernel-faults\n','')
    workflow=workflow.replace(" || inputs.profiling == 'lifecycle-kernel-faults'",'')
    workflow=workflow.replace("inputs.profiling != 'lifecycle-kernel-faults' && ",'')
    workflow=re.sub(r'^      BENCH_(?:LIFECYCLE_SCHEDULER|KERNEL_FAULT_BASELINE_EMPTY|KERNEL_FAULT_FEATURE):.*\n','',workflow,flags=re.MULTILINE)
    workflow,count=re.subn(r'      - name: Provision kernel fault diagnostic dependencies\n.*?(?=      - name: Check lifecycle report)','',workflow,flags=re.DOTALL)
    assert count==1
    workflow,count=re.subn(r'          if \[ "\$BENCH_LIFECYCLE_SCHEDULER" = "true" \]; then\n.*?^          fi\n','',workflow,flags=re.MULTILINE|re.DOTALL)
    assert count==1
    workflow=workflow.replace("        run: |\n          python3 -m unittest discover -s contrib/bench/lifecycle -p 'test_*.py'\n          python3 -m unittest discover -s contrib/bench/lifecycle/scheduler", "        run: python3 -m unittest discover -s contrib/bench/lifecycle -p 'test_*.py'")
    return workflow


class CapacityWorkflowTests(unittest.TestCase):
    def test_five_slot_workflow_preserves_entire_reviewed_setup_policy(self):
        workflow = (Path(__file__).resolve().parents[3] /
                    '.github/workflows/bench-e2e.yml').read_text()
        workflow = without_fault_scheduler(workflow)
        for old, new in [('max-parallel: 4', 'max-parallel: 5'),
                         ('slot: [1, 2, 3, 4]', 'slot: [1, 2, 3, 4, 5]'),
                         ('BENCH_CAPACITY_SLOTS: "4"', 'BENCH_CAPACITY_SLOTS: "5"')]:
            self.assertEqual(workflow.count(new), 1)
            workflow = workflow.replace(new, old)
        self.assertEqual(hashlib.sha256(workflow.encode()).hexdigest(), 'd57b1802b22a1a802d7fe7c1eb7165ee1d0e86b47fe7a2812822a0d977e41e73')

    def test_only_matrix_size_changes_from_reviewed_three_slot_workflow(self):
        workflow = (Path(__file__).resolve().parents[3] /
                    '.github/workflows/bench-e2e.yml').read_text()
        workflow = without_fault_scheduler(workflow)
        self.assertEqual(workflow.count('      BENCH_CAPACITY_POLICY: "setup_failure_v2"\n'), 1)
        workflow = workflow.replace('      BENCH_CAPACITY_POLICY: "setup_failure_v2"\n', '')
        workflow, count = re.subn(r'      - name: Publish capacity admission receipt\n.*?(?=      - name: Reset workspace directory)', '', workflow, flags=re.DOTALL)
        self.assertEqual(count, 1)
        for old, new in [('max-parallel: 3', 'max-parallel: 5'),
                         ('slot: [1, 2, 3]', 'slot: [1, 2, 3, 4, 5]'),
                         ('BENCH_CAPACITY_SLOTS: "3"', 'BENCH_CAPACITY_SLOTS: "5"')]:
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
        self.assertGreater(len(steps), 5)
        self.assertTrue(steps[0].startswith('name: Prepare runner cleanup\n'))
        self.assertNotRegex(steps[0], re.compile(r'^        if:', re.MULTILINE), 'cleanup preparation runs on every slot')
        self.assertTrue(steps[-1].startswith('name: Remove runner benchmark artifacts\n'))
        self.assertIn("if: ${{ always() && steps.runner-cleanup.outputs.directory != '' }}", steps[-1])
        steps = steps[1:-1]
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
        for step in [next(s for s in steps if "id: " + identity + "\n" in s)
                     for identity in ("runner-cleanup", "capacity-probe", "capacity-election")]:
            self.assertIn('ref: context.sha', step)
            self.assertIn('debug: false', step)
            self.assertIn('retries: 0', step)
            self.assertIn('signal: AbortSignal.timeout(10000)', step)
            self.assertNotIn('require(process.cwd()', step)
        self.assertIn('max-parallel: 5', workflow)
        self.assertIn('slot: [1, 2, 3, 4, 5]', workflow)
        self.assertIn('fail-fast: false', workflow)
        self.assertIn('BENCH_CAPACITY_SLOTS: "5"', workflow)


if __name__ == '__main__':
    unittest.main()
