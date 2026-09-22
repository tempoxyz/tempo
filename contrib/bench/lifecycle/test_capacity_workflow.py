"""Fail closed if a later workflow edit lets a nonselected slot run a step."""
from pathlib import Path
import re
import unittest


class CapacityWorkflowTests(unittest.TestCase):
    def test_single_diagnostic_workflow_has_one_reserved_slot(self):
        workflow = (Path(__file__).resolve().parents[3] /
                    '.github/workflows/bench-e2e.yml').read_text()
        self.assertEqual(workflow.count('      max-parallel: 1\n'), 1)
        self.assertEqual(workflow.count('        slot: [1]\n'), 1)
        self.assertEqual(workflow.count('      BENCH_CAPACITY_SLOTS: "1"\n'), 1)
        self.assertNotIn('slot: [1, 2', workflow)

    def test_single_diagnostic_constants_are_closed(self):
        workflow = (Path(__file__).resolve().parents[3] /
                    '.github/workflows/bench-e2e.yml').read_text()
        for line in (
                '      BENCH_CAPACITY_POLICY: "single_diagnostic_v1"\n',
                '      BENCH_BINARY_MODE: "prebuilt_v1"\n',
                '      BENCH_LIFECYCLE: "true"\n',
                '      BENCH_LIFECYCLE_SCHEDULER: "false"\n',
                '      BENCH_LIFECYCLE_DETAIL: "milestones"\n',
                '      BENCH_DURATION: "30"\n',
                '      BENCH_NO_SLACK: "true"\n',
                '      BENCH_SAMPLY: "false"\n',
                '      BENCH_TRACY: "off"\n',
                '      BENCH_OTLP: "false"\n',
                '      BENCH_VALSCOPE: "false"\n',
                '      BENCH_METRICS: "false"\n',
                '      BENCH_FEATURE_ENV: "RETH_EXPERIMENTAL_PROOF_BACKLOG_GROUPING=1"\n',
                '      BENCH_READ_READINESS: "true"\n',
                '      BENCH_RUN_PAIRS: "1"\n',
                '      BENCH_RUN_SIDE: "comparison"\n'):
            self.assertEqual(workflow.count(line), 1, line)

    def test_read_readiness_is_forwarded_to_both_feature_validators(self):
        harness = (Path(__file__).resolve().parents[3] / 'bench-e2e.nu').read_text()
        self.assertEqual(harness.count('"TEMPO_READ_READINESS=1 "'), 1)
        self.assertIn(
            'let a_capture = if $ctx.lifecycle { $"($prewarm_config.env)($scheduler_env)'
            '($readiness_env)RETH_LIFECYCLE_FILE=', harness)
        self.assertIn(
            'let b_capture = if $ctx.lifecycle { $"($prewarm_config.env)($scheduler_env)'
            '($readiness_env)RETH_LIFECYCLE_FILE=', harness)
        self.assertIn('$"($env_prefix)($a_capture)"', harness)
        self.assertIn('$"($env_prefix)($b_capture)"', harness)

    def test_read_readiness_guard_fails_closed_before_phase_setup(self):
        harness = (Path(__file__).resolve().parents[3] / 'bench-e2e.nu').read_text()
        guard = harness.split(
            'let readiness_mode = ($env.BENCH_READ_READINESS? | default "false")', 1)[1]
        guard = guard.split('if $lifecycle_scheduler and', 1)[0]
        for requirement in (
                '$readiness_mode not-in ["false" "true"]', 'not $prebuilt',
                'not $lifecycle', '$lifecycle_detail != "milestones"',
                '$run_side != "feature"', '$run_pairs != 1', '$duration != 30',
                '$lifecycle_scheduler', '$lifecycle_prewarm_cpu != "disabled"'):
            self.assertIn(requirement, guard)
        self.assertIn(
            'Read-readiness requires a 30-second prebuilt milestone diagnostic capture', guard)
        self.assertLess(harness.index('let readiness_mode ='),
                        harness.index('let preset_spec =', harness.index('let readiness_mode =')))

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
        self.assertTrue(steps[0].startswith('name: Secure runner\n'))
        self.assertNotRegex(steps[0], re.compile(r'^        if:', re.MULTILINE))
        steps = steps[1:]
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
        self.assertIn('max-parallel: 1', workflow)
        self.assertIn('slot: [1]', workflow)
        self.assertIn('fail-fast: false', workflow)
        self.assertIn('BENCH_CAPACITY_SLOTS: "1"', workflow)


if __name__ == '__main__':
    unittest.main()
