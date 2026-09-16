import json
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT=Path(__file__).parent

@unittest.skipUnless(shutil.which('nu'), 'Nushell required')
class RunPlanTests(unittest.TestCase):
    def plan(self, sides, detail):
        result=subprocess.run(['nu','-c',f'source run-plan.nu; lifecycle-run-plan {json.dumps(sides)} {detail} | to json --raw'],cwd=ROOT,text=True,capture_output=True,check=True)
        return json.loads(result.stdout)

    def test_ordinary_order_and_labels_are_preserved(self):
        for detail in ('full','milestones'):
            plan=self.plan(['feature','baseline','baseline','feature'],detail)
            self.assertEqual([r['phase'] for r in plan],['feature-1','baseline-1','baseline-2','feature-2'])
            self.assertEqual([r['side'] for r in plan],['feature','baseline','baseline','feature'])
            self.assertTrue(all(r['detail']==detail for r in plan))
        self.assertEqual([r['phase'] for r in self.plan(['feature','feature'],'full')],['feature-1','feature-2'])

    def test_comparison_counterbalances_both_variant_and_detail_order(self):
        plan=self.plan(['feature','baseline','baseline','feature'],'compare')
        self.assertEqual([r['phase'] for r in plan],[
            'full-feature-1','full-baseline-1','milestones-feature-1','milestones-baseline-1',
            'milestones-baseline-2','milestones-feature-2','full-baseline-2','full-feature-2'])
        for detail in ('full','milestones'):
            selected=[r for r in plan if r['detail']==detail]
            self.assertEqual([r['side'] for r in selected],['feature','baseline','baseline','feature'])
            # Side is explicit: mode-prefixed labels must never select feature args for a baseline.
            self.assertTrue(all(('baseline' in r['phase'])==(r['side']=='baseline') for r in selected))
        self.assertEqual(len({r['phase'] for r in plan}),8)

if __name__=='__main__': unittest.main()
