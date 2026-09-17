"""Exact account-worker association and explicit missing inline-counter semantics."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from report import build, write_report
from perfetto import trace_events
from test_report import fixture

COUNTERS = ('worker_inline_storage_attempts','worker_inline_storage_targets')
COMMON = dict(worker_job_counts_measured=1,worker_job_counts_saturated=0,
              worker_jobs=2,worker_account_targets=0,worker_storage_groups=2,
              worker_jobs_targets_0=2,worker_jobs_targets_1=0,worker_jobs_targets_2_8=0,
              worker_jobs_targets_9_32=0,worker_jobs_targets_33_plus=0,worker_target_max=0,
              worker_jobs_storage_only_single_group=2)

def add_worker(records, ident, fields, name='account_worker', stage='proof_account_worker_totals',
               when=1_000_000_300, parent=1):
    records[-1:-1]=[
        dict(type='start',id=ident,parent=parent,ts=1_000_000_100,thread=2,name=name,
             category='trie::proof_task',fields={}),
        dict(type='event',id=ident,ts=when,fields=dict(COMMON,stage=stage) | fields),
        dict(type='end',id=ident,ts=1_000_000_500),
    ]

class InlineCountsTests(unittest.TestCase):
    def test_raw_package_and_trace_bind_exact_worker_and_preserve_zero_legacy(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);paths=[root/'a.jsonl',root/'b.jsonl']
            for n,path in enumerate(paths):
                fixture(path);records=[json.loads(x) for x in path.read_text().splitlines()]
                add_worker(records,201,dict(zip(COUNTERS,(n,8*n))))
                add_worker(records,202,{})
                path.write_text('\n'.join(map(json.dumps,records)))
            data=write_report(paths,root/'out',warmup=0)
            totals=data['blocks'][0]['proof_worker_totals']
            self.assertEqual([{k:r[k] for k in COUNTERS} for r in totals if r['span']==201],
                             [dict(zip(COUNTERS,(0,0))),dict(zip(COUNTERS,(1,8)))])
            self.assertTrue(all(not any(k in r for k in COUNTERS) for r in totals if r['span']==202))
            for span in data['spans']:
                if span['id']==201:
                    self.assertEqual(span['block'],1)
                    self.assertEqual(span['details'][COUNTERS[0]],int(span['node']=='Validator B'))
                if span['id']==202:self.assertTrue(all(k not in span['details'] for k in COUNTERS))
            traces=[e for e in trace_events(data) if e.get('ph')=='X' and e['args']['span_id']==201]
            self.assertCountEqual([e['args'][COUNTERS[1]] for e in traces],[0,8])
            focused=json.loads((root/'out'/'lifecycle.json').read_text())
            self.assertEqual(focused['blocks'][0]['proof_worker_totals'],totals)
            cut=build(paths,warmup=0,window={'backpressure':dict(ts=1_000_000_300,node='Validator A')})
            self.assertTrue(all(not b['proof_worker_totals'] for b in cut['blocks']))
            self.assertTrue(all(all(k not in s['details'] for k in COUNTERS) for s in cut['spans']))

    def test_mismatched_missing_duplicate_invalid_and_unbound_are_unavailable(self):
        valid=dict(zip(COUNTERS,(1,4)))
        cases=[({**valid,'worker_job_counts_measured':True},{},False),
               ({**valid,'worker_job_counts_saturated':False},{},False),({}, {},False),({COUNTERS[0]:1},{},False),
               ({**valid,COUNTERS[0]:True},{},False),({**valid,COUNTERS[1]:2**64},{},False),
               ({**valid,COUNTERS[0]:0},{},False),({**valid,COUNTERS[0]:3},{},False),
               ({**valid,COUNTERS[1]:'private'},{},False),
               (valid,{'name':'storage_worker'},False),(valid,{'when':1_000_000_600},False),
               (valid,{'parent':None},False),(valid,{},True)]
        for fields,options,duplicate in cases:
            with self.subTest(fields=fields,options=options,duplicate=duplicate),tempfile.TemporaryDirectory() as d:
                path=Path(d)/'a.jsonl';fixture(path)
                records=[json.loads(x) for x in path.read_text().splitlines()]
                add_worker(records,201,fields,**options)
                if duplicate:
                    records.insert(-1,dict(type='event',id=201,ts=1_000_000_400,
                        fields=dict(COMMON,stage='proof_account_worker_totals',**valid)))
                path.write_text('\n'.join(map(json.dumps,records)))
                data=build([path],warmup=0)
                self.assertTrue(all(all(k not in t for k in COUNTERS) for b in data['blocks'] for t in b['proof_worker_totals']))
                self.assertTrue(all(all(k not in s['details'] for k in COUNTERS) for s in data['spans']))

    @unittest.skipUnless(shutil.which('node'),'Node required')
    def test_viewer_missing_zero_partial_and_failed_attempts(self):
        helper=Path(__file__).with_name('viewer.html').read_text().split('// BEGIN WORKER_CPU_HELPER')[1].split('// END WORKER_CPU_HELPER')[0]
        common=dict(COMMON,stage='proof_account_worker_totals')
        measured=dict(common,worker_inline_storage_attempts=1,worker_inline_storage_targets=4,worker_success=0)
        zero=dict(common,worker_inline_storage_attempts=0,worker_inline_storage_targets=0)
        rows=[[common],[zero],[measured],[common,measured],
              [{**measured,'worker_inline_storage_targets':'private'}],
              [{**measured,'worker_inline_storage_attempts':3}],
              [{**measured,'worker_job_counts_saturated':1}]]
        output=json.loads(subprocess.check_output(['node','-e',helper+'\nconsole.log(JSON.stringify('+json.dumps(rows)+'.map(proofJobSummary)))'],text=True))
        self.assertIn('inline storage attempts/targets unavailable',output[0])
        self.assertIn('0 attempted calculations / 0 vector targets',output[1])
        self.assertIn('1 attempted calculations / 4 vector targets',output[2])
        self.assertIn('not storage-pool dequeues',output[2])
        self.assertIn('1/2 completions measured',output[3])
        self.assertTrue(all('private' not in x for x in output))
        self.assertTrue(all('1 attempted calculations' not in x for x in output[4:]))
