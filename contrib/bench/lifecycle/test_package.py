import copy
from collections import Counter
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from perfetto import trace_events
from report import build
from report_package import write_package
from test_report import fixture


def embedded(path):
    return json.loads(re.search(r'<script type="application/json" id="data">(.*?)</script>', path.read_text(), re.S)[1])


def identity(event):
    return json.dumps({k:v for k,v in event.items() if k != 'tid'}, sort_keys=True)


class PackageTests(unittest.TestCase):
    def capture(self, directory, cutoff=None):
        path = Path(directory)/'a.jsonl'
        fixture(path)
        return build([path], warmup=5, window={'backpressure': {'ts': cutoff, 'node':'Validator A'}} if cutoff else None)

    def test_context_chunks_preserve_every_interval_marker_and_source_data(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.capture(directory)
            extra = dict(data['spans'][0], id=12345, block=None, attempt=None, start=0, end=110_000)
            data['spans'].append(extra)
            data['transfers'] = [dict(start=0, end=100_500, bytes=12, **{'from':'Validator A', 'to':'Validator A'})]
            original = copy.deepcopy(data)
            out = Path(directory)/'report'
            manifest = write_package(data, out, chunk_intervals=23)
            self.assertEqual(data, original)
            self.assertFalse((out/'perfetto.json').exists())
            actual = []
            for chunk in manifest['chunks']:
                self.assertLessEqual(chunk['records'], 23)
                actual.extend(e for e in json.loads((out/chunk['file']).read_text())['traceEvents'] if e['ph'] != 'M')
            expected_data = dict(data, blocks=data['blocks'] + [dict(a, id=None, attempt=a['id']) for a in data['attempt_details'] if not a.get('block')])
            expected = [e for e in trace_events(expected_data) if e['ph'] != 'M']
            self.assertEqual(Counter(map(identity, actual)), Counter(map(identity, expected)))
            long = next(e for e in actual if e.get('args', {}).get('span_id') == 12345)
            self.assertEqual(long['dur'], 110_000_000)
            self.assertGreater(manifest['chunks'][0]['end'], manifest['chunks'][1]['start'])
            self.assertEqual(sum(c['spans'] for c in manifest['chunks']), len(data['spans']))
            self.assertEqual(sum(c['transfers'] for c in manifest['chunks']), 1)

    def test_compact_summary_focus_population_links_and_cutoff(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.capture(directory, cutoff=20_500_000_000)
            data['read_readiness'] = {'events': [{'fields': {'global_payload': 'must stay in lifecycle.json'}}] * 100}
            for index, block in enumerate(data['blocks'], 1):
                block['read_readiness'] = [{'stage': 'read_totals', 'fields': {'read_role': index, 'read_calls': index}}]
            out = Path(directory)/'report'
            out.mkdir()
            (out/'lifecycle.json').write_text(json.dumps(data))
            before = (out/'lifecycle.json').read_bytes()
            manifest = write_package(data, out, chunk_intervals=25)
            self.assertEqual((out/'lifecycle.json').read_bytes(), before)
            index = (out/'index.html').read_text()
            self.assertNotIn('"spans":', index)
            self.assertLess(len(index), 30_000)
            self.assertEqual({p['id'] for p in manifest['pages'] if not p['attempt']}, {b['id'] for b in data['blocks']})
            self.assertEqual({p['block'] for p in manifest['percentiles']}, set(data['representatives'].values()))
            for p in manifest['percentiles']:
                focused = embedded(out/p['page'])
                self.assertEqual([b['id'] for b in focused['blocks']], [p['block']])
                self.assertEqual(
                    [(b['id'], b['duration'], b['in_population']) for b in focused['population_blocks']],
                    [(b['id'], b['duration'], b['in_population']) for b in data['blocks']])
                self.assertTrue(all(set(b) == {'id', 'duration', 'in_population'}
                                    for b in focused['population_blocks']))
                self.assertEqual(focused['blocks'],
                                 [b for b in data['blocks'] if b['id'] == p['block']])
                self.assertNotIn('read_readiness', focused)
                selected = focused['blocks'][0]['read_readiness']
                expected = next(b['read_readiness'] for b in data['blocks'] if b['id'] == p['block'])
                self.assertEqual(selected, expected)
                self.assertEqual(focused['eligible'], data['eligible'])
            self.assertIn('global_payload', (out/'lifecycle.json').read_text())
            for page in out.glob('*.html'):
                for href in re.findall(r'href="([^"]+)"', page.read_text()):
                    self.assertTrue((out/href).exists(), (page.name, href))
            cutoff = data['boundary']['relative_ms'] * 1000
            for path in [out/c['file'] for c in manifest['chunks']] + [out/p['trace'] for p in manifest['pages']]:
                for event in json.loads(path.read_text())['traceEvents']:
                    if event['ph'] == 'M': continue
                    if event['ph'] == 'X': self.assertLessEqual(event['ts'] + event['dur'], cutoff + 1e-7)
                    else: self.assertLess(event['ts'], cutoff)

    def test_focused_page_keeps_causal_ancestors_without_unrelated_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.capture(directory, cutoff=3_500_000_000)
            selected = data['spans'][0]
            selected['parent'] = 12345
            parent = dict(selected, id=12345, parent=None, block=None, attempt=None)
            unrelated = dict(parent, id=12346)
            data['spans'].extend([parent, unrelated])
            out = Path(directory)/'report'
            write_package(data, out)
            page = embedded(out/f"block-{selected['block']}.html")
            self.assertEqual({s['id'] for s in page['spans']}, {selected['id'], 12345})
            events = json.loads((out/f"perfetto-block-{selected['block']}.json").read_text())['traceEvents']
            ancestor = next(e for e in events if e.get('args', {}).get('span_id') == 12345)
            self.assertEqual(ancestor['args']['block'], None)
            self.assertIn('causal ancestor', ancestor['args']['association'])

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for viewer helper regression')
    def test_job_summary_uses_attempted_own_vectors_and_rejects_missing_or_inexact(self):
        template = Path(__file__).with_name('viewer.html').read_text()
        helper = template.split('// BEGIN WORKER_CPU_HELPER')[1].split('// END WORKER_CPU_HELPER')[0]
        script = helper + """
const base={stage:'proof_storage_worker_totals',worker_job_counts_measured:1,worker_job_counts_saturated:0,
 worker_jobs:1,worker_target_max:0,worker_storage_targets:0,worker_root_requests:1,
 worker_jobs_targets_0:1,worker_jobs_targets_1:0,worker_jobs_targets_2_8:0,
 worker_jobs_targets_9_32:0,worker_jobs_targets_33_plus:0};
const account={...base,stage:'proof_account_worker_totals',worker_account_targets:0,worker_storage_groups:3};
delete account.worker_storage_targets;delete account.worker_root_requests;
console.log(JSON.stringify([[{}],[base],[account],[base,{}],[{...base,worker_job_counts_saturated:1}],
 [{...base,worker_jobs:0}],[{...base,worker_storage_targets:2**64}],
 [{...base,worker_jobs:0,worker_root_requests:0,worker_jobs_targets_0:0}]].map(proofJobSummary)));
"""
        missing, storage, account, partial, saturated, invalid, inexact, zero = json.loads(subprocess.check_output(['node','-e',script],text=True))
        self.assertIn('unmeasured',missing)
        self.assertIn('1 attempted jobs',storage)
        self.assertIn('0 storage vector targets',storage)
        self.assertIn('1 root requests',storage)
        self.assertIn('failed calculations or abandoned results',storage)
        self.assertIn('0 account vector targets',account)
        self.assertIn('3 storage groups (storage target total unmeasured)',account)
        self.assertIn('1/2 completions',partial)
        for value in [saturated,invalid,inexact]: self.assertIn('unmeasured',value)
        self.assertIn('0 attempted jobs',zero)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for viewer helper regression')
    def test_joint_account_shape_is_optional_and_rejects_invalid_counts(self):
        template = Path(__file__).with_name('viewer.html').read_text()
        helper = template.split('// BEGIN WORKER_CPU_HELPER')[1].split('// END WORKER_CPU_HELPER')[0]
        script = helper + """
const base={stage:'proof_account_worker_totals',worker_job_counts_measured:1,worker_job_counts_saturated:0,
 worker_jobs:3,worker_target_max:1,worker_account_targets:1,worker_storage_groups:2,
 worker_jobs_targets_0:2,worker_jobs_targets_1:1,worker_jobs_targets_2_8:0,
 worker_jobs_targets_9_32:0,worker_jobs_targets_33_plus:0};
console.log(JSON.stringify([[base],[{...base,worker_jobs_storage_only_single_group:0}],
 [{...base,worker_jobs_storage_only_single_group:2}],
 [base,{...base,worker_jobs_storage_only_single_group:1}],
 ...[-1,3,2**64,'private'].map(value=>[{...base,worker_jobs_storage_only_single_group:value}]),
 [{...base,worker_jobs_storage_only_single_group:1,worker_job_counts_saturated:1}]].map(proofJobSummary)));
"""
        missing, zero, exact, partial, *invalid = json.loads(subprocess.check_output(['node','-e',script],text=True))
        self.assertIn('joint storage-only single-group count unmeasured',missing)
        self.assertIn('0/3 attempted account jobs',zero)
        self.assertIn('2/3 attempted account jobs',exact)
        self.assertIn('zero account targets and exactly one storage group',exact)
        self.assertIn('1/2 completions with joint counts',partial)
        for value in invalid:
            self.assertIn('unmeasured',value)
            self.assertNotIn('private',value)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for viewer helper regression')
    def test_worker_cpu_summary_preserves_unavailable_zero_and_failure(self):
        template = Path(__file__).with_name('viewer.html').read_text()
        helper = template.split('// BEGIN WORKER_CPU_HELPER')[1].split('// END WORKER_CPU_HELPER')[0]
        script = "const ms=n=>n.toFixed(3)+' ms';" + helper + """
const base={node:'Validator A',stage:'proof_storage_worker_totals',worker_success:1};
const unavailable={...base,worker_cpu_measured:0};
const zero={...base,worker_cpu_measured:1,worker_thread_cpu_ns:0};
const measured={...base,worker_cpu_measured:1,worker_thread_cpu_ns:12000000,worker_run_ns:10000000};
console.log(JSON.stringify([[],[unavailable],[zero],[zero,unavailable,{...measured,worker_success:0}]].map(proofWorkerSummary)));
"""
        absent, unavailable, zero, mixed = json.loads(subprocess.check_output(['node', '-e', script], text=True))
        self.assertIn('Not measured', absent)
        self.assertIn('1 unavailable', unavailable)
        self.assertIn('CPU unmeasured', unavailable)
        self.assertIn('CPU 0.000 ms', zero)
        self.assertIn('3 recorded completions', mixed)
        self.assertIn('2 measured', mixed)
        self.assertIn('1 unavailable', mixed)
        self.assertIn('1 failed', mixed)
        self.assertIn('CPU 12.000 ms', mixed)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for viewer helper regression')
    def test_viewer_resource_counts_are_not_durations_and_missing_is_not_zero(self):
        template = Path(__file__).with_name('viewer.html').read_text()
        helper = template.split('// BEGIN EXECUTION_LOOP_HELPER')[1].split('// END EXECUTION_LOOP_HELPER')[0]
        script = "const ms=n=>n.toFixed(3)+' ms';" + helper + """
const zero={execution_resources_measured:1,execution_voluntary_context_switches:0,
  execution_involuntary_context_switches:0,execution_minor_page_faults:0,
  execution_major_page_faults:0,execution_block_input_operations:0,execution_block_output_operations:0};
console.log(JSON.stringify([
  {}, {execution_resources_measured:0}, zero,
  {...zero,execution_voluntary_context_switches:7,execution_minor_page_faults:13,execution_block_input_operations:19},
  {...zero,execution_major_page_faults:null},
  {execution_loop_ns:10000000,execution_cpu_measured:1,execution_thread_cpu_ns:12000000}
].map(executionLoopSummary)));
"""
        old, unavailable, zero, counts, incomplete, cpu = json.loads(subprocess.check_output(['node', '-e', script], text=True))
        for text in (old, unavailable, incomplete):
            self.assertIn('loop resource counters unmeasured', text)
        self.assertIn('voluntary/involuntary context switches 0/0', zero)
        self.assertIn('minor/major page faults 13/0', counts)
        self.assertIn('filesystem input/output operations 19/0', counts)
        self.assertIn('counts, not wait durations or proof of a cause', counts)
        self.assertIn('loop thread CPU 12.000 ms', cpu)
        self.assertIn('loop resource counters unmeasured', cpu)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for viewer helper regression')
    def test_viewer_cpu_distinguishes_unmeasured_from_zero(self):
        template = Path(__file__).with_name('viewer.html').read_text()
        helper = template.split('// BEGIN EXECUTION_LOOP_HELPER')[1].split('// END EXECUTION_LOOP_HELPER')[0]
        script = "const ms=n=>n.toFixed(3)+' ms';" + helper + """
console.log(JSON.stringify([
  {},
  {execution_loop_ns:10000000,execution_cpu_measured:0},
  {execution_loop_ns:10000000,execution_cpu_measured:1,execution_thread_cpu_ns:0},
  {execution_loop_ns:10000000,execution_cpu_measured:1,execution_thread_cpu_ns:12000000}
].map(executionLoopSummary)));
"""
        old, missing, zero, larger = json.loads(subprocess.check_output(['node', '-e', script], text=True))
        self.assertIn('loop wall unmeasured', old)
        self.assertIn('loop thread CPU unmeasured', old)
        self.assertIn('loop wall 10.000 ms', missing)
        self.assertIn('loop thread CPU unmeasured', missing)
        self.assertIn('loop thread CPU 0.000 ms', zero)
        # Preserve the measured values independently, without clamping to wall time.
        self.assertIn('loop wall 10.000 ms', larger)
        self.assertIn('loop thread CPU 12.000 ms', larger)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for viewer helper regression')
    def test_viewer_reveals_nonoverlapping_causal_ancestors_and_extends_axis(self):
        template = Path(__file__).with_name('viewer.html').read_text()
        helpers = template.split('// BEGIN FOCUSED_CONTEXT_HELPERS')[1].split('// END FOCUSED_CONTEXT_HELPERS')[0]
        script = helpers + """
const block={id:2,start:100,end:200};
const own={id:2,block:2,start:100,end:200};
const before={id:1,block:null,start:0,end:1};
const after={id:3,block:null,start:300,end:400};
const data={packaged:true,spans:[own,before,after]};
const isOwn=s=>s.block===2;
const extra=contextSpans(data,block,isOwn,true);
console.log(JSON.stringify({ids:extra.map(s=>s.id),extent:timelineExtent(data,block,[own],[own,...extra]),
  hidden:contextSpans(data,block,isOwn,false),ancestor:associationLabel(data,false,false),
  temporal:associationLabel({...data,context_chunk:true},false,false),
  chunk:contextSpans({...data,context_chunk:true},block,isOwn,false).length,
  legacy:contextSpans({...data,packaged:false},block,isOwn,true)}));
"""
        result = json.loads(subprocess.check_output(['node', '-e', script], text=True))
        self.assertEqual(result['ids'], [1, 3])
        self.assertEqual(result['extent'], [0, 400])
        self.assertEqual(result['hidden'], [])
        self.assertEqual(result['legacy'], [])
        self.assertEqual(result['chunk'], 3)
        self.assertIn('causal ancestor', result['ancestor'])
        self.assertEqual(result['temporal'], 'temporal context; no causal assertion')

    def test_repack_removes_stale_generated_exports_but_keeps_raw(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.capture(directory, cutoff=3_500_000_000)
            out = Path(directory)/'report'
            out.mkdir()
            for name in ('perfetto.json', 'block-999.html', 'context-9999.json', 'perfetto-p99.json'):
                (out/name).write_text('stale')
            (out/'a.jsonl').write_text('raw unchanged')
            data['bad_capture'] = True
            manifest = write_package(data, out)
            self.assertEqual(manifest['percentiles'], [])
            self.assertEqual((out/'a.jsonl').read_text(), 'raw unchanged')
            self.assertFalse((out/'perfetto.json').exists())
            self.assertFalse((out/'block-999.html').exists())
            self.assertFalse((out/'context-9999.json').exists())
            self.assertFalse((out/'perfetto-p99.json').exists())
            self.assertEqual(embedded(out/'block-1.html')['percentile_blocks'], {})


if __name__ == '__main__':
    unittest.main()
