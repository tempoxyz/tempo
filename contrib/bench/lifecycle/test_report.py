import json
from pathlib import Path
import tempfile
import unittest
from report import build, nearest_rank, write_report, active_wall_ns, read_node


def fixture(path, lost=0, close=True):
    events=[{'type':'header','schema':1}]
    for i in range(1,101):
        token=f'{i:024x}'
        start=i*1_000_000_000
        events += [
            {'type':'start','id':i,'ts':start,'thread':1,'name':'handle_propose','category':'consensus','parent':None,'fields':{}},
            {'type':'event','id':i,'ts':start,'fields':{'stage':'proposal_start'}},
            {'type':'event','id':i,'ts':start+100,'fields':{'stage':'proposal_ready','block_hash':token}},
            {'type':'event','id':i,'ts':start+i*1_000_000,'fields':{'stage':'finalized','block_hash':token}},
            {'type':'end','id':i,'ts':start+i*1_000_000},
        ]
    # A cancelled attempt must not become a zero-duration percentile sample.
    events += [{'type':'start','id':101,'ts':101_000_000_000,'thread':1,'name':'handle_propose','category':'consensus','parent':None,'fields':{}},
               {'type':'event','id':101,'ts':101_000_000_001,'fields':{'stage':'cancelled'}},
               {'type':'end','id':101,'ts':101_000_000_002}]
    if close:events.append({'type':'footer','dropped':lost,'io_error':False})
    path.write_text('\n'.join(json.dumps(e) for e in events))


class ReportTests(unittest.TestCase):
    def test_worker_slice_cpu_uses_exact_node_span_kind_and_retained_completion(self):
        from perfetto import trace_events
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory)/name for name in ('a.jsonl', 'b.jsonl')]
            for index, path in enumerate(paths):
                fixture(path)
                records = [json.loads(line) for line in path.read_text().splitlines()]
                extra = []
                for ident, name in ((201, 'storage_worker'), (202, 'account_worker'),
                                    (203, 'storage_worker'), (204, 'storage_worker')):
                    extra += [dict(type='start', id=ident, ts=1_000_000_100, thread=2,
                                   name=name, category='trie::proof_task', parent=1, fields={}),
                              dict(type='end', id=ident, ts=1_000_000_500)]
                def total(ident, stage, **fields):
                    return dict(type='event', id=ident, ts=1_000_000_400,
                                fields=dict(stage=stage, **fields))
                extra += [
                    total(201, 'proof_storage_worker_totals', worker_run_ns=10,
                          worker_thread_cpu_ns=index*20, worker_cpu_measured=1, worker_success=1),
                    # An account completion on a storage span cannot populate its CPU.
                    total(203, 'proof_account_worker_totals', worker_thread_cpu_ns=999),
                    total(202, 'proof_account_worker_totals', worker_run_ns=20,
                          worker_cpu_measured=0, worker_success=0),
                    total(204, 'proof_storage_worker_totals', worker_thread_cpu_ns=30),
                    total(204, 'proof_storage_worker_totals', worker_thread_cpu_ns=40),
                    # Never attach a worker completion to its execution/proposal ancestor.
                    total(1, 'proof_storage_worker_totals', worker_thread_cpu_ns=999),
                ]
                records[-1:-1] = extra
                path.write_text('\n'.join(map(json.dumps, records)))
            result = build(paths, warmup=0)
            spans = {(s['node'], s['id']): s for s in result['spans']}
            for index, node in enumerate(('Validator A', 'Validator B')):
                details = spans[(node, 201)]['details']
                self.assertEqual(details['worker_thread_cpu_ns'], index*20)
                self.assertEqual(details['worker_completion_count'], 1)
                self.assertEqual(spans[(node, 202)]['details']['worker_cpu_measured'], 0)
                self.assertNotIn('worker_thread_cpu_ns', spans[(node, 202)]['details'])
                self.assertEqual(spans[(node, 203)]['details'], {'worker_completion_count': 0})
                self.assertEqual(spans[(node, 204)]['details'], {'worker_completion_count': 2})
                self.assertNotIn('worker_thread_cpu_ns', spans[(node, 1)]['details'])
            exported = [e for e in trace_events(result) if e['ph']=='X'
                        and e['args']['span_id']==201]
            self.assertCountEqual([e['args']['worker_thread_cpu_ns'] for e in exported], [0,20])
            self.assertTrue(all('not block elapsed' in e['args']['worker_cpu_scope'] for e in exported))
            pruned = build(paths, warmup=0, window={'backpressure': {
                'ts': 1_000_000_400, 'node': 'Validator A'}})
            workers = [s for s in pruned['spans'] if s['id'] in (201,202,203,204)]
            self.assertEqual(len(workers), 8)
            self.assertTrue(all(s['details']=={'worker_completion_count': 0} for s in workers))

    def test_proof_worker_totals_preserve_completions_and_strict_cutoff(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            values = [
                dict(worker_run_ns=10, worker_thread_cpu_ns=20, worker_cpu_measured=1, worker_success=1),
                dict(worker_run_ns=30, worker_thread_cpu_ns=0, worker_cpu_measured=1, worker_success=1),
                dict(worker_run_ns=40, worker_cpu_measured=0, worker_success=0),
            ]
            records[-1:-1] = [dict(type='event', id=1, ts=1_000_000_200+i,
                                  fields=dict(stage='proof_storage_worker_totals', **fields))
                              for i, fields in enumerate(values)]
            path.write_text('\n'.join(map(json.dumps, records)))
            result = write_report([path], Path(directory)/'report', warmup=0)
            totals = result['blocks'][0]['proof_worker_totals']
            self.assertEqual(len(totals), 3)
            for row, fields in zip(totals, values):
                self.assertEqual(row['span'], 1)
                self.assertEqual(row['node'], 'Validator A')
                self.assertEqual({k:v for k,v in row.items() if k.startswith('worker_')}, fields)
            pruned = build([path], warmup=0, window={'backpressure': {'ts': 1_000_000_200, 'node': 'Validator A'}})
            self.assertTrue(all(not b['proof_worker_totals'] for b in pruned['blocks']))

    def test_job_counts_preserve_kind_missing_saturation_and_cutoff(self):
        common = dict(worker_job_counts_measured=1, worker_jobs=1, worker_target_max=0,
                      worker_jobs_targets_0=1, worker_jobs_targets_1=0,
                      worker_jobs_targets_2_8=0, worker_jobs_targets_9_32=0,
                      worker_jobs_targets_33_plus=0, worker_job_counts_saturated=0)
        values = [dict(stage='proof_storage_worker_totals', **common,
                       worker_storage_targets=0, worker_root_requests=1),
                  dict(stage='proof_account_worker_totals', **common,
                       worker_account_targets=0, worker_storage_groups=3,
                       worker_jobs_storage_only_single_group=1),
                  dict(stage='proof_storage_worker_totals', worker_job_counts_measured=0),
                  dict(stage='proof_storage_worker_totals', worker_job_counts_measured=1,
                       worker_job_counts_saturated=1, worker_jobs=2**64-1)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            records[-1:-1] = [dict(type='event', id=1, ts=1_000_000_200+i, fields=value)
                              for i,value in enumerate(values)]
            path.write_text('\n'.join(map(json.dumps,records)))
            result = write_report([path], Path(directory)/'report', warmup=0)
            totals = result['blocks'][0]['proof_worker_totals']
            for row,fields in zip(totals,values):
                self.assertEqual({k:v for k,v in row.items() if k=='stage' or k.startswith('worker_')}, fields)
            self.assertEqual(len(totals),4)
            pruned = build([path],warmup=0,window={'backpressure':dict(ts=1_000_000_202,node='Validator A')})
            self.assertEqual(len(pruned['blocks'][0]['proof_worker_totals']),2)

    def test_execution_resource_counts_preserve_unavailable_and_cutoff(self):
        counters = [
            'execution_voluntary_context_switches', 'execution_involuntary_context_switches',
            'execution_minor_page_faults', 'execution_major_page_faults',
            'execution_block_input_operations', 'execution_block_output_operations',
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            values = [
                dict(execution_resources_measured=1, **dict(zip(counters, range(6)))),
                dict(execution_resources_measured=1, **dict.fromkeys(counters, 0)),
                dict(execution_resources_measured=0),
                {},  # CPU-capable older capture without supplemental counters.
            ]
            records[-1:-1] = [dict(type='event', id=i, ts=i*1_000_000_000+200,
                                  fields=dict(stage='execution_totals', execution_loop_ns=100,
                                              execution_cpu_measured=1, execution_thread_cpu_ns=80, **fields))
                              for i, fields in enumerate(values, 1)]
            path.write_text('\n'.join(map(json.dumps, records)))
            result = write_report([path], Path(directory)/'report', warmup=0)
            for block, fields in zip(result['blocks'], values):
                self.assertEqual(block['execution_totals'][0],
                                 dict(node='Validator A', execution_loop_ns=100,
                                      execution_cpu_measured=1, execution_thread_cpu_ns=80, **fields))
            pruned = build([path], warmup=0, window={'backpressure': {'ts': 1_000_000_200, 'node': 'Validator A'}})
            self.assertTrue(all(not b['execution_totals'] for b in pruned['blocks']))

    def test_execution_cpu_totals_preserve_unmeasured_and_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            values = [
                dict(execution_loop_ns=70, execution_cpu_measured=1, execution_thread_cpu_ns=50),
                dict(execution_loop_ns=80, execution_cpu_measured=1, execution_thread_cpu_ns=0),
                dict(execution_loop_ns=90, execution_cpu_measured=0),
                {},  # Historical recording without CPU instrumentation.
            ]
            records[-1:-1] = [dict(type='event', id=i, ts=i*1_000_000_000+200,
                                  fields=dict(stage='execution_totals', execution_ns=40, **fields))
                              for i, fields in enumerate(values, 1)]
            path.write_text('\n'.join(map(json.dumps, records)))
            result = write_report([path], Path(directory)/'report', warmup=0)
            for block, fields in zip(result['blocks'], values):
                totals = block['execution_totals'][0]
                self.assertEqual(totals, dict(node='Validator A', execution_ns=40, **fields))
            # The same execution_totals event must be excluded at the strict cutoff.
            cutoff = 1_000_000_200
            pruned = build([path], warmup=0, window={'backpressure': {'ts': cutoff, 'node': 'Validator A'}})
            self.assertTrue(all(not b['execution_totals'] for b in pruned['blocks']))

    def test_milestone_detail_preserves_population_and_marks_unmeasured_polls(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            original = build([path], warmup=0, expected_detail='full')
            records = [json.loads(line) for line in path.read_text().splitlines()]
            records[0]['detail'] = 'milestones'
            path.write_text('\n'.join(map(json.dumps, records)))
            out = Path(directory)/'report'
            reduced = write_report([path], out, warmup=0, expected_detail='milestones')
            self.assertFalse(reduced['bad_capture'])
            self.assertEqual(reduced['blocks'], original['blocks'])
            self.assertEqual(reduced['attempt_details'], original['attempt_details'])
            self.assertEqual(reduced['representatives'], original['representatives'])
            self.assertTrue(all(s['active_ms'] is None for s in reduced['spans']))
            self.assertIn('Milestone-only capture', (out/'index.html').read_text())
            self.assertIn('not recorded in milestone-only capture', (out/'block-50.html').read_text())
            self.assertIn('not recorded in milestone-only capture', (out/'perfetto-p50.json').read_text())

    def test_wrong_unknown_or_mixed_detail_disables_percentiles(self):
        with tempfile.TemporaryDirectory() as directory:
            a = Path(directory)/'a.jsonl'; fixture(a)
            records = [json.loads(line) for line in a.read_text().splitlines()]
            # Legacy recorder headers are full, never silently accepted as milestones.
            self.assertTrue(build([a], expected_detail='milestones')['bad_capture'])
            self.assertFalse(build([a], expected_detail='full')['bad_capture'])
            for detail in ('unknown', 'milestones'):
                b = Path(directory)/'b.jsonl'
                b.write_text('\n'.join(map(json.dumps, [dict(records[0], detail=detail), *records[1:]])))
                result = build([a, b], warmup=0)
                self.assertTrue(result['bad_capture'])
                self.assertFalse(result['detail_valid'])
                self.assertTrue(all(v is None for v in result['representatives'].values()))
            records[0]['detail'] = 'unknown'
            a.write_text('\n'.join(map(json.dumps, records)))
            self.assertTrue(build([a])['bad_capture'])

    def test_explicit_completion_precedes_retained_child_close(self):
        records = [
            {'type':'header','schema':1},
            {'type':'start','id':1,'ts':0,'thread':1,'name':'handler','category':'consensus','parent':None,'fields':{}},
            {'type':'start','id':2,'ts':1,'thread':1,'name':'detached','category':'consensus','parent':1,'fields':{}},
            {'type':'enter','id':1,'ts':1,'thread':1},
            {'type':'exit','id':1,'ts':2,'thread':1},
            {'type':'event','id':1,'ts':10,'fields':{'stage':'operation_completed'}},
            {'type':'end','id':2,'ts':100},
            {'type':'end','id':1,'ts':101},
            {'type':'footer','dropped':0},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';path.write_text('\n'.join(map(json.dumps,records)))
            spans, _, quality = read_node(path, 'Validator A')
            self.assertEqual(spans[0]['end'],10)
            self.assertEqual(spans[0]['reference_end'],101)
            self.assertEqual(spans[1]['parent'],1)
            self.assertEqual(spans[1]['end'],100)
            spans, _, quality = read_node(path, 'Validator A', cutoff=50)
            self.assertEqual(spans[0]['end'],10)
            self.assertFalse(spans[0].get('right_censored',False))
            self.assertTrue(spans[1]['right_censored'])
            result=build([path],warmup=0,window={'backpressure':{'ts':50,'node':'Validator A'}})
            operation=next(s for s in result['spans'] if s['id']==1)
            self.assertEqual(operation['timing_semantics'],'operation_completed')
            self.assertFalse(operation['right_censored'])
            self.assertTrue(operation['reference_right_censored'])
            self.assertIsNone(operation['retained_after_operation_ms'])
            self.assertEqual(operation['reference_retention_lower_bound_ms'],40/1e6)
            # No completion is inferred from a pending future's last poll exit.
            spans, _, quality = read_node(path, 'Validator A', cutoff=10)
            self.assertTrue(spans[0]['right_censored'])
            self.assertNotIn('operation_status',spans[0])
            records[5]['fields']['stage']='operation_abandoned'
            path.write_text('\n'.join(map(json.dumps,records)))
            spans, _, _ = read_node(path, 'Validator A')
            self.assertEqual(spans[0]['operation_status'],'abandoned')
            self.assertEqual(spans[0]['end'],10)

    def test_percentiles_are_actual_blocks_with_late_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            result=build([path],warmup=0)
            self.assertEqual(result['representatives'],{'50':50,'90':90,'99':99})
            self.assertEqual(result['eligible'],100)
            self.assertEqual(result['unbound_attempts'],1)
            self.assertEqual(result['blocks'][49]['duration'],50)
            self.assertEqual(build([path],warmup=5)['eligible'],95)

    def test_payload_resource_late_binding_requires_unique_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl'
            h1='1'*24; h2='2'*24
            records=[{'type':'header','schema':1}]
            for ident, payload, block in [(1,'unique',h1),(2,'unique',None),
                                          (3,'ambiguous',h1),(4,'ambiguous',h2),
                                          (5,'ambiguous',None)]:
                records.append({'type':'start','id':ident,'ts':ident,'thread':1,
                    'name':'resource_worker','category':'trie','parent':None,
                    'fields':{'payload_id':payload, **({'block_hash':block} if block else {})}})
                records.append({'type':'end','id':ident,'ts':ident+1})
            records.append({'type':'footer','dropped':0,'io_error':False})
            path.write_text('\n'.join(map(json.dumps,records)))
            spans, _, _ = read_node(path, 'Validator A')
            by_id={span['id']:span for span in spans}
            self.assertEqual(by_id[2]['fields']['block_hash'],h1)
            self.assertNotIn('block_hash',by_id[5]['fields'])

    def test_loss_or_missing_footer_disables_percentiles(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl'
            for lost,close in [(1,True),(0,False)]:
                fixture(path,lost,close)
                result=build([path],warmup=0)
                self.assertTrue(result['bad_capture'])
                self.assertTrue(all(v is None for v in result['representatives'].values()))

    def test_unclosed_scopes_invalidate_capture_but_cutoff_censoring_does_not(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            records=[json.loads(line) for line in path.read_text().splitlines()]
            records.insert(-1,dict(type='start',id=102,ts=101_100_000_000,thread=1,
                name='storage_worker',category='trie',parent=None,fields={}))
            path.write_text('\n'.join(map(json.dumps,records)))
            result=build([path],warmup=0)
            self.assertEqual(result['quality'][0]['open_spans'],1)
            self.assertTrue(result['bad_capture'])
            self.assertTrue(all(v is None for v in result['representatives'].values()))
            cut=build([path],warmup=0,window={'backpressure':{'ts':101_200_000_000,'node':'Validator A'}})
            self.assertEqual(cut['quality'][0]['open_spans'],0)
            self.assertEqual(cut['quality'][0]['cutoff_spans'],1)
            self.assertFalse(cut['bad_capture'])
            self.assertEqual(cut['representatives'],{'50':50,'90':90,'99':99})

    def test_valid_load_window_exposes_post_window_tail_without_invalidating_population(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            records=[json.loads(line) for line in path.read_text().splitlines()]
            records.insert(-1,dict(type='start',id=102,ts=102_000_000_000,thread=1,
                name='storage_worker',category='trie',parent=None,fields={}))
            path.write_text('\n'.join(map(json.dumps,records)))
            window={'start_ns':1_000_000_000,'end_ns':101_050_000_000,'stop_reason':'load_finished'}
            result=build([path],warmup=0,window=window)
            self.assertEqual(result['quality'][0]['open_spans'],1)
            self.assertEqual(result['quality'][0]['post_window_open_spans'],1)
            self.assertFalse(result['bad_capture'])

    def test_open_span_before_window_or_invalid_window_remains_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            records=[json.loads(line) for line in path.read_text().splitlines()]
            records.insert(-1,dict(type='start',id=102,ts=50_000_000_000,thread=1,
                name='storage_worker',category='trie',parent=None,fields={}))
            path.write_text('\n'.join(map(json.dumps,records)))
            valid={'start_ns':1_000_000_000,'end_ns':101_050_000_000,'stop_reason':'load_finished'}
            result=build([path],warmup=0,window=valid)
            self.assertEqual(result['quality'][0]['post_window_open_spans'],0)
            self.assertTrue(result['bad_capture'])
            for invalid in [
                {'start_ns':101_050_000_000,'end_ns':1_000_000_000,'stop_reason':'load_finished'},
                {'start_ns':1_000_000_000,'end_ns':101_050_000_000,'stop_reason':'backpressure'},
                {'start_ns':1_000_000_000,'end_ns':101_050_000_000},
            ]:
                self.assertTrue(build([path],warmup=0,window=invalid)['bad_capture'])

    def test_exact_unbound_shutdown_payload_forest_is_reported_as_censored(self):
        latest = f'{100:024x}'
        window = {'start_ns':1_000_000_000, 'end_ns':103_000_000_000,
                  'stop_reason':'load_finished'}

        def terminal(path, mutation=None, footer=True):
            fixture(path)
            records = [json.loads(line) for line in path.read_text().splitlines()][:-1]
            tail = [
                dict(type='start', id=102, ts=102_000_000_000, thread=1,
                     name='handle_propose', category='consensus', parent=None,
                     fields={'parent_digest':latest}),
                dict(type='event', id=102, ts=102_000_000_001,
                     fields={'stage':'proposal_start'}),
                dict(type='start', id=103, ts=102_000_000_010, thread=2,
                     name='payload_resources', category='builder', parent=None,
                     fields={'payload_id':'a'*24}),
                dict(type='start', id=104, ts=102_000_000_020, thread=3,
                     name='build_payload', category='builder', parent=None,
                     fields={'payload_id':'a'*24, 'parent_hash':latest}),
                dict(type='start', id=105, ts=102_000_000_030, thread=4,
                     name='storage_worker', category='trie', parent=103, fields={}),
                dict(type='start', id=106, ts=102_000_000_040, thread=5,
                     name='account_worker', category='trie', parent=103, fields={}),
                dict(type='start', id=107, ts=102_000_000_050, thread=6,
                     name='sparse_trie_task', category='trie', parent=103, fields={}),
            ]
            if mutation:
                mutation(tail)
            records.extend(tail)
            if footer:
                records.append({'type':'footer','dropped':0,'io_error':False})
            path.write_text('\n'.join(map(json.dumps, records)))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'
            terminal(path)
            result = build([path], warmup=0, window=window)
            self.assertEqual(result['quality'][0]['open_spans'], 6)
            self.assertEqual(result['quality'][0]['post_window_open_spans'], 0)
            self.assertEqual(result['quality'][0]['shutdown_tail_open_spans'], 6)
            self.assertFalse(result['bad_capture'])
            self.assertEqual(result['attempt_details'][-1]['status'], 'shutdown_incomplete')

            mutations = {
                'wrong payload': lambda rows: rows[3]['fields'].__setitem__('payload_id', 'b'*24),
                'wrong parent': lambda rows: rows[3]['fields'].__setitem__('parent_hash', 'b'*24),
                'bound worker': lambda rows: rows[4]['fields'].__setitem__('block_hash', latest),
                'unknown span': lambda rows: rows[4].__setitem__('name', 'unknown_worker'),
            }
            for name, mutation in mutations.items():
                with self.subTest(name=name):
                    terminal(path, mutation)
                    rejected = build([path], warmup=0, window=window)
                    self.assertEqual(rejected['quality'][0]['shutdown_tail_open_spans'], 0)
                    self.assertTrue(rejected['bad_capture'])
            terminal(path, footer=False)
            rejected = build([path], warmup=0, window=window)
            self.assertEqual(rejected['quality'][0]['shutdown_tail_open_spans'], 0)
            self.assertTrue(rejected['bad_capture'])

    def test_unexplained_attempt_fails_cli_after_publishing_diagnostics(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            records=[json.loads(line) for line in path.read_text().splitlines()]
            records[-1:-1]=[
                dict(type='start',id=102,ts=102_000_000_000,thread=1,
                     name='handle_propose',category='consensus',parent=None,fields={}),
                dict(type='end',id=102,ts=102_000_000_100)]
            path.write_text('\n'.join(map(json.dumps,records)))
            out=Path(directory)/'report'
            run=subprocess.run([sys.executable,str(Path(__file__).with_name('report.py')),
                '--out',str(out),'--warmup','0',str(path)],capture_output=True,text=True)
            self.assertEqual(run.returncode,2,run.stderr)
            data=json.loads((out/'lifecycle.json').read_text())
            self.assertEqual(data['unexplained_attempts'],1)
            self.assertTrue(data['bad_capture'])
            self.assertTrue(all(v is None for v in data['representatives'].values()))
            self.assertTrue((out/'index.html').is_file())
            self.assertTrue((out/'block-1.html').is_file())

    def test_portable_exports_have_only_run_local_block_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            out=Path(directory)/'report';write_report([path],out,0)
            for name in ('index.html','lifecycle.json','context-0001.json','block-50.html'):
                text=(out/name).read_text()
                self.assertNotIn('000000000000000000000064',text)
                self.assertNotIn(str(directory),text)
            self.assertNotIn('__LIFECYCLE_DATA__',(out/'index.html').read_text())
            for event in json.loads((out/'context-0001.json').read_text())['traceEvents']:
                self.assertIsInstance(event['pid'],int)
                self.assertIsInstance(event['tid'],int)

    def test_load_window_requires_both_endpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            result=build([path],warmup=0,window={'start_ns':50_000_000_000,'end_ns':90_050_000_000})
            self.assertEqual(result['eligible'],40)
            self.assertTrue(result['blocks'][49]['in_population'])
            self.assertFalse(result['blocks'][89]['in_population'])

    def test_cross_validator_finalization_and_frame_matching(self):
        with tempfile.TemporaryDirectory() as directory:
            a=Path(directory)/'a.jsonl';fixture(a)
            records=[json.loads(line) for line in a.read_text().splitlines()]
            remote=[e for e in records if e.get('fields',{}).get('stage')=='finalized']
            records=[e for e in records if e not in remote]
            frame='abcdef0123456789abcdef01'
            records.insert(-1,{'type':'event','id':0,'ts':500,'fields':{'stage':'frame_send','frame_hash':frame,'bytes':100}})
            a.write_text('\n'.join(map(json.dumps,records)))
            b=Path(directory)/'b.jsonl'
            b.write_text('\n'.join(map(json.dumps,[{'type':'header','schema':1},*remote,
                {'type':'event','id':0,'ts':600,'fields':{'stage':'frame_receive','frame_hash':frame}},
                {'type':'footer','dropped':0,'io_error':False}])))
            result=build([a,b],warmup=0)
            self.assertEqual(result['eligible'],100)
            self.assertEqual(len(result['transfers']),1)
            self.assertEqual(result['transfers'][0]['from'],'Validator A')
            self.assertEqual(result['transfers'][0]['to'],'Validator B')
            self.assertNotIn(frame,json.dumps(result))

    def test_overlapping_entries_are_wall_time_not_cpu_sum(self):
        self.assertEqual(active_wall_ns([(100,200,1),(150,220,2),(110,120,1)]),120)

    def test_aggregates_inherit_block_without_expanding_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            records=[json.loads(line) for line in path.read_text().splitlines()]
            records.insert(-1,{'type':'aggregate','id':50,'ts':50_000_000_001,'end':50_001_000_001,
                'name':'database_provider_ro','category':'state','count':100_000,'elapsed_ns':500_000})
            path.write_text('\n'.join(map(json.dumps,records)))
            result=build([path],warmup=0)
            rows=[s for s in result['spans'] if s['count']]
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['block'],50)
            self.assertEqual(rows[0]['count'],100_000)
            self.assertEqual(rows[0]['elapsed_sum_ms'],0.5)
            self.assertEqual(result['representatives']['50'],50)

    def test_empty_sample(self):
        self.assertIsNone(nearest_rank([],99))



class AttributionTests(unittest.TestCase):
    def test_attempt_outcomes_and_detached_payload_without_block(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'
            records = [{'type':'header','schema':1}]
            def start(i, name='handle_propose', parent=None, fields=None):
                return dict(type='start', id=i, ts=i*100, thread=1, name=name,
                            category='consensus', parent=parent, fields=fields or {})
            records += [start(i) for i in range(1, 6)]
            records += [dict(type='event',id=i,ts=600+i,fields={'stage':stage})
                        for i,stage in [(1,'cancelled'),(2,'proposal_failed')]]
            records += [dict(type='end',id=i,ts=700+i) for i in (1,2,3)]
            records += [start(6,'job',1,{'payload_id':'0123456789abcdef01234567'}),
                        start(7,'builder',None,{'payload_id':'0123456789abcdef01234567'}),
                        start(8,'builder.child',7),
                        dict(type='footer',dropped=0,io_error=False)]
            path.write_text('\n'.join(map(json.dumps,records)))
            result = build([path],0,{'backpressure':{'ts':1000,'node':'Validator A'}})
            self.assertEqual([a['status'] for a in result['attempt_details']],
                             ['cancelled','failed','unexplained_unassociated','cutoff_incomplete','cutoff_incomplete'])
            child = next(s for s in result['spans'] if s['id']==8)
            self.assertEqual(child['attempt'],1)
            self.assertIsNone(child['block'])
            self.assertEqual(result['eligible'],0)
            result = build([path],0)
            self.assertEqual(result['attempt_details'][-1]['status'],'shutdown_incomplete')

    def test_queue_pairs_and_numeric_metadata_stop_at_cutoff(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'
            records = [dict(type='header',schema=1),
                dict(type='start',id=1,ts=0,thread=1,name='handle_propose',category='consensus',parent=None,fields={}),
                dict(type='start',id=2,ts=100,thread=1,name='mailbox',category='consensus',parent=1,fields={'block_count':4,'secret':'PRIVATE'}),
                dict(type='event',id=2,ts=200,fields={'stage':'marshal_enqueued'}),
                dict(type='event',id=2,ts=500,fields={'stage':'marshal_dequeued'}),
                dict(type='end',id=2,ts=600),
                dict(type='start',id=3,ts=700,thread=1,name='mailbox',category='consensus',parent=1,fields={}),
                dict(type='event',id=3,ts=800,fields={'stage':'marshal_enqueued'}),
                dict(type='event',id=3,ts=1000,fields={'stage':'marshal_dequeued'}),
                dict(type='footer',dropped=0,io_error=False)]
            path.write_text('\n'.join(map(json.dumps,records)))
            result = build([path],0,{'backpressure':{'ts':1000,'node':'Validator A'}})
            waits = [s for s in result['spans'] if s['name']=='marshal.queue_wait']
            self.assertEqual(len(waits),2)
            self.assertAlmostEqual(waits[0]['end']-waits[0]['start'],300/1e6)
            self.assertFalse(waits[0]['right_censored'])
            self.assertTrue(waits[1]['right_censored'])
            self.assertEqual(waits[1]['end'],1000/1e6)
            self.assertEqual(waits[1]['attempt'],1)
            self.assertEqual(next(s for s in result['spans'] if s['id']==2)['details'],{'block_count':4})
            self.assertNotIn('PRIVATE',json.dumps(result))


if __name__ == '__main__':
    unittest.main()
