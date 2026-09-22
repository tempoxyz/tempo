import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from read_readiness import build
import report

def event(stage, ts=100, block='a', ident=1, **fields):
    return {'type':'event','ts':ts,'id':ident,'node':'Validator A','block':block,'fields':{'stage':stage,**fields}}

class ReadinessTests(unittest.TestCase):
    def test_progress_totals_round_trip_privacy_association_and_cutoff(self):
        from read_readiness import PROGRESS_FIELDS
        numeric = {name: 1 for name in PROGRESS_FIELDS}
        numeric['phase'] = 4
        numeric['cpu_missing_calls'] = 0
        events = [
            event('proof_progress_totals', ts=90, **numeric,
                  address='private', target_hash='private', private_counter=999),
            event('proof_progress_totals', ts=95, phase=9, calls=1),
            event('proof_progress_totals', ts=100, **numeric),
            event('proof_progress_totals', ts=110, **numeric),
        ]
        result = build(events, [{'read_readiness':'v1'}], {'a':7}, 0, cutoff=100)
        self.assertEqual(len(result['events']), 1)
        self.assertEqual(result['events'][0]['stage'], 'proof_progress_totals')
        self.assertEqual(result['events'][0]['block'], 7)
        self.assertEqual(result['events'][0]['fields'], numeric)

    def test_overlap_root_tail_and_grouping_fields_are_numeric_and_pruned(self):
        from read_readiness import CACHE_FIELDS, ROOT_FIELDS, PROOF_FIELDS
        for stage, fields in [('execution_cache_readiness', CACHE_FIELDS),
                              ('proof_root_tail_totals', ROOT_FIELDS),
                              ('proof_dispatch_totals', PROOF_FIELDS)]:
            numeric = {name: 1 for name in fields}
            events = [event(stage, ts=90, **numeric, key='private', address='private'),
                      event(stage, ts=100, **numeric),
                      event(stage, ts=110, **numeric),
                      event(stage, ts=95, **{name: 'private' for name in fields})]
            result = build(events, [{'read_readiness':'v1'}], {'a':1}, 0, cutoff=100)
            self.assertEqual(len(result['events']), 2)
            self.assertEqual(result['events'][0]['fields'], numeric)
            self.assertEqual(result['events'][0]['block'], 1)
            self.assertEqual(result['events'][1]['fields'], {})

    def test_queue_and_backing_latency_numeric_fields_and_cutoff(self):
        events = [event('execution_cache_readiness', ts=90,
                        storage_backing_inflight_count=2, storage_backing_inflight_ns=300,
                        prewarm_queue_delay_ns=400, prewarm_start_ahead_gt_64=5,
                        storage_backing_failed_ns='private', key='private'),
                  event('proof_state_at_updates_finished', ts=95,
                        in_flight=7, storage_queue_depth=3, result_queue_depth=1,
                        pending_storage_targets=5, account_queue_depth=True, address='private'),
                  event('proof_state_at_updates_finished', ts=100, in_flight=999)]
        result = build(events, [{'read_readiness':'v1'}], {'a':1}, 0, cutoff=100)
        self.assertEqual(len(result['events']), 2)
        self.assertEqual(result['events'][0]['fields'], {
            'storage_backing_inflight_count':2, 'storage_backing_inflight_ns':300,
            'prewarm_queue_delay_ns':400, 'prewarm_start_ahead_gt_64':5})
        self.assertEqual(result['events'][1]['fields'], {
            'in_flight':7, 'storage_queue_depth':3, 'result_queue_depth':1,
            'pending_storage_targets':5})

    def test_actual_emit_schema_is_numeric_and_associated(self):
        result = build([event('read_totals',read_role=4,read_class=7,read_calls=3,read_ns=9,read_max_ns=4,read_lt_10us=1,secret=9),event('read_sample',read_role=4,read_class=7,read_begin_ns=10,read_end_ns=20,read_thread=2,ts=20,filename='drop'),event('execution_cache_readiness',cache_checkout_reason=2,cache_diag_keys_tracked=3,account_miss_prewarm_unknown_contention=1),event('proof_dispatch_totals',dispatches=2,targets=3,reason_force=1,split_when_queue_nonempty=1),event('read_totals',ts=110,block=None,read_role=4,read_class=7,read_calls=0)], [{'read_readiness':'v1'}], {'a':7}, 0)
        self.assertTrue(result['mode_valid']); self.assertEqual(result['events'][0]['block'],7); self.assertNotIn('secret',result['events'][0]['fields']); self.assertEqual(result['unattributed'][0]['fields'],{'read_role':4,'read_class':7,'read_calls':0})

    def test_sample_end_and_scope_cap(self):
        events=[event('read_sample',ident=77,ts=100,read_role=1,read_class=2,read_begin_ns=10+i,read_end_ns=20+i,read_thread=3) for i in range(9)]
        events += [event('read_sample',ident=77,ts=100,read_role=2,read_class=2,read_begin_ns=10,read_end_ns=20,read_thread=3),event('read_sample',ident=77,ts=200,read_role=1,read_class=2,read_begin_ns=10,read_end_ns=201,read_thread=3)]
        result=build(events,[{'read_readiness':'v1'}],{'a':1},0,cutoff=200)
        self.assertEqual(result['read_samples_retained'],9); self.assertEqual(result['read_samples_omitted'],0); self.assertEqual(result['report_dropped_samples'],1)

    def test_header_modes(self):
        self.assertEqual(build([],[{'read_readiness':'v1'},{'read_readiness':'disabled'}],{},0)['mode'],'mixed')
        result=build([],[{'read_readiness':'future'}],{},0); self.assertEqual(result['mode'],'invalid'); self.assertFalse(result['mode_valid'])

    def test_unattributed_samples_share_the_same_cap(self):
        events = [event('read_sample', block=None, ident=9, ts=100, read_role=1,
                        read_class=0, read_begin_ns=1, read_end_ns=2,
                        read_thread=1) for _ in range(9)]
        result = build(events, [{'read_readiness':'v1'}], {}, 0)
        self.assertEqual(result['read_samples_retained'], 8)
        self.assertEqual(result['report_dropped_samples'], 1)
        self.assertEqual(len(result['unattributed']), 8)

    def test_coverage_mode_and_failed_cache_counters_are_whitelisted(self):
        result = build([event('read_coverage', read_execution_mode=1, secret=9),
                        event('execution_cache_readiness', account_miss_prewarm_failed=1,
                              storage_miss_prewarm_failed=2, code_miss_prewarm_failed=3)],
                       [{'read_readiness':'v1'}], {'a':1}, 0)
        self.assertEqual(result['events'][0]['fields'], {'read_execution_mode':1})
        self.assertEqual(result['events'][1]['fields']['account_miss_prewarm_failed'], 1)
        self.assertNotIn('secret', result['events'][0]['fields'])

    def test_pruned_report_strictly_excludes_cutoff_readiness_and_private_fields(self):
        cutoff = 100
        block = 'a' * 24
        records = [
            {'type':'header', 'schema':1, 'detail':'milestones', 'read_readiness':'v1'},
            {'type':'event', 'id':1, 'ts':90, 'fields':{
                'stage':'read_sample', 'block_hash':block, 'read_role':1,
                'read_class':2, 'read_begin_ns':70, 'read_end_ns':80,
                'read_thread':3, 'secret':'private-before'}},
            {'type':'event', 'id':1, 'ts':95, 'fields':{
                'stage':'execution_cache_readiness', 'block_hash':block,
                'cache_checkout_reason':2}},
            {'type':'event', 'id':1, 'ts':92, 'fields':{
                'stage':'proof_progress_totals', 'block_hash':block, 'phase':4,
                'wall_ns':10, 'cpu_measured_wall_ns':9, 'caller_cpu_ns':8,
                'cpu_measured_calls':1, 'cpu_missing_calls':0, 'calls':1,
                'failures':0, 'work_items':2, 'work_outputs':1,
                'work_items_max':2, 'minor_faults':0, 'major_faults':0,
                'voluntary_context_switches':0, 'involuntary_context_switches':0,
                'secret':'private-progress-before'}},
            {'type':'event', 'id':1, 'ts':cutoff, 'fields':{
                'stage':'proof_progress_totals', 'block_hash':block, 'phase':4,
                'calls':999, 'secret':'private-progress-at-cutoff'}},
            {'type':'event', 'id':1, 'ts':cutoff + 10, 'fields':{
                'stage':'proof_progress_totals', 'block_hash':block, 'phase':4,
                'calls':999, 'secret':'private-progress-after-cutoff'}},
            {'type':'event', 'id':1, 'ts':cutoff, 'fields':{
                'stage':'read_sample', 'block_hash':block, 'read_role':1,
                'read_class':2, 'read_begin_ns':80, 'read_end_ns':90,
                'read_thread':3, 'secret':'private-at-cutoff'}},
            {'type':'event', 'id':1, 'ts':cutoff + 10, 'fields':{
                'stage':'read_sample', 'block_hash':block, 'read_role':1,
                'read_class':2, 'read_begin_ns':90, 'read_end_ns':100,
                'read_thread':3, 'secret':'private-after-cutoff'}},
            {'type':'event', 'id':0, 'ts':cutoff,
             'fields':{'stage':'backpressure_start'}},
            {'type':'footer', 'written':5, 'dropped':0, 'io_error':False},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'source'/'published.jsonl'
            source.parent.mkdir()
            source.write_text('\n'.join(json.dumps(record) for record in records) + '\n')
            out = root/'report'

            result = report.write_report([source], out, warmup=0, prune=True)

            published = (out/'published.jsonl').read_text()
            derived = (out/'lifecycle.json').read_text()
            published_records = [json.loads(line) for line in published.splitlines()]
            self.assertEqual(published_records[0]['read_readiness'], 'v1')
            self.assertTrue(all(record['ts'] < cutoff for record in published_records
                                if record['type'] not in ('header', 'footer')))
            self.assertNotIn('private-at-cutoff', published)
            self.assertNotIn('private-after-cutoff', published)
            self.assertNotIn('private-at-cutoff', derived)
            self.assertNotIn('private-after-cutoff', derived)
            self.assertNotIn('private-before', derived)
            self.assertNotIn('private-progress-before', derived)
            self.assertNotIn('private-progress-at-cutoff', published)
            self.assertNotIn('private-progress-after-cutoff', published)
            self.assertNotIn('private-progress-at-cutoff', derived)
            self.assertNotIn('private-progress-after-cutoff', derived)
            self.assertEqual(result['read_readiness']['mode'], 'v1')
            self.assertEqual(result['read_readiness']['read_samples_retained'], 1)
            self.assertEqual([event['ts_ns'] for event in result['read_readiness']['events']],
                             [90, 95, 92])

if __name__ == '__main__': unittest.main()
