import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from read_readiness import build

def event(stage, ts=100, block='a', ident=1, **fields):
    return {'type':'event','ts':ts,'id':ident,'node':'Validator A','block':block,'fields':{'stage':stage,**fields}}

class ReadinessTests(unittest.TestCase):
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

if __name__ == '__main__': unittest.main()
