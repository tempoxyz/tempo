import copy
from collections import defaultdict
from pathlib import Path
import tempfile
import unittest
from perfetto import trace_events, write_exports


def sample(intervals):
    return {'quality': [{'node': 'Validator A'}, {'node': 'Validator B'}], 'bad_capture': False,
            'representatives': {'50': 1, '90': 1, '99': 1}, 'transfers': [],
            'blocks': [{'id': 1, 'start': 0, 'end': 100, 'markers': [
                {'node': 'Validator A', 'stage': 'proposal_start', 'ts': 0},
                {'node': 'Validator B', 'stage': 'finalized', 'ts': 100}]}],
            'spans': [{'id': i+1, 'node': 'Validator A', 'category': 'execution', 'parent': None,
                       'name': f'operation {i}', 'block': 1, 'start': a, 'end': b, 'thread': i+20,
                       'active_ms': 0, 'count': None, 'elapsed_sum_ms': 0}
                      for i, (a,b) in enumerate(intervals)]}


class PerfettoTests(unittest.TestCase):
    def test_sequential_async_spans_reuse_lane_regardless_of_source_thread(self):
        data = sample([(i, i+1) for i in range(10000)])
        events = trace_events(data)
        slices = [e for e in events if e['ph'] == 'X']
        self.assertEqual(len(slices), 10000)
        self.assertEqual(len({(e['pid'], e['tid']) for e in slices}), 1)
        self.assertEqual(len({e['args']['source_thread_ordinal'] for e in slices}), 10000)

    def test_crossing_nested_equal_and_zero_intervals_are_preserved_without_overlap(self):
        data = sample([(0,10),(1,5),(2,12),(5,7),(10,10),(10,11),(10,11),(12,13)])
        events = trace_events(data)
        slices = [e for e in events if e['ph'] == 'X']
        self.assertCountEqual([(e['name'], e['ts'], e['dur']) for e in slices],
                         [(s['name'], s['start']*1000, (s['end']-s['start'])*1000) for s in data['spans']])
        lanes = defaultdict(list)
        for e in slices:
            lanes[(e['pid'], e['tid'])].append(e)
        self.assertLessEqual(len(lanes), 4)
        for events in lanes.values():
            for a,b in zip(events, events[1:]):
                self.assertLessEqual(a['ts']+a['dur'], b['ts'])
        # Metadata declares virtual wall-time lanes; these are not real OS threads.
        self.assertTrue(any('(virtual)' in e['args']['name'] for e in trace_events(data) if e['ph']=='M'))

    def test_aggregate_envelopes_are_separate_from_operation_lanes(self):
        data = sample([(0,10),(0,10)])
        data['spans'][1].update(count=100, elapsed_sum_ms=25)
        slices = [e for e in trace_events(data) if e['ph'] == 'X']
        self.assertNotEqual(slices[0]['tid'], slices[1]['tid'])
        aggregate = next(e for e in slices if e['args'].get('call_count'))
        self.assertEqual(aggregate['args']['elapsed_sum_ms'], 25)
        self.assertNotIn('active_wall_ms', aggregate['args'])
        self.assertIn('not continuous work', aggregate['args']['semantics'])

    def test_focus_keeps_only_selected_block_and_explicit_frame_context(self):
        data = sample([(0,10),(10,20)])
        data['spans'][1]['block'] = 2
        data['transfers'] = [dict(start=3,end=4,bytes=20,**{'from':'Validator A','to':'Validator B'}),
                             dict(start=101,end=102,bytes=10,**{'from':'Validator B','to':'Validator A'})]
        events = trace_events(data,1)
        slices = [e for e in events if e['ph']=='X']
        self.assertEqual(len(slices),2)
        self.assertEqual({e['args'].get('block') for e in slices},{1,None})
        self.assertTrue(any('no block attribution' in e['args']['semantics'] for e in slices))
        self.assertEqual({e['pid'] for e in events if e['ph']=='i'},{1,2})
        with self.assertRaisesRegex(ValueError,'not in this capture'):
            trace_events(data,999)

    def test_invalid_capture_removes_stale_percentile_exports(self):
        data = sample([(0,1)])
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            write_exports(data,out)
            self.assertTrue((out/'perfetto-p99.json').exists())
            invalid = copy.deepcopy(data);invalid['bad_capture'] = True
            write_exports(invalid,out)
            self.assertTrue((out/'perfetto.json').exists())
            self.assertFalse((out/'perfetto-p99.json').exists())
            write_exports(data,out,1)
            self.assertTrue((out/'perfetto-block-1.json').exists())


if __name__ == '__main__':
    unittest.main()
