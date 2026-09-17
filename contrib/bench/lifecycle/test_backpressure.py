import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from backpressure import CaptureTail, first_boundary, run
from report import build, write_report
from test_report import fixture


def marker(ts):
    return {'type': 'event', 'id': 0, 'ts': ts, 'fields': {'stage': 'backpressure_start'}}


class BackpressureTests(unittest.TestCase):
    def test_milestone_capture_prunes_boundary_and_preserves_declared_detail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'a.jsonl'; fixture(path)
            records = [json.loads(line) for line in path.read_text().splitlines()]
            records[0]['detail'] = 'milestones'
            cutoff = 50_025_000_000
            records.insert(-1, marker(cutoff))
            path.write_text('\n'.join(map(json.dumps, records)))
            out = Path(directory)/'out'
            result = write_report([path], out, 0, prune=True, expected_detail='milestones')
            self.assertFalse(result['bad_capture'])
            self.assertEqual(result['eligible'], 49)
            self.assertEqual(result['capture_detail'], 'milestones')
            self.assertEqual(result['quality'][0]['cutoff_spans'], 1)
            for capture in out.glob('*.jsonl'):
                kept = [json.loads(line) for line in capture.read_text().splitlines()]
                self.assertEqual(kept[0]['detail'], 'milestones')
                self.assertTrue(all(e['ts'] < cutoff for e in kept if e['type'] not in ('header', 'footer')))
            rebuilt = build(list(out.glob('*.jsonl')), 0,
                            json.loads((out/'window.json').read_text()), expected_detail='milestones')
            self.assertEqual(rebuilt['blocks'], result['blocks'])
            self.assertFalse(rebuilt['bad_capture'])

    def test_partial_record_and_earliest_source_time_across_validators(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory)/'a.jsonl', Path(directory)/'b.jsonl'
            encoded = json.dumps(marker(200)).encode() + b'\n'
            a.write_bytes(encoded[:20])
            tail = CaptureTail(a, 'Validator A')
            self.assertIsNone(tail.poll())
            with a.open('ab') as out:
                out.write(encoded[20:])
            self.assertEqual(tail.poll()['ts'], 200)
            b.write_text(json.dumps(marker(100)))
            self.assertEqual(first_boundary([a,b]), {'ts':100, 'node':'Validator B'})

    def test_cutoff_filters_markers_fields_frames_totals_and_aggregate_envelopes(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory)/'a.jsonl', Path(directory)/'b.jsonl'
            fixture(a)
            cutoff = 50_025_000_000
            records = [json.loads(line) for line in a.read_text().splitlines()]
            # Learn this attempt's identity only after cutoff: it must remain unbound.
            for event in records:
                if event.get('id') == 50 and event.get('fields',{}).get('stage') == 'proposal_ready':
                    event['ts'] = cutoff + 10
            token = f'{49:024x}'
            records.extend([
                marker(cutoff + 100),
                {'type':'aggregate','id':49,'ts':49_000_000_000,'end':49_010_000_000,
                 'name':'safe_aggregate','category':'state','count':10,'elapsed_ns':100},
                {'type':'aggregate','id':49,'ts':49_000_000_000,'end':cutoff,
                 'name':'crossing_aggregate','category':'state','count':999,'elapsed_ns':999},
                {'type':'event','id':49,'ts':cutoff,'fields':{'stage':'execution_totals','block_hash':token,'execution_ns':999}},
                {'type':'event','id':49,'ts':cutoff-10,'fields':{'stage':'frame_send','frame_hash':token}},
                {'type':'event','id':49,'ts':cutoff+10,'fields':{'stage':'frame_receive','frame_hash':token}},
                {'type':'enter','id':50,'ts':cutoff-100,'thread':1},
                {'type':'exit','id':50,'ts':cutoff+100,'thread':1},
            ])
            a.write_text('\n'.join(map(json.dumps,records))+'\n')
            b.write_text('\n'.join(map(json.dumps,[{'type':'header','schema':1},marker(cutoff),{'type':'footer','dropped':0}]))+'\n')
            out=Path(directory)/'report'
            result=write_report([a,b],out,0, {'load_stopped_ns':cutoff+1}, prune=True)
            self.assertNotIn('load_stopped_ns',(out/'window.json').read_text())
            self.assertTrue(a.exists())
            for clean in out.glob('*.jsonl'):
                for line in clean.read_text().splitlines():
                    event=json.loads(line)
                    if event['type'] not in ('header','footer'):
                        self.assertLess(event['ts'],cutoff)
                        if 'end' in event:self.assertLess(event['end'],cutoff)
            self.assertIsNone(first_boundary(list(out.glob('*.jsonl'))))
            self.assertFalse(result['bad_capture'])
            self.assertEqual(result['eligible'],49)
            self.assertEqual(result['representatives'], {'50':25,'90':45,'99':49})
            self.assertEqual(result['boundary']['node'],'Validator B')
            self.assertEqual(result['quality'][0]['crossing_aggregates_excluded'],1)
            self.assertEqual(result['quality'][0]['cutoff_spans'],1)
            self.assertEqual(result['transfers'],[])
            self.assertTrue(all(not block['execution_totals'] for block in result['blocks']))
            limit=result['boundary']['relative_ms']
            self.assertTrue(all(s['end']<=limit for s in result['spans']))
            self.assertTrue(all(m['ts']<limit for b in result['blocks'] for m in b['markers']))
            crossing=next(s for s in result['spans'] if s['id']==50)
            self.assertTrue(crossing['right_censored'])
            self.assertIsNone(crossing['block'])
            self.assertAlmostEqual(crossing['active_ms'],0.0001)
            self.assertNotIn('crossing_aggregate',result['coverage'])
            self.assertIn('safe_aggregate',json.dumps(result))
            for path in out.glob('perfetto*.json'):
                for event in json.loads(path.read_text())['traceEvents']:
                    if 'ts' in event:
                        self.assertLessEqual(event['ts']+event.get('dur',0),limit*1000+0.001)

    def test_backpressure_before_load_has_no_percentile_population(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            result=build([path],0,{'start_ns':60_000_000_000,'end_ns':80_000_000_000,
                                  'backpressure':{'ts':50_025_000_000,'node':'Validator A'}})
            self.assertEqual(result['eligible'],0)
            self.assertTrue(all(v is None for v in result['representatives'].values()))

    def test_pruning_keeps_capture_integrity_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path,lost=3)
            with path.open('a') as out:out.write('\nnot json\n')
            result=write_report([path],Path(directory)/'out',0,prune=True)
            self.assertTrue(result['bad_capture'])
            self.assertEqual(result['quality'][0]['dropped'],3)
            self.assertEqual(result['quality'][0]['invalid_lines'],1)

    def test_live_boundary_stops_load_and_keeps_raw_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path, window = Path(directory)/'a.jsonl', Path(directory)/'window.json'
            epoch = time.monotonic_ns()
            # The load emits a boundary and would otherwise run for a minute.
            code = '''import json,signal,sys,time
from pathlib import Path
signal.signal(signal.SIGINT,lambda *_:sys.exit(0))
p=Path(sys.argv[1]);ts=time.monotonic_ns()-int(sys.argv[2])
p.write_text(json.dumps({'type':'event','id':0,'ts':ts,'fields':{'stage':'backpressure_start'}})+'\\n')
time.sleep(60)
'''
            start=time.monotonic()
            self.assertEqual(run([sys.executable,'-c',code,str(path),str(epoch)],[path],window,epoch),0)
            self.assertLess(time.monotonic()-start,3)
            data=json.loads(window.read_text())
            self.assertEqual(data['stop_reason'],'backpressure')
            self.assertEqual(data['end_ns'],first_boundary([path])['ts'])
            self.assertGreaterEqual(data['load_stopped_ns'],data['end_ns'])
            self.assertTrue(path.exists())

    def test_natural_failure_is_not_hidden_and_existing_boundary_skips_load(self):
        with tempfile.TemporaryDirectory() as directory:
            path, window = Path(directory)/'a.jsonl', Path(directory)/'window.json'
            epoch=time.monotonic_ns()
            self.assertEqual(run([sys.executable,'-c','raise SystemExit(7)'],[path],window,epoch),7)
            self.assertEqual(json.loads(window.read_text())['stop_reason'],'load_finished')
            path.write_text(json.dumps(marker(1))+'\n')
            self.assertEqual(run(['/does/not/exist'],[path],window,epoch),0)
            self.assertEqual(json.loads(window.read_text())['end_ns'],1)


if __name__ == '__main__':
    unittest.main()
