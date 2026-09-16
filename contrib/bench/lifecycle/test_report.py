import json
from pathlib import Path
import tempfile
import unittest
from report import build, nearest_rank, write_report, active_wall_ns


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
    def test_percentiles_are_actual_blocks_with_late_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            result=build([path],warmup=0)
            self.assertEqual(result['representatives'],{'50':50,'90':90,'99':99})
            self.assertEqual(result['eligible'],100)
            self.assertEqual(result['unbound_attempts'],1)
            self.assertEqual(result['blocks'][49]['duration'],50)
            self.assertEqual(build([path],warmup=5)['eligible'],95)

    def test_loss_or_missing_footer_disables_percentiles(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl'
            for lost,close in [(1,True),(0,False)]:
                fixture(path,lost,close)
                result=build([path],warmup=0)
                self.assertTrue(result['bad_capture'])
                self.assertTrue(all(v is None for v in result['representatives'].values()))

    def test_portable_exports_have_only_run_local_block_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path)
            out=Path(directory)/'report';write_report([path],out,0)
            for name in ('index.html','lifecycle.json','perfetto.json'):
                text=(out/name).read_text()
                self.assertNotIn('000000000000000000000064',text)
                self.assertNotIn(str(directory),text)
            self.assertNotIn('__LIFECYCLE_DATA__',(out/'index.html').read_text())

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

if __name__=='__main__':unittest.main()
