"""Attempt-index regression against the original independent linear scan."""
import json
from pathlib import Path
import tempfile
import unittest
from backpressure import first_boundary
from report import STAGES, build, read_node


def legacy_attempts(paths, window=None):
    # Frozen original algorithm; intentionally do not share the indexed lookup.
    boundary = first_boundary(paths)
    recorded = (window or {}).get('backpressure')
    if recorded and (boundary is None or recorded['ts'] < boundary['ts']):boundary=recorded
    cutoff = boundary['ts'] if boundary else None
    spans, events = [], []
    for i, path in enumerate(paths):
        ss, es, _ = read_node(path, f'Validator {chr(65+i)}', cutoff)
        spans.extend(ss); events.extend(es)
    first=min((x['ts'] for x in spans+events), default=0)
    by_block={}
    for event in events:
        if event.get('block'):by_block.setdefault(event['block'],[]).append(event)
    keys=sorted(by_block,key=lambda key:min(e['ts'] for e in by_block[key]))
    aliases={key:i+1 for i,key in enumerate(keys)}
    attempts=sorted((s for s in spans if s['name']=='handle_propose'),key=lambda s:(s['ts'],s['node'],s['id']))
    result=[]
    for ordinal,attempt in enumerate(attempts,1):
        markers=[dict(stage=e['fields']['stage'],ts=(e['ts']-first)/1e6,node=e['node'])
                 for e in events if e['node']==attempt['node'] and e['id']==attempt['id'] and e['fields'].get('stage') in STAGES]
        stages={e['stage'] for e in markers}
        status=('cancelled' if 'cancelled' in stages else 'failed' if 'proposal_failed' in stages else
                'cutoff_incomplete' if attempt.get('right_censored') else 'shutdown_incomplete' if attempt['end'] is None else
                'associated' if attempt.get('block') else 'unexplained_unassociated')
        start=(attempt['ts']-first)/1e6
        end=(attempt['end']-first)/1e6 if attempt['end'] is not None else max([start,*(m['ts'] for m in markers)])
        result.append(dict(id=ordinal,node=attempt['node'],block=aliases.get(attempt.get('block')),status=status,
                           start=start,end=end,duration=end-start,markers=markers,execution_totals=[],complete=status in ('cancelled','failed','associated')))
    return result


def fixture(path, detail, other=False):
    rows=[dict(type='header',schema=1,detail=detail)]
    for sid in range(1,7):rows.append(dict(type='start',id=sid,parent=None,ts=sid*100,thread=1,name='handle_propose',category='consensus',fields={}))
    def event(sid,ts,**fields):rows.append(dict(type='event',id=sid,ts=ts,thread=1,fields=fields))
    # Publication order and duplicate markers must survive; do not sort/deduplicate.
    event(1,210,stage='proposal_start');event(1,209,stage='proposal_start');event(1,209,stage='proposal_start')
    event(1,220,stage='proposal_ready',block_hash=('b' if other else 'a')*24);event(1,230,stage='finalized')
    event(2,250,stage='proposal_failed')
    if not other:event(2,260,stage='cancelled')
    event(3,350,stage='proposal_failed');event(4,450);event(5,550,stage='proposal_start')
    event(5,1000,stage='cancelled')
    for i in range(200):event(i%6+1,601+i,stage='prewarm_leaf_completed',prewarm_leaf=i+1)
    event(6,900,stage='not_a_stage')
    for sid in (1,2,3,4):rows.append(dict(type='end',id=sid,ts=950,thread=1))
    rows.append(dict(type='footer',dropped=0,io_error=False))
    path.write_text('\n'.join(map(json.dumps,rows)))


class AttemptIndexTests(unittest.TestCase):
    def test_node_identity_order_duplicates_and_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            paths=[Path(directory)/f'{node}.jsonl' for node in ('a','b')]
            for detail in ('full','milestones'):
                for i,path in enumerate(paths):fixture(path,detail,bool(i))
                result=build(paths,0)
                self.assertEqual(result['attempt_details'],legacy_attempts(paths))
                first=result['attempt_details'][0]
                self.assertEqual([m['stage'] for m in first['markers']],['proposal_start']*3+['proposal_ready','finalized'])
                self.assertGreater(first['markers'][0]['ts'],first['markers'][1]['ts'])
                same_id=[a for a in result['attempt_details'] if a['start']==.0001]
                self.assertEqual([x['status'] for x in same_id],['cancelled','failed'])
                self.assertEqual(result['attempt_details'][-1]['status'],'shutdown_incomplete')
                self.assertEqual(result['attempt_details'][-1]['end'],result['attempt_details'][-1]['start'])
                self.assertTrue(result['bad_capture'])
    def test_cutoff_before_index_and_incomplete_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl';fixture(path,'milestones')
            window=dict(backpressure=dict(ts=1000,node='Validator A'))
            result=build([path],0,window)
            self.assertEqual(result['attempt_details'],legacy_attempts([path],window))
            self.assertEqual([a['status'] for a in result['attempt_details']],['associated','cancelled','failed','unexplained_unassociated','cutoff_incomplete','cutoff_incomplete'])
            self.assertNotIn('cancelled',[m['stage'] for m in result['attempt_details'][4]['markers']])
            self.assertEqual(result['attempt_details'][-1]['end'],.0009)
    def test_no_attempts_and_missing_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.jsonl'
            rows=[dict(type='header',schema=1),dict(type='event',id=0,ts=2,thread=1,fields={}),dict(type='footer',dropped=0,io_error=False)]
            path.write_text('\n'.join(map(json.dumps,rows)))
            self.assertEqual(build([path],0)['attempt_details'],legacy_attempts([path]))

if __name__=='__main__':unittest.main()
