"""Builder topology: detached build scope, prewarm completion, then own hash."""
import json
from pathlib import Path
import tempfile
import unittest

from report import build
from test_prewarm import captures


class BuilderPrewarmLineageTests(unittest.TestCase):
    def capture(self, directory, result, retain=True):
        paths=captures(directory)
        for index,path in enumerate(paths):
            rows=[json.loads(line) for line in path.read_text().splitlines()]
            for row in rows:
                if row.get('type')=='start' and row.get('id')==20:
                    row['parent']=30 if retain else None
            if retain:
                rows[-1:-1]=[
                    dict(type='start',id=30,parent=None,thread=1,ts=1,name='build_payload',category='builder',fields={}),
                    dict(type='end',id=30,thread=1,ts=100)]
                if result=='produced':
                    rows.insert(-1,dict(type='fields',id=30,thread=1,ts=95,fields=dict(block_hash=('a' if index==0 else 'b')*24)))
                else:
                    rows.insert(-1,dict(type='event',id=30,thread=1,ts=95,fields=dict(stage=result)))
            rows=[rows[0]]+sorted(rows[1:-1],key=lambda x:x['ts'])+[rows[-1]]
            rows[-1]['written']=len(rows)-1
            path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        return paths

    def test_late_own_hash_links_completed_builder_without_time_guess(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            old=build(self.capture(root,'produced',False),0,expected_prewarm_cpu='leaf_v1')
            fixed=build(self.capture(root,'produced'),0,expected_prewarm_cpu='leaf_v1')
            self.assertTrue(old['prewarm_valid'] and fixed['prewarm_valid'])
            before=[x for x in old['prewarm']['leaves'] if x['role']=='builder_tx']
            after=[x for x in fixed['prewarm']['leaves'] if x['role']=='builder_tx']
            self.assertTrue(all(x['block'] is None for x in before))
            self.assertTrue(all(x['block'] is not None for x in after))
            self.assertNotEqual(after[0]['block'],after[1]['block'])
            self.assertEqual([{k:v for k,v in x.items() if k!='block'} for x in before],
                             [{k:v for k,v in x.items() if k!='block'} for x in after])
            contexts=[s for s in fixed['spans'] if s['name']=='prewarm.context' and s['id']==20]
            self.assertTrue(all(s['parent']==30 for s in contexts))
            self.assertTrue(all(s['end'] < (95-fixed['prewarm']['time_origin_ns'])/1e6 for s in contexts))

    def test_cancelled_failed_and_post_cutoff_identity_remain_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for outcome in ('cancelled','proposal_failed'):
                data=build(self.capture(root,outcome),0,expected_prewarm_cpu='leaf_v1')
                self.assertTrue(data['prewarm_valid'])
                self.assertTrue(all(x['block'] is None for x in data['prewarm']['leaves'] if x['role']=='builder_tx'))
            data=build(self.capture(root,'produced'),0,window=dict(backpressure=dict(ts=95,node='Validator A')),expected_prewarm_cpu='leaf_v1')
            self.assertTrue(data['prewarm_valid'])
            self.assertTrue(all(x['block'] is None for x in data['prewarm']['leaves'] if x['role']=='builder_tx'))

if __name__=='__main__':unittest.main()
