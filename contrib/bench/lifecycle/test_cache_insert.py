import copy,json,re,tempfile,unittest
from pathlib import Path
from cache_insert import FIELDS, valid_counts, attach_cache_insert_details
from report import build, write_report
from perfetto import trace_events
from test_report import fixture


def counts():
    return dict(zip(FIELDS,(1,3,1,1,1,0,2,1,1,1,0)))


class CacheInsertTests(unittest.TestCase):
    def test_cardinality_outcome_bounds_and_unavailable(self):
        self.assertTrue(valid_counts(counts()))
        for key,value in [('cache_insert_slots_attempted',3),('cache_insert_accounts_seen',4),
                          ('cache_insert_measured',0),('cache_insert_counts_saturated',1),
                          ('cache_insert_outcome',0),('cache_insert_accounts_removed',True),
                          ('cache_insert_contracts_attempted',2**53)]:
            fields=counts();fields[key]=value
            self.assertFalse(valid_counts(fields))
        for outcome in (2,3):
            fields=counts();fields.update(cache_insert_outcome=outcome,cache_insert_accounts_seen=4)
            self.assertTrue(valid_counts(fields))
        fields=counts();fields.pop('cache_insert_slots_changed');self.assertFalse(valid_counts(fields))

    def test_exact_node_scope_unique_summary_no_causal_guessing(self):
        row=dict(node='Validator A',id=1,name='insert_state',start=0,end=1,details={})
        event=dict(node='Validator A',id=1,ts=100,fields=dict(counts(),stage='execution_cache_insert_totals'))
        for events in ([event],[event,event],[dict(event,id=2)],[dict(event,node='Validator B')],[dict(event,ts=2_000_000)]):
            rows=[copy.deepcopy(row)];attach_cache_insert_details(rows,events,0)
            self.assertEqual('cache_insert_measured' in rows[0]['details'],events==[event])

    def test_declared_mode_rejects_missing_mixed_or_unknown_summaries(self):
        with tempfile.TemporaryDirectory() as directory:
            paths=[Path(directory)/name for name in ('a.jsonl','b.jsonl')]
            for path in paths:
                fixture(path)
                rows=[json.loads(s) for s in path.read_text().splitlines()]
                rows[0]['cache_insert']='counts_v1'
                rows[-1:-1]=[dict(type='start',id=200,ts=1_000_000_300,thread=1,name='insert_state',category='execution',parent=1,fields={}),
                             dict(type='end',id=200,ts=1_000_000_500)]
                path.write_text('\n'.join(map(json.dumps,rows)))
            data=build(paths,warmup=0)
            self.assertTrue(data['bad_capture']);self.assertFalse(data['cache_insert_valid'])
            self.assertTrue(all(v is None for v in data['representatives'].values()))
            for mode in ('disabled','unknown'):
                rows=[json.loads(s) for s in paths[1].read_text().splitlines()];rows[0]['cache_insert']=mode
                paths[1].write_text('\n'.join(map(json.dumps,rows)))
                self.assertTrue(build(paths,warmup=0)['bad_capture'])

    def test_raw_report_cutoff_selected_page_and_perfetto(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'a.jsonl';fixture(path)
            events=[json.loads(s) for s in path.read_text().splitlines()]
            events[0]['cache_insert']='counts_v1'
            extra=[dict(type='start',id=200,ts=1_000_000_300,thread=1,name='insert_state',category='execution',parent=1,fields={}),
                   dict(type='event',id=200,ts=1_000_000_400,fields=dict(counts(),stage='execution_cache_insert_totals')),
                   dict(type='end',id=200,ts=1_000_000_500)]
            events[-1:-1]=extra;path.write_text('\n'.join(map(json.dumps,events)))
            result=write_report([path],root/'report',warmup=0)
            row=next(s for s in result['spans'] if s['id']==200)
            self.assertEqual(row['block'],1);self.assertEqual(row['details']['cache_insert_slots_unchanged'],1)
            trace=trace_events(result,block_id=1)
            self.assertTrue(any(e.get('args',{}).get('cache_insert_slots_unchanged')==1 for e in trace))
            focused=json.loads(re.search(r'<script type="application/json" id="data">(.*?)</script>',(root/'report/block-1.html').read_text(),re.S)[1])
            self.assertEqual(next(s for s in focused['spans'] if s['id']==200)['details'],row['details'])
            events[-1:-1]=[dict(type='event',id=0,ts=1_000_000_400,fields=dict(stage='backpressure_start'))]
            path.write_text('\n'.join(map(json.dumps,events)))
            clipped=build([path],warmup=0)
            row=next(s for s in clipped['spans'] if s['id']==200)
            self.assertNotIn('cache_insert_measured',row['details'])
            self.assertEqual(row['details']['cache_insert_summary_count'],0)


if __name__=='__main__':unittest.main()
