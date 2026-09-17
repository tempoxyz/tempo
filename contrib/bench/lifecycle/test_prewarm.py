import copy
import json
from pathlib import Path
import tempfile
import unittest

import prewarm
from backpressure import prepare_captures
from report import build, write_report


def fixture():
    spans, events, quality = [], [], []
    for node in ('Validator A','Validator B'):
        quality.append(dict(node=node,prewarm_cpu='leaf_v1',prewarm_coverage_failures=0))
        for role in (1,2):
            context=role*10
            spans.append(dict(id=context,node=node,name='prewarm.context',ts=2,end=90,thread=1,
                              fields=dict(prewarm_role=role,prewarm_mode=1),block='a'*24))
            def event(ts,stage,**fields):
                return dict(node=node,id=context,thread=role,ts=ts,fields=dict(stage=stage,**fields))
            events.extend([
                event(3,'prewarm_context_started',prewarm_role=role,prewarm_mode=1),
                event(10,'prewarm_leaf_started',prewarm_leaf=1),
                event(40,'prewarm_leaf_completed',prewarm_leaf=1,prewarm_cpu_measured=1,prewarm_thread_cpu_ns=0,prewarm_outcome=5),
                event(80,'prewarm_context_completed',prewarm_dispatched=1,prewarm_started=1,prewarm_completed=1,prewarm_context_outcome=0)])
    return spans,events,quality


def captures(out, cutoff=None, failed=False):
    spans,events,_=fixture()
    paths=[]
    for node in ('Validator A','Validator B'):
        rows=[dict(type='header',schema=1,clock='shared_monotonic_relative_ns',detail='milestones',prewarm_cpu='leaf_v1'),
              dict(type='start',id=1,parent=None,thread=1,ts=1,name='validate_block_with_state',category='execution',fields=dict(block_hash='a'*24))]
        for span in spans:
            if span['node'] == node:
                rows.append(dict(type='start',id=span['id'],parent=1,thread=1,ts=span['ts'],name=span['name'],category='lifecycle',fields=span['fields']))
        for e in events:
            if e['node'] == node:
                rows.append(dict(type='event',**{k:v for k,v in e.items() if k!='node'}))
        milestones=[(4,'proposal_start'),(5,'digest_released'),(50,'body_ready'),(51,'verify_start'),(52,'replay_start'),(53,'replay_done'),(54,'verify_done'),(55,'notarize_vote_sent'),(56,'finalized')]
        for ts,stage in milestones:
            if (node=='Validator A' and stage in ('proposal_start','digest_released','finalized')) or (node=='Validator B' and stage not in ('proposal_start','digest_released','finalized')):
                rows.append(dict(type='event',id=1,ts=ts,thread=1,fields=dict(stage=stage)))
        rows.extend(dict(type='end',id=role*10,ts=90,thread=1) for role in (1,2))
        rows.append(dict(type='end',id=1,ts=100,thread=1))
        if cutoff is not None and node=='Validator A':
            rows.append(dict(type='event',id=1,ts=cutoff,thread=1,fields=dict(stage='backpressure_start')))
        if failed:
            rows.append(dict(type='event',id=1,ts=200,thread=1,fields=dict(stage='prewarm_coverage_failure',prewarm_failure=1)))
        rows=[rows[0]]+sorted(rows[1:],key=lambda x:x['ts'])
        rows.append(dict(type='footer',written=len(rows),dropped=0,io_error=False,prewarm_coverage_failures=int(failed)))
        path=out/('a.jsonl' if node=='Validator A' else 'b.jsonl')
        path.write_text(''.join(json.dumps(r)+'\n' for r in rows));paths.append(path)
    return paths


class PrewarmTests(unittest.TestCase):
    def test_roles_measured_zero_and_absent_cpu(self):
        spans,events,quality=fixture()
        events[2]['fields'].update(prewarm_cpu_measured=0)
        events[2]['fields'].pop('prewarm_thread_cpu_ns')
        data=prewarm.inspect(spans,events,quality,{'a'*24:7},None,'leaf_v1')
        self.assertEqual(len(data['leaves']),4)
        self.assertIsNone(data['leaves'][0]['cpu_ns'])
        self.assertEqual(data['leaves'][1]['cpu_ns'],0)
        self.assertTrue(all(x['block']==7 for x in data['leaves']))

    def test_missing_partial_bad_numbers_and_roles_reject(self):
        base=fixture()
        for mutate in (
            lambda s,e,q:e.pop(2),
            lambda s,e,q:e.pop(0),
            lambda s,e,q:e.append(copy.deepcopy(e[1])),
            lambda s,e,q:e[2]['fields'].update(prewarm_cpu_measured=True),
            lambda s,e,q:e[2]['fields'].update(prewarm_thread_cpu_ns=-1),
            lambda s,e,q:e[2]['fields'].update(prewarm_outcome=9),
            lambda s,e,q:e[2].update(thread=99),
            lambda s,e,q:e[3]['fields'].update(prewarm_dispatched=2),
            lambda s,e,q:q[0].update(prewarm_coverage_failures=1),
            lambda s,e,q:q[0].update(prewarm_cpu='disabled'),
        ):
            args=copy.deepcopy(base);mutate(*args)
            with self.assertRaises(ValueError):prewarm.inspect(*args,{},None,'leaf_v1')
        spans,events,quality=fixture()
        spans=[s for s in spans if s['id']!=20]
        events=[e for e in events if e['id']!=20]
        with self.assertRaisesRegex(ValueError,'missing required'):prewarm.inspect(spans,events,quality,{},None)

    def test_cutoff_equality_is_censored_not_zero_and_failure_footer_survives(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);out=root/'out'
            paths=captures(root,40)
            data=write_report(paths,out,warmup=0,prune=True,expected_prewarm_cpu='leaf_v1')
            self.assertTrue(data['prewarm_valid'])
            self.assertTrue(all(x['end_ns'] is None and x['cpu_ns'] is None for x in data['prewarm']['leaves']))
            for path in (out/'a.jsonl',out/'b.jsonl'):
                self.assertTrue(all(e.get('ts',0)<40 for e in map(json.loads,path.read_text().splitlines())))
            paths=captures(root,40,failed=True)
            clean,window=prepare_captures(paths,root/'failure')
            self.assertEqual(json.loads(clean[0].read_text().splitlines()[-1])['prewarm_coverage_failures'],1)
            self.assertTrue(build(clean,window=window,expected_prewarm_cpu='leaf_v1')['bad_capture'])

    def test_unordered_ordinals_and_nested_thread_overlap(self):
        spans,events,quality=fixture()
        events[1]['fields']['prewarm_leaf']=2;events[2]['fields']['prewarm_leaf']=2
        extra=copy.deepcopy(events[1]);extra['ts']=20;extra['fields']['prewarm_leaf']=1
        end=copy.deepcopy(events[2]);end['ts']=30;end['fields']['prewarm_leaf']=1
        events.extend([extra,end]);events[3]['fields'].update(prewarm_dispatched=2,prewarm_started=2,prewarm_completed=2)
        data=prewarm.inspect(spans,events,quality,{},None)
        self.assertEqual(sum(x['overlaps_same_thread'] for x in data['leaves']),2)

    def test_unwound_skipped_context_cannot_declare_unstarted_transaction_jobs(self):
        spans,events,quality=fixture()
        spans[0]['fields']['prewarm_mode']=3
        events[0]['fields']['prewarm_mode']=3
        events=[e for e in events if not(e['node']=='Validator A' and e['id']==10 and e['fields']['stage'] in ('prewarm_leaf_started','prewarm_leaf_completed'))]
        finish=next(e for e in events if e['node']=='Validator A' and e['id']==10 and e['fields']['stage']=='prewarm_context_completed')
        finish['fields'].update(prewarm_dispatched=1,prewarm_started=0,prewarm_completed=0,prewarm_context_outcome=1)
        with self.assertRaisesRegex(ValueError,'unmeasured selection'):prewarm.inspect(spans,events,quality,{},None)

    def test_old_binary_cannot_silently_accept_requested_mode(self):
        quality=[dict(node='Validator A'),dict(node='Validator B')]
        self.assertEqual(prewarm.inspect([],[],quality,{},None)['mode'],'disabled')
        with self.assertRaisesRegex(ValueError,'coverage failure'):
            prewarm.inspect([],[],[dict(node='Validator A',prewarm_cpu='disabled',prewarm_coverage_failures=1)],{},None)
        with self.assertRaises(ValueError):prewarm.inspect([],[],quality,{},None,'leaf_v1')

    def test_package_preserves_every_leaf_once_and_removes_stale_chunks(self):
        spans,events,quality=fixture();data=prewarm.inspect(spans,events,quality,{},None)
        with tempfile.TemporaryDirectory() as root:
            out=Path(root);prewarm.write_view(data,out,limit=2)
            manifest=json.loads((out/'prewarm-manifest.json').read_text())
            self.assertEqual([x['leaves'] for x in manifest['chunks']],[2,2])
            exported=[x for chunk in manifest['chunks'] for x in json.loads((out/chunk['file']).read_text())['traceEvents'] if x['ph'] != 'M']
            self.assertEqual(len(exported),len(data['leaves']))
            self.assertEqual(len({(e['pid'],e['args']['context'],e['args']['ordinal']) for e in exported}),4)
            prewarm.write_view(data,out,limit=10)
            self.assertFalse((out/'prewarm-0002.json').exists())
            prewarm.write_view(dict(mode='disabled'),out)
            self.assertFalse((out/'prewarm.html').exists())


if __name__=='__main__':unittest.main()
