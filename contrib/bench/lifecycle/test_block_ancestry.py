"""Differential ancestry behavior against the original parent walk."""
import json
from pathlib import Path
import random
import tempfile
import unittest
from report import block_key, read_node


def original_inherited(span, spans):
    seen = set()
    while span and span['id'] not in seen:
        seen.add(span['id'])
        key = block_key(span['fields'])
        if key:
            return key
        span = spans.get(span.get('parent'))
    return None


class BlockAncestryTests(unittest.TestCase):
    def check_rows(self, rows, cutoff=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.jsonl'
            path.write_text('\n'.join(map(json.dumps, rows)))
            spans, events, _ = read_node(path, 'Validator A', cutoff)
        by_id = {span['id']: span for span in spans}
        for span in spans:
            self.assertEqual(span['block'], original_inherited(span, by_id))
        for event in events:
            self.assertEqual(event['block'], block_key(event['fields']) or
                             original_inherited(by_id.get(event['id']), by_id))
        return by_id, events

    @staticmethod
    def start(sid, parent, fields=None):
        return dict(type='start', id=sid, parent=parent, ts=sid, thread=1,
                    name='scope', category='lifecycle', fields=fields or {})

    def test_nearest_hash_cycles_missing_parents_and_late_fields(self):
        starts=[self.start(1, 2), self.start(2, 3), self.start(3, 1),
                self.start(4, 2, {'block_hash':'a'*24}),
                self.start(5, 6), self.start(6, 7), self.start(7, 5),
                self.start(8, 999), self.start(9, 4),
                self.start(10, 9, {'block_hash':'bad', 'hash':'b'*24})]
        rows=[dict(type='header',schema=1), *starts,
              dict(type='fields',id=3,ts=100,fields={'block_hash':'c'*24}),
              dict(type='event',id=9,ts=110,fields={'stage':'finalized','block_hash':'d'*24}),
              dict(type='event',id=9,ts=120,fields={'block_hash':'e'*24}),
              dict(type='footer',dropped=0,io_error=False)]
        spans, events=self.check_rows(rows,200)
        self.assertEqual([spans[i]['block'] for i in (1,2,3)], ['c'*24]*3)
        self.assertEqual([spans[i]['block'] for i in (5,6,7,8)], [None]*4)
        self.assertEqual(spans[4]['block'],'a'*24)
        self.assertEqual(spans[9]['block'],'d'*24)
        self.assertEqual(spans[10]['block'],'b'*24)
        self.assertEqual(events[-1]['block'],'e'*24)
        before,_=self.check_rows(rows,100)
        self.assertIsNone(before[1]['block'])

    def test_deterministic_mixed_graph_and_publication_order(self):
        rng=random.Random(718)
        starts=[]
        for sid in range(1,401):
            parent=rng.choice([None,999,*range(1,401)])
            fields={'block_hash': f'{sid:024x}'} if sid%13==0 else {}
            starts.append(self.start(sid,parent,fields))
        rng.shuffle(starts)
        rows=[dict(type='header',schema=1),*starts,
              *(dict(type='event',id=sid,ts=500+sid,fields={'stage':'proposal_start'})
                for sid in range(1,401)),
              dict(type='footer',dropped=0,io_error=False)]
        self.check_rows(rows,1000)
        self.check_rows([rows[0],*reversed(starts),*rows[401:]],1000)


if __name__=='__main__':unittest.main()
