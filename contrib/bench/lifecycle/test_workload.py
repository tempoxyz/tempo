import json
from pathlib import Path
import tempfile
import unittest
import workload

class WorkloadTests(unittest.TestCase):
    def test_select_excludes_setup_empty_postload_and_incomplete_blocks(self):
        blocks=[dict(id=i,start=i,execution_totals=[{'transactions':n}]) for i,n in [(1,3),(2,10),(3,0),(4,20),(5,30)]]
        events={str(i):[{'fields':{'height':i}}] for i in range(1,7)}
        selected,meta=workload.select(blocks,events,{str(i):i for i in range(1,7)},{2:10,3:0,4:20,6:40})
        self.assertEqual([b['id'] for b in selected],[2,4])
        self.assertEqual(meta['completed_transactions'],30)
        self.assertNotIn('height',json.dumps(meta))
    def test_mismatch_and_ambiguous_height_reject(self):
        b=[dict(id=1,start=0,execution_totals=[{'transactions':10}])]
        with self.assertRaises(ValueError):workload.select(b,{'a':[{'fields':{'height':1}}]},{'a':1},{1:11})
        with self.assertRaises(ValueError):workload.select(b,{'a':[{'fields':{'height':1}},{'fields':{'height':2}}]},{'a':1},{1:10})
    def test_private_report_keeps_only_numeric_fields_and_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'sender.json'
            p.write_text(json.dumps({'secret':'discard','blocks':[{'number':1,'tx_count':10,'hash':'discard'}]}))
            self.assertEqual(workload.load(p),{1:10})
            for rows in [[{'number':True,'tx_count':2}],[{'number':1,'tx_count':2}]*2]:
                p.write_text(json.dumps({'blocks':rows}))
                with self.assertRaises(ValueError):workload.load(p)
