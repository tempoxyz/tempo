"""Exercise the actual lifecycle exporter through scheduler publication."""
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest

from report import write_report
sys.path.insert(0,str(Path(__file__).parent/'scheduler'))
from test_fault_reasons import capture


class SchedulerIntegrationTests(unittest.TestCase):
    def test_pruned_registered_full_capture_exports_exact_origin_and_fault_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);raw=root/'raw';out=root/'out';raw.mkdir()
            for process,role in enumerate(('a','b'),1):
                _,source=capture(raw,process);source.rename(raw/f'scheduler-{role}.json.gz')
                values=[
                    dict(type='header',schema=1,clock='shared_monotonic_relative_ns',detail='full',prewarm_cpu='disabled',scheduler='registered_threads_v1'),
                    dict(type='start',id=1,ts=2,thread=1,parent=None,name='handle_propose',category='consensus',fields={}),
                    dict(type='enter',id=1,ts=2,thread=1),
                    dict(type='event',id=1,ts=2,thread=1,fields={'stage':'proposal_start'}),
                    dict(type='event',id=1,ts=3,thread=1,fields={'stage':'proposal_ready','block_hash':'1'*24}),
                    dict(type='event',id=1,ts=8,thread=1,fields={'stage':'finalized','block_hash':'1'*24}),
                    dict(type='exit',id=1,ts=8,thread=1),dict(type='end',id=1,ts=8,thread=1),
                    dict(type='event',id=0,ts=10,thread=1,fields={'stage':'backpressure_start'}),
                    dict(type='footer',dropped=0,io_error=False,prewarm_coverage_failures=0)]
                (raw/f'{role}.jsonl').write_text('\n'.join(map(json.dumps,values))+'\n')
            result=write_report([raw/'a.jsonl',raw/'b.jsonl'],out,warmup=0,
                window={'start_ns':0,'end_ns':20},prune=True,expected_detail='full',expected_prewarm_cpu='disabled',scheduler_dir=raw)
            self.assertFalse(result['bad_capture']);self.assertEqual(result['eligible'],1)
            self.assertEqual(result['time_origin_ns'],2)
            self.assertEqual(result['prewarm']['time_origin_ns'],2)
            summary=json.loads((out/'scheduler-summary.json').read_text())
            self.assertEqual(summary['cutoff_ns'],10)
            self.assertEqual(summary['nodes'][0]['blocked_wall_ns_by_wait_reason'],{'filemap_fault_io_schedule':2})
            trace=json.loads(gzip.decompress((out/'perfetto-scheduler-block-1.json.gz').read_bytes()))
            waits=[x for x in trace['traceEvents'] if x.get('args',{}).get('kernel_wait_reason')==6]
            self.assertEqual(len(waits),2)
            self.assertTrue(all(x['ts']==.001 and x['dur']==.002 for x in waits))
            self.assertTrue((out/'scheduler.html').exists())
            self.assertNotIn('backpressure_start',(out/'a.jsonl').read_text())

if __name__=='__main__':unittest.main()
