import base64
import copy
import ctypes as C
import errno
import gzip
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time
import unittest
from binary_capture import prepare_native, program_for
from binary_transport import EVENT
from spool import FOOTER,MAGIC,WAIT_FOOTER,WAIT_MAGIC,footer,integrity,rows
from stream_decode import publish_streamed
from wait_reasons import classify_symbols,helper_failure,pack,unpack,counts,resolver
from test_runtime import report

RAW=struct.Struct('<QI H H i I')
META=dict(scope='registered validator thread windows only',process=1,cutoff_reason='backpressure',registration='registered_threads_v1')


def capture(directory, values=None, cutoff=10, process=1):
    values=values or [(1,1,0,0),(3,1,1,pack(1,1,1)),(5,1,3,0),(7,1,2,0),(12,1,4,0)]
    output=Path(directory)/f'source-{process}.json.gz'
    with tempfile.TemporaryFile(dir=directory) as source:
        for row in values:source.write(EVENT.pack(*row))
        publish_streamed(output,source,directory,0,cutoff,len(values),dict(META,process=process),probe_misses=0,wait_reasons=True)
    return json.loads(gzip.decompress(output.read_bytes())),output


class WaitTests(unittest.TestCase):
    def test_truncated_unresolved_conflicting_and_unknown_are_distinct(self):
        self.assertEqual(classify_symbols([b'futex_wait']), (1,1))
        self.assertEqual(classify_symbols([b'futex_wait'],truncated=True),(0,6))
        self.assertEqual(classify_symbols([b'futex_wait',b'0xPRIVATE']),(0,7))
        self.assertEqual(classify_symbols([b'futex_wait',b'pipe_read']),(0,8))
        self.assertEqual(classify_symbols([b'unknown_valid_kernel_symbol']),(0,2))
        self.assertEqual(helper_failure(-errno.EEXIST),(0,4))
        self.assertEqual(helper_failure(-errno.ENOMEM),(0,5))
        self.assertEqual(helper_failure(-errno.EFAULT),(0,3))
        self.assertEqual(helper_failure(-999),(0,3))

    def test_kernel_stack_limit_below_map_depth_remains_truncated(self):
        class Table:
            Key=int
            def __getitem__(self,key):
                return type('Entry',(),{'ip':[1,2,3,0,0]})()
        class Fake:
            def __getitem__(self,key):return Table()
            def ksym(self,address):return b'futex_wait'
        self.assertEqual(resolver(Fake(),3)(0),6<<12)
        self.assertEqual(resolver(Fake(),5)(0),1<<9|1<<12)

    def test_source_exact_interval_join_cutoff_and_known_unknown_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            result,_=capture(directory)
            self.assertEqual(result['schema'],4)
            report.validate(result,1,10,'backpressure')
            observed=[r for r in result['records'] if 'wait_status' in r]
            self.assertEqual([(r['ts'],r['wait_reason'],r['wait_status']) for r in observed],[(3,1,1)])
            blocked=[r for r in result['intervals'] if 'wait_status' in r]
            self.assertEqual([(r['start'],r['end'],r['kind']) for r in blocked],[(3,5,'blocked_before_wakeup')])
            self.assertEqual(result['wait_reasons']['known'],1)
            self.assertEqual(result['wait_reasons']['unknown'],0)
            for cut in (3,4,5):
                result,_=capture(directory,cutoff=cut)
                self.assertTrue(all(r['ts']<cut for r in result['records']))
                self.assertTrue(all(r['end']<cut for r in result['intervals']))
                self.assertEqual(result['wait_reasons']['sampled'],int(cut>3))
                if cut==5:
                    blocked=next(r for r in result['intervals'] if r['kind']=='blocked_before_wakeup')
                    self.assertEqual((blocked['end'],blocked['wait_reason'],blocked['right_censored']),(4,1,True))
            for status in range(2,10):
                state=4 if status==9 else 2
                result,_=capture(directory,[(1,1,0,0),(3,1,1,pack(state,0,status)),(5,1,3,0),(7,1,2,0),(12,1,4,0)])
                report.validate(result,1,10,'backpressure')
                self.assertEqual(result['wait_reasons']['status_counts'][str(status)],1)
                self.assertEqual(result['wait_reasons']['unknown'],int(status!=9))
                self.assertEqual(result['wait_reasons']['not_sampled'],int(status==9))

    def test_malformed_modes_fields_counts_and_missing_wakeup_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            result,_=capture(directory)
            for change in ('schema','missing_record','wrong_interval','count','boolean'):
                bad=copy.deepcopy(result)
                if change=='schema':bad['schema']=3
                if change=='missing_record':bad['records'][1].pop('wait_status')
                if change=='wrong_interval':bad['intervals'][0].update(wait_reason=1,wait_status=1)
                if change=='count':bad['wait_reasons']['known']+=1
                if change=='boolean':bad['wait_reasons']['known']=True
                with self.subTest(change=change),self.assertRaises(ValueError):report.validate(bad,1,10,'backpressure')
            result,_=capture(directory,[(1,1,0,0),(3,1,1,pack(1,1,1)),(7,1,2,0),(12,1,4,0)])
            self.assertFalse(result['registered_window_edges_complete'])
            self.assertFalse(any('wait_status' in r for r in result['intervals']))
        for kind,bits in [(0,pack(1,1,1)),(1,1),(1,256|(1<<12)),(1,1|(1<<9)|(2<<12)),(1,4|(1<<12))]:
            with self.assertRaises(ValueError):unpack(kind,bits,True)

    def test_native_resolves_immutable_id_once_before_private_spool(self):
        with tempfile.TemporaryDirectory() as directory,tempfile.TemporaryFile(dir=directory) as source:
            native=prepare_native(directory);calls=[]
            callback_type=C.CFUNCTYPE(C.c_int,C.c_int)
            callback=callback_type(lambda key:(calls.append(key) or (1<<9|1<<12)))
            native.configure_waits.argtypes=[C.c_void_p,callback_type];native.configure_waits.restype=C.c_int
            native.collect.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t]
            context=native.allocate(source.fileno())
            try:
                self.assertEqual(native.configure_waits(context,callback),0)
                values=[(1,1,0,0,-2**31,0),(2,1,1,1,17,0),(3,1,1,1,17,0),(4,1,1,2,-errno.EEXIST,0),(5,1,1,2,-errno.ENOMEM,0),(6,1,1,2,-errno.EFAULT,0),(7,1,1,4,-2**31,0)]
                for item in values:
                    raw=RAW.pack(*item);native.collect(context,C.create_string_buffer(raw),len(raw))
                native.finalize(context)
                self.assertEqual(calls,[17]);self.assertEqual(native.metric(context,1),0)
                safe=list(rows(source));self.assertEqual(len(safe),len(values))
                self.assertEqual(os.fstat(source.fileno()).st_size,len(values)*16)
                self.assertEqual([unpack(k,b,True)[1].get('wait_status') for _,_,k,b in safe],[None,1,1,4,5,3,9])
                self.assertEqual([r[0] for r in safe],list(range(1,8)))
                for item in [(8,1,1,1,1024,0),(8,1,1,0,17,0),(8,1,1,1,17,1)]:
                    raw=RAW.pack(*item);native.collect(context,C.create_string_buffer(raw),len(raw))
                self.assertEqual(native.metric(context,1),3)
            finally:native.release(context)

    def test_footer_versions_and_indexed_runtime_loader_and_perfetto(self):
        values=[1,1,0,0,0,0,1,5,0]
        self.assertNotIn('wait_reasons',footer(FOOTER.pack(MAGIC,*values)))
        self.assertEqual(footer(WAIT_FOOTER.pack(WAIT_MAGIC,*values,1))['wait_reasons'],1)
        with self.assertRaises(ValueError):footer(WAIT_FOOTER.pack(WAIT_MAGIC,*values,0))
        with tempfile.TemporaryDirectory() as directory:
            private=Path(directory)/'private';private.mkdir();out=Path(directory)/'out';out.mkdir()
            for process,role in enumerate(('a','b'),1):
                _,path=capture(private,process=process)
                path.rename(private/f'scheduler-{role}.json.gz')
                (out/f'{role}.jsonl').write_text('{"type":"header","scheduler":"registered_threads_v1"}\n')
            captures,coverage=report.load(private,out,{'backpressure':{'ts':10}})
            try:
                self.assertEqual([c['schema'] for c in captures],[4,4])
                events=report.scheduler_events(captures,0,0,1)
                selected=[e for e in events if 'kernel_wait_reason' in e.get('args',{})]
                self.assertEqual(len(selected),2)
                self.assertTrue(all(e['name']=='blocked_before_wakeup' for e in selected))
                self.assertTrue(all(e['args']['observed_kernel_wait_path']=='futex_wait' for e in selected))
                self.assertEqual(captures[0]['intervals'].wait_totals(),{'futex_wait':2})
                (out/'perfetto-block-1.json').write_text('{"traceEvents":[]}')
                (out/'index.html').write_text('<h1>Lifecycle</h1>')
                data={'time_origin_ns':0,'blocks':[{'id':1,'start':0,'end':.00001}],
                      'representatives':{'50':1,'90':1,'99':1},'bad_capture':False}
                report.publish(data,captures,out,coverage)
                summary=json.loads((out/'scheduler-summary.json').read_text())
                self.assertEqual(summary['nodes'][0]['wait_reasons']['known'],1)
                self.assertEqual(summary['nodes'][0]['blocked_wall_ns_by_wait_reason'],{'futex_wait':2})
                exported=json.loads(gzip.decompress((out/'perfetto-scheduler-block-1.json.gz').read_bytes()))
                self.assertEqual(len([e for e in exported['traceEvents'] if 'kernel_wait_reason' in e.get('args',{})]),2)
                self.assertIn('Unknown, unavailable, truncated and conflicting',(out/'scheduler.html').read_text())
            finally:report.close(captures)

    @unittest.skipUnless(os.environ.get('TEMPO_SCHEDULER_LIVE_TEST')=='1','requires local BPF/root')
    def test_live_production_transport_private_symbols_exact_edges_and_pruning(self):
        root=Path(__file__).parent
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'synthetic'
            subprocess.run(['gcc','-O2','-pthread',str(root/'wait_reason_probe/child.c'),'-o',str(binary)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            origin=time.monotonic_ns()
            with tempfile.TemporaryFile(dir=directory) as source:
                result=subprocess.run(['/usr/bin/python3',str(root/'binary_capture.py'),'--wait-reasons','--binary',str(binary),'--epoch','1','--command-base64',base64.b64encode(str(binary).encode()).decode(),'--spool-fd',str(source.fileno()),'--scratch-dir',directory],pass_fds=(source.fileno(),),capture_output=True,timeout=20)
                self.assertEqual(result.returncode,0);self.assertFalse(result.stderr)
                evidence=footer(result.stdout);self.assertEqual(evidence['wait_reasons'],1);integrity(evidence,source)
                stamps=[r[0] for r in rows(source)];cutoff=(min(stamps)+max(stamps))//2-origin
                output=Path(directory)/'capture.json.gz'
                publish_streamed(output,source,directory,origin,cutoff,evidence['emitted'],META,probe_misses=evidence['probe_misses'],wait_reasons=True)
                decoded=json.loads(gzip.decompress(output.read_bytes()))
            report.validate(decoded,1,cutoff,'backpressure')
            self.assertTrue(decoded['registered_window_edges_complete'])
            self.assertGreater(decoded['quality']['at_or_post_cutoff_records_pruned'],0)
            observed={r['wait_reason'] for r in decoded['records'] if r.get('wait_status')==1}
            self.assertTrue({1,3,4}<=observed)
            for role,expected in [(1,3),(2,1),(3,4)]:
                self.assertIn(expected,{r['wait_reason'] for r in decoded['records'] if r['thread']==role and r.get('wait_status')==1})
            self.assertGreater(decoded['wait_reasons']['known'],0)
            self.assertTrue(all(r['ts']<cutoff for r in decoded['records']))
            self.assertTrue(all(r['end']<cutoff for r in decoded['intervals']))

if __name__=='__main__':unittest.main()
