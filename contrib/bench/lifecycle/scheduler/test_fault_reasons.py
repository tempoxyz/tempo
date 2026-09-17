import base64
import copy
import ctypes as C
import gzip
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import unittest
from binary_capture import prepare_native
from binary_transport import EVENT
from spool import WAIT_FOOTER,WAIT_MAGIC,FAULT_MAGIC,footer,integrity,rows
from stream_decode import publish_streamed
from wait_reasons import classify_symbols,pack,unpack,resolver
from test_wait_reasons import META,RAW
from test_runtime import report


def capture(directory,process=1,cutoff=10):
    values=[(1,1,0,0),(3,1,1,pack(1,6,1,2)),(5,1,3,0),(7,1,2,0),(12,1,4,0)]
    output=Path(directory)/f'source-{process}.json.gz'
    with tempfile.TemporaryFile(dir=directory) as source:
        for row in values:source.write(EVENT.pack(*row))
        publish_streamed(output,source,directory,0,cutoff,len(values),dict(META,process=process),probe_misses=0,wait_reasons=2)
    return json.loads(gzip.decompress(output.read_bytes())),output


class FaultTests(unittest.TestCase):
    def test_versioned_full_stack_refinement_and_conservative_fallback(self):
        frames=[b'io_schedule',b'folio_wait_bit_common',b'filemap_fault',b'handle_mm_fault']
        self.assertEqual(classify_symbols(frames),(2,1))
        self.assertEqual(classify_symbols(frames,version=2),(6,1))
        self.assertEqual(classify_symbols(frames,version=2,truncated=True),(0,6))
        self.assertEqual(classify_symbols(frames+[b'futex_wait'],version=2),(0,8))
        self.assertEqual(classify_symbols(frames+[b'0xffff'],version=2),(0,7))
        for frames in ([b'io_schedule',b'filemap_fault.constprop.0'],[b'filemap_fault',b'io_schedule'],[b'io_schedule',b'filemap_read']):
            self.assertEqual(classify_symbols(frames,version=2),(2,1))
        self.assertEqual(classify_symbols([b'filemap_fault'],version=2),(0,2))
        with self.assertRaises(ValueError):pack(1,6,1)
        bits=pack(1,6,1,2)
        self.assertEqual(unpack(1,bits,2)[1],{'wait_reason':6,'wait_status':1})
        with self.assertRaises(ValueError):unpack(1,bits,True)

    def test_footer_mode_and_native_callback_downgrade_rejected(self):
        values=[1,1,0,0,0,0,1,5,0]
        self.assertEqual(footer(WAIT_FOOTER.pack(FAULT_MAGIC,*values,2))['wait_reasons'],2)
        for magic,version in ((FAULT_MAGIC,1),(WAIT_MAGIC,2)):
            with self.assertRaises(ValueError):footer(WAIT_FOOTER.pack(magic,*values,version))
        for version in (1,2):
            with tempfile.TemporaryDirectory() as directory,tempfile.TemporaryFile(dir=directory) as source:
                native=prepare_native(directory);kind=C.CFUNCTYPE(C.c_int,C.c_int)
                callback=kind(lambda key:6<<9|1<<12)
                configure=native.configure_faults if version==2 else native.configure_waits
                configure.argtypes=[C.c_void_p,kind];configure.restype=C.c_int
                native.collect.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t]
                context=native.allocate(source.fileno())
                try:
                    self.assertEqual(configure(context,callback),0)
                    raw=RAW.pack(1,1,1,1,0,0);native.collect(context,C.create_string_buffer(raw),len(raw));native.finalize(context)
                    self.assertEqual(native.metric(context,1),0 if version==2 else 1)
                    self.assertEqual(len(list(rows(source))),1 if version==2 else 0)
                finally:native.release(context)

    def test_exact_source_interval_cutoff_and_schema_downgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            result,path=capture(directory)
            self.assertEqual(result['schema'],5);self.assertEqual(result['wait_reasons']['mode'],'kernel_stacks_v2')
            report.validate(result,1,10,'backpressure')
            self.assertEqual([(r['start'],r['end'],r['wait_reason']) for r in result['intervals'] if 'wait_reason' in r],[(3,5,6)])
            for cut in (3,4,5):
                result,_=capture(directory,cutoff=cut);report.validate(result,1,cut,'backpressure')
                self.assertTrue(all(r['ts']<cut for r in result['records']))
                self.assertTrue(all(r['end']<cut for r in result['intervals']))
                self.assertEqual(result['wait_reasons']['sampled'],int(cut>3))
            result,path=capture(directory)
            bad=copy.deepcopy(result);bad['schema']=4;bad['wait_reasons']['mode']='kernel_stacks_v1'
            with self.assertRaises(ValueError):report.validate(bad,1,10,'backpressure')
            path.write_bytes(gzip.compress(json.dumps(bad).encode()))
            with self.assertRaises(ValueError):report.indexed_capture(path,directory,1,10,'backpressure')

    def test_runtime_loader_summary_and_perfetto_preserve_code6(self):
        with tempfile.TemporaryDirectory() as directory:
            private=Path(directory)/'private';private.mkdir();out=Path(directory)/'out';out.mkdir()
            for process,role in enumerate(('a','b'),1):
                _,path=capture(private,process);path.rename(private/f'scheduler-{role}.json.gz')
                (out/f'{role}.jsonl').write_text('{"type":"header","scheduler":"registered_threads_v1"}\n')
            captures,coverage=report.load(private,out,{'backpressure':{'ts':10}})
            try:
                self.assertEqual([c['schema'] for c in captures],[5,5])
                (out/'perfetto-block-1.json').write_text('{"traceEvents":[]}');(out/'index.html').write_text('<h1>Lifecycle</h1>')
                data={'time_origin_ns':0,'blocks':[{'id':1,'start':0,'end':.00001}],'representatives':{'50':1,'90':1,'99':1},'bad_capture':False}
                report.publish(data,captures,out,coverage)
                summary=json.loads((out/'scheduler-summary.json').read_text())
                self.assertEqual(summary['nodes'][0]['blocked_wall_ns_by_wait_reason'],{'filemap_fault_io_schedule':2})
                events=json.loads(gzip.decompress((out/'perfetto-scheduler-block-1.json.gz').read_bytes()))['traceEvents']
                selected=[e for e in events if 'kernel_wait_reason' in e.get('args',{})]
                self.assertTrue(selected);self.assertTrue(all(e['args']['observed_kernel_wait_path']=='filemap_fault_io_schedule' for e in selected))
                self.assertIn('File-backed fault ancestry identifies a kernel path',(out/'scheduler.html').read_text())
            finally:report.close(captures)

    @unittest.skipUnless(os.environ.get('TEMPO_SCHEDULER_LIVE_TEST')=='1','requires local BPF/root and owned scratch')
    def test_live_production_fault_capture_exact_source_and_pruning(self):
        root=Path(__file__).parent
        # Explicit owned scratch avoids tmpfs-backed files that cannot demonstrate IO.
        scratch=os.environ.get('TEMPO_SCHEDULER_FAULT_SCRATCH')
        self.assertTrue(scratch)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            binary=Path(directory)/'synthetic'
            subprocess.run(['gcc','-O2','-pthread',str(root/'fault_path_probe/child.c'),'-o',str(binary)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            with (Path(directory)/'owned-data').open('xb+') as data,tempfile.TemporaryFile(dir=directory) as source:
                for _ in range(32):data.write(bytes([113])*1024**2)
                data.flush();os.fsync(data.fileno());origin=time.monotonic_ns()
                command=f'{shlex.quote(str(binary))} {data.fileno()} >/dev/null 2>&1'
                result=subprocess.run(['/usr/bin/python3',str(root/'binary_capture.py'),'--fault-reasons','--binary',str(binary),'--epoch','1','--command-base64',base64.b64encode(command.encode()).decode(),'--spool-fd',str(source.fileno()),'--scratch-dir',directory],pass_fds=(source.fileno(),data.fileno()),capture_output=True,timeout=40)
                self.assertEqual(result.returncode,0);self.assertFalse(result.stderr)
                evidence=footer(result.stdout);self.assertEqual(evidence['wait_reasons'],2);integrity(evidence,source)
                stamps=[r[0] for r in rows(source)];cutoff=max(stamps)-origin
                output=Path(directory)/'capture.json.gz'
                publish_streamed(output,source,directory,origin,cutoff,evidence['emitted'],META,probe_misses=evidence['probe_misses'],wait_reasons=2)
                decoded=json.loads(gzip.decompress(output.read_bytes()))
            report.validate(decoded,1,cutoff,'backpressure')
            self.assertTrue(decoded['registered_window_edges_complete'])
            self.assertGreater(decoded['quality']['at_or_post_cutoff_records_pruned'],0)
            positive=lambda role:{r['wait_reason'] for r in decoded['records'] if r['thread']==role and r.get('wait_status')==1}
            self.assertIn(6,positive(1));self.assertIn(2,positive(2));self.assertNotIn(6,positive(2))
            self.assertTrue(all(r['ts']<cutoff for r in decoded['records']))
            self.assertTrue(all(r['end']<cutoff for r in decoded['intervals']))

if __name__=='__main__':unittest.main()
