import ctypes as C
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from binary_capture import PROGRAMS, miss_delta, prepare_native
from binary_transport import EVENT
from failures import failure_code
from spool import FOOTER, MAGIC, footer, integrity
from stream_decode import publish_streamed
from test_diagnostic import fixture
from test_runtime import example, report


class MissTests(unittest.TestCase):
    def test_counter_delta_rejects_unavailable_reset_or_wrong_program_set(self):
        self.assertEqual(miss_delta([1,2,3,4,5],[1,4,6,4,5]),5)
        self.assertEqual(miss_delta([0]*5,[0]*5),0)
        for initial,final in (([0]*4,[0]*5),([0]*5,[0]*4),([1]*5,[0]*5)):
            with self.assertRaises(ValueError):
                miss_delta(initial,final)
        with tempfile.TemporaryDirectory() as directory:
            native=prepare_native(directory)
            count=C.c_uint64(123)
            self.assertNotEqual(native.probe_misses(-1,C.byref(count)),0)
            self.assertEqual(count.value,123)

    def test_miss_cannot_hide_behind_matching_transport_counts(self):
        with tempfile.TemporaryFile() as source:
            source.write(EVENT.pack(1,1,0,0));source.flush()
            values=(1,1,0,0,0,0,1,10,1)
            counts=footer(FOOTER.pack(MAGIC,*values))
            with self.assertRaisesRegex(ValueError,'probe misses') as failure:
                integrity(counts,source)
            self.assertEqual(failure_code('decode',failure.exception),'decode_probe_misses')

    def test_schema2_requires_exact_zero_and_preserves_schema1_oracle(self):
        values=fixture()
        with tempfile.TemporaryDirectory() as directory,tempfile.TemporaryFile(dir=directory) as source:
            for row in values:source.write(EVENT.pack(*row))
            output=Path(directory)/'capture.json'
            publish_streamed(output,source,directory,0,50,len(values),{},probe_misses=0)
            capture=json.loads(output.read_text())
            self.assertEqual(capture['schema'],2)
            self.assertEqual(capture['quality']['probe_misses'],0)
            for bad in (1,-1,True,False,0.0):
                output.unlink(missing_ok=True)
                with self.assertRaises(ValueError):
                    publish_streamed(output,source,directory,0,50,len(values),{},probe_misses=bad)
                self.assertFalse(output.exists())
            with self.assertRaises(ValueError):
                publish_streamed(output,source,directory,0,50,len(values),{'schema':1},probe_misses=0)
        for value in (1,False,None):
            capture=example();capture['quality']['probe_misses']=value
            with self.assertRaises(ValueError):report.validate(capture,1,50,'backpressure')
        capture=example();del capture['quality']['probe_misses']
        with self.assertRaises(ValueError):report.validate(capture,1,50,'backpressure')

    def test_raw_probes_keep_actual_wakeup_boundary_and_check_native_read(self):
        source=(Path(__file__).parent/'scheduler.bpf.c.in').read_text()
        self.assertIn('RAW_TRACEPOINT_PROBE(sched_wakeup)',source)
        self.assertIn('RAW_TRACEPOINT_PROBE(sched_migrate_task)',source)
        self.assertNotIn('RAW_TRACEPOINT_PROBE(sched_waking)',source)
        self.assertIn('if(bpf_probe_read_kernel(&tid,sizeof(tid),&task->pid))',source)
        self.assertEqual(len(PROGRAMS),5)


if __name__=='__main__':unittest.main()
