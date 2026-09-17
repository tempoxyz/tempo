import ctypes as C
import json
import gzip
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from binary_capture import prepare_native
from binary_transport import EVENT, decode_binary
from failures import failure_summary
from spool import FOOTER, MAGIC, footer, integrity, rows, sorted_rows
from stream_decode import publish_streamed
from test_binary_transport import packet
from test_diagnostic import fixture


class SpoolTests(unittest.TestCase):
    def test_external_sort_is_stable_across_levels_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as name, tempfile.TemporaryFile(dir=name) as source:
            values = [(i % 7, i + 1, 0, 0) for i in range(500)]
            for row in values:
                source.write(EVENT.pack(*row))
            with patch('spool.CHUNK_RECORDS', 3), patch('spool.MERGE_FAN_IN', 2):
                self.assertEqual(list(sorted_rows(source,name)), sorted(values,key=lambda r:r[0]))
            self.assertFalse(list(Path(name).iterdir()))

    def test_streamed_output_matches_original_all_cutoffs_order_and_gaps(self):
        for values in (fixture(), list(reversed(fixture())), [r for r in fixture() if r[2] != 3],
                       [r for r in fixture() if not(r[1]==3 and r[2]==2)]):
            for cutoff in range(1,73):
                with self.subTest(cutoff=cutoff), tempfile.TemporaryDirectory() as name, tempfile.TemporaryFile(dir=name) as source:
                    for row in values:
                        source.write(EVENT.pack(*row))
                    output=Path(name)/'result.json'
                    with patch('spool.CHUNK_RECORDS',3),patch('spool.MERGE_FAN_IN',2):
                        kept,pruned=publish_streamed(output,source,name,0,cutoff,len(values),{})
                    actual=json.loads(output.read_text())
                    self.assertEqual(actual,decode_binary(packet(values),0,cutoff))
                    self.assertEqual((kept,pruned),(len(actual['records']),len(values)-len(actual['records'])))

    def test_gzip_schema_determinism_and_publication_budget_cleanup(self):
        values=fixture()
        with tempfile.TemporaryDirectory() as name,tempfile.TemporaryFile(dir=name) as source:
            for row in values:
                source.write(EVENT.pack(*row))
            first=Path(name)/'first.json.gz'; second=Path(name)/'second.json.gz'
            for output in (first,second):
                publish_streamed(output,source,name,0,50,len(values),{})
            self.assertEqual(first.read_bytes(),second.read_bytes())
            self.assertEqual(first.read_bytes()[3:8],b'\0'*5)  # no filename flag or wall-clock mtime
            self.assertEqual(json.loads(gzip.decompress(first.read_bytes())),decode_binary(packet(values),0,50))
            for field in ('SOURCE_BYTES','COMPRESSED_SOURCE_BYTES'):
                output=Path(name)/'failure.json.gz'
                with patch('stream_decode.'+field,10),self.assertRaisesRegex(ValueError,'limit exceeded'):
                    publish_streamed(output,source,name,0,50,len(values),{})
                self.assertFalse(output.exists())
                self.assertFalse(output.with_suffix('.partial').exists())

    def test_rejection_and_preexisting_partial_are_atomic(self):
        values=fixture()
        for malformed in (values[1:],values[:-1],values+[(71,2,0,0)],values+[(71,2,1,0)],
                          values+[(4,1,1,512)],values+[(4,0,1,0)],values+[(4,1,6,0)]):
            with tempfile.TemporaryDirectory() as name, tempfile.TemporaryFile(dir=name) as source:
                for row in malformed:
                    source.write(EVENT.pack(*row))
                output=Path(name)/'result.json'
                with self.assertRaises(ValueError):
                    publish_streamed(output,source,name,0,50,len(malformed),{})
                self.assertFalse(list(Path(name).iterdir()))
        with tempfile.TemporaryDirectory() as name,tempfile.TemporaryFile(dir=name) as source:
            for row in values:
                source.write(EVENT.pack(*row))
            output=Path(name)/'result.json'
            output.with_suffix('.partial').write_bytes(b'owned elsewhere')
            with self.assertRaises(FileExistsError):
                publish_streamed(output,source,name,0,50,len(values),{})
            self.assertEqual(output.with_suffix('.partial').read_bytes(),b'owned elsewhere')
            self.assertFalse(output.exists())

    def test_footer_counts_and_numeric_failure_evidence_are_closed(self):
        values=dict(retained=1,emitted=1,lost=0,invalid=0,overflow=0,io_error=0,received=1,observed_duration_ns=5,probe_misses=0)
        with tempfile.TemporaryDirectory() as name,tempfile.TemporaryFile(dir=name) as source:
            source.write(EVENT.pack(1,1,0,0));source.flush()
            self.assertEqual(footer(FOOTER.pack(MAGIC,*values.values())),values)
            integrity(values,source)
            for key in ('lost','invalid','overflow','io_error','probe_misses'):
                with self.assertRaises(ValueError):
                    integrity(dict(values,**{key:1}),source)
            directory=Path(name)
            (directory/'scheduler-a.evidence.json').write_text(json.dumps(values))
            self.assertIn('emitted=1',' '.join(failure_summary(directory)))
            for poisoned in (dict(values,private='PRIVATE'),dict(values,emitted='PRIVATE'),dict(values,emitted=True)):
                (directory/'scheduler-a.evidence.json').write_text(json.dumps(poisoned))
                summary=' '.join(failure_summary(directory))
                self.assertNotIn('PRIVATE',summary)
                self.assertNotIn('numeric capture evidence',summary)

    def test_native_batch_flush_named_fd_rejection_and_write_failure(self):
        with tempfile.TemporaryDirectory() as name:
            native=prepare_native(name)
            native.collect.argtypes=[C.c_void_p,C.c_void_p,C.c_size_t]
            valid=EVENT.pack(15,2,1,256)
            with tempfile.TemporaryFile(dir=name) as source:
                self.assertFalse(os.get_inheritable(source.fileno()))
                self.assertEqual(os.fstat(source.fileno()).st_nlink,0)
                context=native.allocate(source.fileno())
                try:
                    for _ in range(4097):
                        native.collect(context,C.create_string_buffer(valid),16)
                    self.assertEqual(os.fstat(source.fileno()).st_size,65536)
                    native.finalize(context)
                    self.assertEqual(os.fstat(source.fileno()).st_size,4097*16)
                    self.assertEqual(native.metric(context,3),0)
                finally:
                    native.release(context)
            with (Path(name)/'named').open('w+b') as source:
                self.assertFalse(native.allocate(source.fileno()))
            # Read-only anonymous inode: admission succeeds, writes must fail
            # closed without losing the already captured numeric evidence.
            with tempfile.TemporaryFile(dir=name) as source:
                readonly=os.open(f'/proc/self/fd/{source.fileno()}',os.O_RDONLY)
                try:
                    context=native.allocate(readonly)
                    native.collect(context,C.create_string_buffer(valid),16)
                    native.finalize(context)
                    self.assertEqual(native.metric(context,3),1)
                    self.assertEqual(native.metric(context,0),1)
                    native.release(context)
                finally:
                    os.close(readonly)


if __name__=='__main__':
    unittest.main()
