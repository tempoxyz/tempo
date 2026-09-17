import base64
import ctypes as C
import os
from pathlib import Path
import subprocess
import time
import tempfile
import unittest

from binary_capture import prepare_native, program_for
from binary_transport import EVENT, HEADER, MAGIC, decode_binary
from diagnostic import decode
from test_diagnostic import fixture, stream


def packet(rows, **overrides):
    values = dict(collected=len(rows), emitted=len(rows), lost=0, invalid=0, overflow=0, status=0)
    values.update(overrides)
    return HEADER.pack(MAGIC, *values.values()) + b''.join(EVENT.pack(*row) for row in rows)


class BinaryTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('TEMPO_SCHEDULER_LIVE_TEST') == '1', 'requires local BPF/root capability')
    def test_live_stopped_child_complete_capture_and_strict_cutoff(self):
        root = Path(__file__).parent
        source = (root/'synthetic.c').read_text()
        source = (source.replace('void lifecycle_thread_register(uint64_t ordinal)',
                                 'void reth_lifecycle_thread_register(uint64_t ordinal,uint64_t epoch)')
                  .replace(': "r"(ordinal) :', ': "r"(ordinal), "r"(epoch) :')
                  .replace('lifecycle_thread_register((uintptr_t)opaque)', 'reth_lifecycle_thread_register((uintptr_t)opaque,1)')
                  .replace('lifecycle_thread_register(1)', 'reth_lifecycle_thread_register(1,1)'))
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory/'synthetic.c').write_text(source)
            binary = directory/'synthetic'
            built = subprocess.run(['gcc','-O3','-flto','-pthread',str(directory/'synthetic.c'),'-o',str(binary)], capture_output=True)
            self.assertEqual(built.returncode, 0)
            origin = time.monotonic_ns()
            result = subprocess.run(['sudo','-n','python3',str(root/'binary_capture.py'),
                '--binary',str(binary),'--epoch','1','--command-base64',base64.b64encode(str(binary).encode()).decode()],
                capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0)
            self.assertFalse(bool(result.stderr))
            stamps = [event[0] for event in EVENT.iter_unpack(result.stdout[HEADER.size:])]
            cutoff = (min(stamps)+max(stamps))//2-origin
            decoded = decode_binary(result.stdout,origin,cutoff,expected_threads={1,2,3})
            self.assertTrue(decoded['registered_window_edges_complete'])
            self.assertGreater(decoded['quality']['at_or_post_cutoff_records_pruned'],0)
            self.assertTrue(all(row['ts']<cutoff for row in decoded['records']))
            self.assertTrue(all(row['end']<cutoff for row in decoded['intervals']))

    def test_kernel_admission_is_one_incarnation_epoch_and_deletes_tid(self):
        source = program_for(123,456)
        self.assertIn('(native>>32)!=123', source)
        self.assertIn('PT_REGS_PARM2(ctx)!=456', source)
        self.assertIn('ordinals.delete(&tid)', source)
        self.assertIn('if((native>>32)==123&&tid==123)', source)
        self.assertIn('sealed.update(&zero,&one)', source)
        self.assertNotIn('printf', source)
        self.assertNotIn('comm', source)
        for identity, epoch in ((0,1),(2**32,1),(1,0),(1,2**64)):
            with self.assertRaises(ValueError):
                program_for(identity,epoch)

    def test_schema_cutoff_and_delivery_order_match_text(self):
        for rows in (fixture(), list(reversed(fixture()))):
            for cutoff in (10, 12, 20, 30, 50, 60, 71):
                with self.subTest(cutoff=cutoff):
                    self.assertEqual(decode_binary(packet(rows), 0, cutoff, expected_threads={1,2,3}),
                                     decode(stream(rows, cutoff), '', 0, 0))

    def test_no_loss_footer_can_be_overridden(self):
        for field in ('lost', 'invalid', 'overflow', 'status'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                decode_binary(packet(fixture(), **{field:1}), 0, 50)
        with self.assertRaisesRegex(ValueError, 'event loss'):
            decode_binary(packet(fixture(), emitted=len(fixture())+1), 0, 50)

    def test_malformed_or_private_output_is_never_echoed(self):
        for data in (b'PRIVATE_NATIVE_ID', packet(fixture())[:-1], packet(fixture())+b'\0',
                     packet(fixture(), collected=len(fixture())+1)):
            with self.assertRaises(ValueError) as caught:
                decode_binary(data, 0, 50)
            self.assertNotIn('PRIVATE_NATIVE_ID', str(caught.exception))

    def test_registration_exit_reuse_and_state_gates_preserved(self):
        rows = fixture()
        for malformed in (rows[1:], rows[:-1], rows+[(71,2,0,0)], rows+[(71,2,1,0)],
                          rows+[(4,1,1,512)], rows+[(4,0,1,0)], rows+[(4,1,6,0)]):
            with self.assertRaises(ValueError):
                decode_binary(packet(malformed), 0, 50)
        with self.assertRaisesRegex(ValueError, 'clock'):
            decode_binary(packet(rows), 5, 50)

    def test_missing_wakeup_and_unclosed_interval_remain_unavailable(self):
        for rows in ([r for r in fixture() if r[2]!=3],
                     [r for r in fixture() if not (r[1]==3 and r[2]==2)]):
            result = decode_binary(packet(rows), 0, 50)
            self.assertFalse(result['registered_window_edges_complete'])
            self.assertEqual(result, decode(stream(rows), '', 0, 0))

    def test_native_collector_bounds_schema_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            native = prepare_native(directory)
            native.allocate_capacity.argtypes = [C.c_size_t]
            native.allocate_capacity.restype = C.c_void_p
            native.collect.argtypes = [C.c_void_p, C.c_void_p, C.c_size_t]
            self.assertFalse(native.allocate_capacity(0))
            self.assertFalse(native.allocate_capacity(2**30))
            context = native.allocate_capacity(1)
            try:
                valid = EVENT.pack(15,2,1,256)
                native.collect(context, C.create_string_buffer(valid), len(valid))
                native.collect(context, C.create_string_buffer(valid), len(valid))
                for invalid in (b'PRIVATE_NATIVE_ID', EVENT.pack(15,0,1,0), EVENT.pack(15,1,0,1)):
                    native.collect(context, C.create_string_buffer(invalid), len(invalid))
                self.assertEqual([native.metric(context,i) for i in range(3)], [1,3,1])
                self.assertEqual(C.string_at(native.records(context),16), valid)
            finally:
                native.release(context)


if __name__=='__main__':
    unittest.main()
