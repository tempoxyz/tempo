import copy
import gzip
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from diagnostic import decode, marker_call, marker_slots
from failures import CODES, REASONS, failure_code
from runtime import failure_summary, final_cutoff, program_for, publish_capture
from test_diagnostic import fixture, stream
# Avoid confusing this module with the parent lifecycle report module.
spec = importlib.util.spec_from_file_location('scheduler_report', Path(__file__).with_name('report.py'))
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


def example(process=1):
    capture = decode(stream(fixture()), '', 0, 0)
    capture.update(scope='registered validator thread windows only', process=process,
                   cutoff_reason='backpressure', registration='registered_threads_v1')
    return capture


class RuntimeTests(unittest.TestCase):
    def test_capture_is_visible_only_after_complete_serialization(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name)/'scheduler-a.json'
            original_dump = json.dump
            def slow_dump(value, destination, **kwargs):
                self.assertFalse(output.exists())
                original_dump(value, destination, **kwargs)
                destination.flush()
                self.assertFalse(output.exists())
            with patch('runtime.json.dump', side_effect=slow_dump):
                publish_capture(output, {'complete':True})
            self.assertEqual(json.loads(output.read_text()), {'complete':True})
            self.assertFalse(output.with_suffix('.partial').exists())
            output.with_suffix('.partial').write_text('pre-existing private capture')
            with self.assertRaises(FileExistsError):
                publish_capture(output, {})
            self.assertEqual(output.with_suffix('.partial').read_text(), 'pre-existing private capture')
            output.with_suffix('.partial').unlink()
            output.unlink()
            with patch('runtime.json.dump', side_effect=OSError('private details')):
                with self.assertRaises(OSError):
                    publish_capture(output, {})
            self.assertFalse(output.exists())
            self.assertFalse(output.with_suffix('.partial').exists())

    def test_marker_verifies_direct_or_exact_relocated_indirect_call(self):
        symbols = '00001000 T marker\n00002000 T other\n'
        relocations = '00003000 00000008 R_X86_64_RELATIVE 1000\n00004000 00000008 R_X86_64_RELATIVE 2000\n'
        slots = marker_slots(symbols, relocations, 'marker')
        self.assertEqual(slots, {0x3000})
        self.assertTrue(marker_call(' call 1000 <marker>', 'marker', slots))
        self.assertTrue(marker_call(' call *0x42(%rip) # 3000 <_GLOBAL_OFFSET_TABLE_+0x18>', 'marker', slots))
        for line in ('1000 <marker>:', ' call 2000 <other>', ' call *0x42(%rip) # 4000', ' mov 0x42(%rip),%rax # 3000', ' call *%rax'):
            with self.subTest(line=line):
                self.assertFalse(marker_call(line, 'marker', slots))
        self.assertEqual(marker_slots(symbols, relocations, 'missing'), set())

    def test_failure_summary_never_echoes_untrusted_contents(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory/'scheduler-a.failed').write_text('marker\n')
            (directory/'scheduler-b.failed').write_text('native identity or arbitrary command\n')
            self.assertEqual(failure_summary(directory), [
                'Scheduler validator a: startup/capture failure category marker',
                'Scheduler validator b: startup/capture failure category unavailable'])

    def test_failure_codes_are_closed_and_stage_specific(self):
        for (stage, message), expected in REASONS.items():
            self.assertEqual(failure_code(stage, ValueError(message)), expected)
            self.assertIn(expected, CODES)
        self.assertEqual(failure_code('decode', ValueError('private native identity')), 'decode')
        self.assertEqual(failure_code('publish', ValueError('missing switch-in')), 'publish')
        self.assertEqual(failure_code('untrusted stage', OSError('private command')), 'unavailable')

    def test_kernel_loss_line_rejects_even_with_matching_footer(self):
        with self.assertRaisesRegex(ValueError, 'event loss') as failure:
            decode(stream(fixture()) + '\nLost 1 events\n', '', 0, 0)
        self.assertEqual(failure_code('decode', failure.exception), 'decode_event_loss')

    def test_shutdown_failure_exposes_only_closed_categories(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory/'scheduler-a.failed').write_text('decode_missing_switch_in\n')
            (directory/'scheduler-b.failed').write_text('decode_missing_switch_in private identity\n')
            with self.assertRaises(ValueError) as failure:
                report.load(directory, directory, {}, timeout=0)
            self.assertIn('category decode_missing_switch_in', str(failure.exception))
            self.assertIn('category unavailable', str(failure.exception))
            self.assertNotIn('private identity', str(failure.exception))

    def test_source_cutoff_uses_earliest_final_stream_boundary(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            for role, timestamp in [('a',30),('b',20)]:
                (directory/f'{role}.jsonl').write_text(json.dumps({'type':'event','ts':timestamp,'fields':{'stage':'backpressure_start'}})+'\n'+json.dumps({'type':'footer','dropped':0,'io_error':False})+'\n')
            (directory/'window.json').write_text(json.dumps({'end_ns':99,'backpressure':{'ts':30}}))
            self.assertEqual(final_cutoff(directory), (20,'backpressure'))

    def test_missing_footer_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaisesRegex(ValueError, 'footer'):
                final_cutoff(Path(name), timeout=0)

    def test_dropped_lifecycle_capture_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            (Path(name)/'a.jsonl').write_text('{"type":"footer","dropped":1}\n')
            with self.assertRaisesRegex(ValueError, 'integrity'):
                final_cutoff(Path(name), timeout=0)

    def test_program_admits_only_child_epoch_and_keys_process_thread(self):
        program = program_for(Path('/fixture/binary'), 123)
        self.assertIn('/pid == cpid && @alive[cpid] && arg1 == 123/', program)
        self.assertIn('@ordinal[cpid, tid]=arg0', program)
        self.assertIn('delete(@ordinal[cpid, tid])', program)
        self.assertIn('if(pid == cpid && tid == cpid) { delete(@alive[cpid]); }', program)
        self.assertNotIn('lifecycle_cutoff', program)
        self.assertNotIn('comm', program)

    def test_schema_and_cutoff_validate(self):
        capture = example()
        self.assertEqual(report.validate(capture,1,50,'backpressure'), capture)
        for mutation in ('native_id','cutoff','at_cutoff','beyond_cutoff','endpoint_at_cutoff','overlap'):
            bad=copy.deepcopy(capture)
            if mutation=='native_id':bad['native_pid']=123
            elif mutation=='cutoff':bad['cutoff_ns']=51
            elif mutation=='at_cutoff':bad['records'][0]['ts']=50
            elif mutation=='beyond_cutoff':bad['intervals'][0]['end']=51
            elif mutation=='endpoint_at_cutoff':bad['intervals'][0]['end']=50
            elif mutation=='overlap':bad['intervals'].append(bad['intervals'][0])
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                report.validate(bad,1,50,'backpressure')

    def test_process_namespaces_and_focus_clipping_are_explicit(self):
        events = report.scheduler_events([example(1),example(2)], 0, .005, .025)
        slices = [e for e in events if e['ph']=='X']
        self.assertEqual({e['pid'] for e in slices}, {101,102})
        self.assertTrue(any(e['args']['focus_clipped_start'] for e in slices))
        self.assertTrue(any(e['args']['focus_clipped_end'] for e in slices))
        self.assertTrue(all('does not establish block causality' in e['args']['association'] for e in slices))
        self.assertTrue(all(e['ts']>=.005 and e['ts']+e['dur']<=.025 for e in slices))

    def test_application_reference_requires_registration(self):
        with tempfile.TemporaryDirectory() as name:
            path=Path(name)/'a.jsonl'
            path.write_text('{"thread":7,"ts":10}\n')
            with self.assertRaisesRegex(ValueError,'registration missing'):
                report.source_registration(path,example())
            path.write_text('{"thread":2,"ts":1}\n')
            self.assertEqual(report.source_registration(path,example()),
                             {'source_events_before_registration':1,'maximum_registration_gap_ns':1})

    def test_both_captures_validate_before_either_is_published(self):
        with tempfile.TemporaryDirectory() as name:
            directory=Path(name)/'private';out=Path(name)/'artifact'
            directory.mkdir();out.mkdir()
            for role,process in [('a',1),('b',2)]:
                (directory/f'scheduler-{role}.json.gz').write_bytes(gzip.compress(json.dumps(example(process)).encode(),mtime=0))
                (out/f'{role}.jsonl').write_text('{"type":"header","scheduler":"registered_threads_v1"}\n')
            bad=example(2);bad['native_tid']=123
            (directory/'scheduler-b.json.gz').write_bytes(gzip.compress(json.dumps(bad).encode(),mtime=0))
            with self.assertRaises(ValueError):
                report.load(directory,out,{'backpressure':{'ts':50}})
            self.assertFalse((out/'scheduler-a.json.gz').exists())
            (directory/'scheduler-b.json.gz').write_bytes(gzip.compress(json.dumps(example(2)).encode(),mtime=0))
            captures,coverage=report.load(directory,out,{'backpressure':{'ts':50}})
            self.assertEqual(len(captures),2)
            self.assertEqual(coverage[0]['source_events_before_registration'],0)
            self.assertTrue((out/'scheduler-a.json.gz').exists())
            report.close(captures)

    def test_report_uses_same_actual_percentile_block_and_preserves_original_trace(self):
        with tempfile.TemporaryDirectory() as name:
            out=Path(name)
            original={'traceEvents':[{'name':'operation','ph':'X','pid':1,'tid':1,'ts':.006,'dur':.010}]}
            (out/'perfetto-block-7.json').write_text(json.dumps(original))
            (out/'index.html').write_text('<h1>Lifecycle</h1>')
            data={'time_origin_ns':0,'blocks':[{'id':7,'start':.000005,'end':.000025}],
                  'representatives':{'50':7,'90':7,'99':7},'bad_capture':False}
            coverage=[{'source_events_before_registration':0,'maximum_registration_gap_ns':0}]*2
            report.publish(data,[example(1),example(2)],out,coverage)
            summary=json.loads((out/'scheduler-summary.json').read_text())
            self.assertEqual({p['block'] for p in summary['percentiles']},{7})
            trace=json.loads(gzip.decompress((out/'perfetto-scheduler-block-7.json.gz').read_bytes()))
            self.assertEqual(trace['traceEvents'][0],original['traceEvents'][0])
            self.assertEqual(json.loads((out/'perfetto-block-7.json').read_text()),original)
            self.assertIn('scheduler.html',(out/'index.html').read_text())

    def test_after_cutoff_source_reference_not_required(self):
        with tempfile.TemporaryDirectory() as name:
            path=Path(name)/'a.jsonl'
            path.write_text('{"thread":7,"ts":50}\n')
            self.assertEqual(report.source_registration(path,example())['source_events_before_registration'],0)


if __name__=='__main__':
    unittest.main()
