import copy
import json
import gzip
from pathlib import Path
import tempfile
import unittest

from diagnostic import decode_records, KINDS
from stream_decode import decode_stream, publish_streamed
from binary_transport import EVENT
from test_runtime import report

CODES = {name: code for code, name in KINDS.items()}


def rows(events):
    return [dict(ts=t, thread=1, kind=kind, state_bits=bits) for t, kind, bits in events]


VALID = rows([(1,'register',0), (3,'wakeup',0), (5,'switch_out',1),
              (7,'wakeup',0), (9,'switch_in',0), (10,'wakeup',0), (11,'exit',0)])


class RunningWakeTests(unittest.TestCase):
    def both(self, events, cutoff=12, corrected=True):
        legacy = decode_records(copy.deepcopy(events), [cutoff], [len(events)+1],
            expected_threads={1}, cutoff_ns=None, classify_running_wakes=corrected)
        kept, intervals = [], []
        streamed, count = decode_stream(
            [(e['ts'],e['thread'],CODES[e['kind']],e['state_bits']) for e in events],
            0, cutoff, len(events), kept.append, lambda *args: intervals.append(args),
            expected_threads={1}, classify_running_wakes=corrected)
        self.assertEqual(legacy['quality'], streamed['quality'])
        self.assertEqual(legacy['registered_window_edges_complete'], streamed['registered_window_edges_complete'])
        self.assertEqual(legacy['records'], kept)
        return legacy

    def test_kernel_running_wake_preserves_every_record_and_interval(self):
        old, new = self.both(VALID,corrected=False), self.both(VALID)
        self.assertFalse(old['registered_window_edges_complete'])
        self.assertTrue(new['registered_window_edges_complete'])
        self.assertEqual(new['quality']['wakeups_while_running'],2)
        self.assertEqual(new['quality']['unmatched_wakeups'],0)
        self.assertEqual(new['records'],old['records'])
        self.assertEqual(new['intervals'],old['intervals'])
        self.assertNotIn('wakeups_while_running',old['quality'])

    def test_strict_cutoff_keeps_running_wake_counter_precise(self):
        result=self.both(VALID,cutoff=10)
        self.assertEqual(result['quality']['wakeups_while_running'],1)
        self.assertTrue(all(r['ts']<10 for r in result['records']))
        self.assertTrue(all(r['end']<10 for r in result['intervals']))

    def test_duplicate_off_cpu_wake_remains_incomplete(self):
        duplicate=VALID[:4]+rows([(8,'wakeup',0)])+VALID[4:]
        result=self.both(duplicate)
        self.assertFalse(result['registered_window_edges_complete'])
        self.assertEqual(result['quality']['unmatched_wakeups'],1)
        self.assertEqual(result['quality']['wakeups_while_running'],2)

    def test_missing_sleep_wake_and_boundaries_are_not_excused(self):
        result=self.both([e for e in VALID if e['ts']!=7])
        self.assertEqual(result['quality']['unclassified_off_cpu_intervals'],1)
        self.assertFalse(result['registered_window_edges_complete'])
        for missing in (1,5,11):
            with self.subTest(missing=missing),self.assertRaises(ValueError):
                self.both([e for e in VALID if e['ts']!=missing])

        missing_in=self.both([e for e in VALID if e['ts']!=9])
        self.assertFalse(missing_in['registered_window_edges_complete'])
        self.assertEqual(missing_in['quality']['unclosed_intervals_excluded'],1)

    def test_runtime_load_accepts_schema3_with_identical_source_rows(self):
        with tempfile.TemporaryDirectory() as name:
            directory=Path(name)/'private';out=Path(name)/'artifact'
            directory.mkdir();out.mkdir()
            for process,role in enumerate(('a','b'),1):
                capture=self.both(VALID)
                capture.update(schema=3,scope='registered validator thread windows only',
                    process=process,cutoff_reason='backpressure',registration='registered_threads_v1')
                capture['quality']['probe_misses']=0
                (directory/f'scheduler-{role}.json.gz').write_bytes(gzip.compress(json.dumps(capture).encode(),mtime=0))
                (out/f'{role}.jsonl').write_text('{"type":"header","scheduler":"registered_threads_v1"}\n')
            captures,coverage=report.load(directory,out,{'backpressure':{'ts':12}})
            try:
                self.assertEqual([c['schema'] for c in captures],[3,3])
                self.assertEqual([c['quality']['wakeups_while_running'] for c in captures],[2,2])
                self.assertEqual(list(captures[0]['records']),VALID)
                self.assertEqual((directory/'scheduler-a.json.gz').read_bytes(),(out/'scheduler-a.json.gz').read_bytes())
            finally:
                report.close(captures)
            # Old load admission required the same schema on both validators.
            old=self.both(VALID,corrected=False)
            old.update(schema=2,scope='registered validator thread windows only',
                process=2,cutoff_reason='backpressure',registration='registered_threads_v1')
            old['quality']['probe_misses']=0
            (directory/'scheduler-b.json.gz').write_bytes(gzip.compress(json.dumps(old).encode(),mtime=0))
            for role in ('a','b'):(out/f'scheduler-{role}.json.gz').unlink()
            with self.assertRaises(ValueError):
                report.load(directory,out,{'backpressure':{'ts':12}})
            self.assertFalse((out/'scheduler-a.json.gz').exists())

    def test_schema3_exact_quality_and_legacy_read_compatibility(self):
        with tempfile.TemporaryDirectory() as directory,tempfile.TemporaryFile() as raw:
            for e in VALID:raw.write(EVENT.pack(e['ts'],1,CODES[e['kind']],e['state_bits']))
            path=Path(directory)/'scheduler.json'
            metadata=dict(scope='registered validator thread windows only',process=1,
                          cutoff_reason='backpressure',registration='registered_threads_v1')
            publish_streamed(path,raw,directory,0,12,len(VALID),metadata,probe_misses=0)
            result=json.loads(path.read_text())
            self.assertEqual(result['schema'],3)
            report.validate(result,1,12,'backpressure')
            for bad in (True,-1,None):
                changed=copy.deepcopy(result);changed['quality']['wakeups_while_running']=bad
                with self.assertRaises(ValueError):report.validate(changed,1,12,'backpressure')
            for schema in (1,2):
                old=self.both(VALID,corrected=False);old.update(metadata,schema=schema)
                if schema==2:old['quality']['probe_misses']=0
                report.validate(old,1,12,'backpressure')
                self.assertFalse(old['registered_window_edges_complete'])


if __name__=='__main__':unittest.main()
