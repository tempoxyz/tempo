import copy
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from index import DiskRows, RecordSummary
from test_fault_reasons import capture
from test_runtime import report


def source(directory, schema, process=1):
    value, path = capture(directory, process)
    value['schema'] = schema
    if schema == 4:
        value['wait_reasons']['mode'] = 'kernel_stacks_v1'
        for row in value['records'] + value['intervals']:
            if row.get('wait_reason') == 6:
                row['wait_reason'] = 2
    elif schema == 3:
        value.pop('wait_reasons')
        for row in value['records'] + value['intervals']:
            row.pop('wait_reason', None)
            row.pop('wait_status', None)
    path.write_bytes(gzip.compress(json.dumps(value).encode(), mtime=0))
    return value, path


class SummaryIndexTests(unittest.TestCase):
    def test_default_rows_and_explicit_summary_keep_counts_registration_and_intervals(self):
        for schema in (3, 4, 5):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as directory:
                expected, path = source(directory, schema)
                original = path.read_bytes()
                for retain in (True, False):
                    indexed = report.indexed_capture(path, directory, 1, 10, 'backpressure', retain_records=retain)
                    try:
                        rows = indexed['records']
                        self.assertIsInstance(rows, DiskRows if retain else RecordSummary)
                        self.assertEqual(len(rows), len(expected['records']))
                        self.assertEqual(rows.registrations(), {1: 1})
                        changed = rows.registrations(); changed[1] = 99
                        self.assertEqual(rows.registrations(), {1: 1})
                        self.assertEqual(list(indexed['intervals']), expected['intervals'])
                        tables = {r[0] for r in indexed['intervals'].owner.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                        self.assertEqual(tables, {'records', 'intervals'} if retain else {'intervals'})
                        if retain:
                            self.assertEqual(list(rows), expected['records'])
                            report.validate(indexed, 1, 10, 'backpressure')
                        else:
                            with self.assertRaisesRegex(TypeError, 'not retained'):
                                list(rows)
                            with self.assertRaisesRegex(ValueError, 'invalid scheduler rows'):
                                report.validate(indexed, 1, 10, 'backpressure')
                    finally:
                        report.close([indexed])
                    self.assertEqual(path.read_bytes(), original)
                    self.assertFalse(list(Path(directory).glob('.scheduler-index-*')))

    def test_load_and_published_files_are_byte_identical_for_all_modes(self):
        for schema in (3, 4, 5):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory() as directory:
                private = Path(directory)/'private'; private.mkdir()
                for process, role in enumerate(('a', 'b'), 1):
                    _, path = source(private, schema, process)
                    path.rename(private/f'scheduler-{role}.json.gz')
                originals = {p.name: p.read_bytes() for p in private.iterdir()}
                outputs = []
                for retain in (True, False):
                    out = Path(directory)/str(retain); out.mkdir()
                    for role in ('a', 'b'):
                        (out/f'{role}.jsonl').write_text('{"type":"header","scheduler":"registered_threads_v1"}\n{"thread":1,"ts":2}\n')
                    captures, coverage = report.load(private, out, {'backpressure': {'ts':10}}, retain_records=retain)
                    try:
                        self.assertEqual(coverage, [{'source_events_before_registration':0, 'maximum_registration_gap_ns':0}]*2)
                        for block in (1, 2):
                            (out/f'perfetto-block-{block}.json').write_text('{"traceEvents":[{"name":"fixture","ph":"i","ts":0.002}],"displayTimeUnit":"ns"}')
                        (out/'index.html').write_text('<h1>Lifecycle</h1>')
                        data = {'time_origin_ns':0, 'blocks':[{'id':1,'start':0,'end':.00001}, {'id':2,'start':.000002,'end':.000008}], 'representatives':{'50':1,'90':2,'99':2}, 'bad_capture':False}
                        report.publish(data, captures, out, coverage)
                    finally:
                        report.close(captures)
                    outputs.append({p.name:p.read_bytes() for p in out.iterdir()})
                self.assertEqual(outputs[0], outputs[1])
                self.assertEqual({p.name:p.read_bytes() for p in private.iterdir()}, originals)
                for name, content in originals.items():
                    self.assertEqual(outputs[1][name], content)

    def test_malformed_sources_reject_identically_and_cleanup(self):
        for schema in (3, 4, 5):
            with tempfile.TemporaryDirectory() as directory:
                valid, path = source(directory, schema)
                cases = []
                bad = copy.deepcopy(valid); bad['records'][1]['ts'] = 10; cases.append(bad)
                bad = copy.deepcopy(valid); bad['records'].append(copy.deepcopy(bad['records'][0])); cases.append(bad)
                bad = copy.deepcopy(valid); bad['intervals'][0]['end'] = 10; cases.append(bad)
                bad = copy.deepcopy(valid); bad['quality']['event_loss_detected'] = True; cases.append(bad)
                if schema >= 4:
                    bad = copy.deepcopy(valid); bad['wait_reasons']['sampled'] += 1; cases.append(bad)
                    bad = copy.deepcopy(valid); bad['records'][1]['wait_reason'] = 6 if schema == 4 else 7; cases.append(bad)
                malformed = [gzip.compress(json.dumps(case).encode(),mtime=0) for case in cases]
                malformed.append(gzip.compress(json.dumps(valid).encode(),mtime=0)[:-5])
                for encoded in malformed:
                    path.write_bytes(encoded)
                    errors = []
                    for retain in (True, False):
                        with self.assertRaises((ValueError, EOFError)) as caught:
                            report.indexed_capture(path, directory, 1, 10, 'backpressure', retain_records=retain)
                        errors.append((type(caught.exception), str(caught.exception)))
                        self.assertFalse(list(Path(directory).glob('.scheduler-index-*')))
                        self.assertEqual(path.read_bytes(), encoded)
                    self.assertEqual(errors[0], errors[1])


if __name__ == '__main__':
    unittest.main()
