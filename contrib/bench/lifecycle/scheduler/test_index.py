import json
import gzip
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_runtime
from index import read_capture, CaptureIndex
from test_runtime import report, example


class IndexTests(unittest.TestCase):
    def test_stream_parser_and_index_match_list_capture_at_every_boundary(self):
        capture=example()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source.json'
            path.write_text(json.dumps(capture,separators=(',',':')))
            for chunk in (1,7,64*1024):
                with patch('index.CHUNK',chunk):
                    actual=report.indexed_capture(path,directory,1,capture['cutoff_ns'],'backpressure')
                try:
                    self.assertEqual(list(actual['records']),capture['records'])
                    self.assertEqual(list(actual['intervals']),capture['intervals'])
                    self.assertEqual(actual['records'].registrations(),{r['thread']:r['ts'] for r in capture['records'] if r['kind']=='register'})
                    for low in range(0,50):
                        for high in (low+1,50):
                            expected=report.scheduler_events([capture],0,low/1000,high/1000)
                            indexed=report.scheduler_events([actual],0,low/1000,high/1000)
                            canonical=lambda rows:sorted(json.dumps(r,sort_keys=True) for r in rows)
                            self.assertEqual(canonical(indexed),canonical(expected))
                finally:
                    report.close([actual])
                self.assertEqual([p.name for p in Path(directory).iterdir()],['source.json'])

    def test_gzip_reader_preserves_exact_rows(self):
        capture=example()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source.json.gz'
            path.write_bytes(gzip.compress(json.dumps(capture).encode(),mtime=0))
            indexed=report.indexed_capture(path,directory,1,capture['cutoff_ns'],'backpressure')
            try:
                self.assertEqual(list(indexed['records']),capture['records'])
                self.assertEqual(list(indexed['intervals']),capture['intervals'])
            finally:
                report.close([indexed])

    def test_index_page_cap_rejects_without_hiding_source(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as directory:
            owner=CaptureIndex(directory)
            try:
                owner.db.execute('PRAGMA max_page_count=4')
                with self.assertRaises(sqlite3.DatabaseError):
                    for i in range(10000):
                        owner.add('records',{'ts':i,'thread':1,'kind':'migration','state_bits':0})
            finally:
                owner.close()
            self.assertFalse(list(Path(directory).iterdir()))

    def test_parser_rejects_duplicate_keys_giant_values_truncation_and_unknown_rows(self):
        capture=example()
        encoded=json.dumps(capture)
        cases=(encoded[:-1],encoded+'PRIVATE',encoded[:-1]+',"records":[]}',
               encoded.replace('"thread": 1','"thread": 1,"thread": 1',1),
               encoded.replace('"records": [','"records": ["'+('x'*5000)+'",',1),
               encoded.replace('"ts": 1','"ts": 50000',1))
        for malformed in cases:
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'source.json'
                path.write_text(malformed)
                with self.assertRaises((ValueError,TypeError)):
                    report.indexed_capture(path,directory,1,capture['cutoff_ns'],'backpressure')
                self.assertEqual([p.name for p in Path(directory).iterdir()],['source.json'])


if __name__=='__main__':
    unittest.main()
