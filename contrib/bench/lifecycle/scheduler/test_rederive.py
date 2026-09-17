import copy
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import rederive
from diagnostic import decode_records
from test_running_wake import VALID, rows


class RederivationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);(self.root/'original').mkdir()
        self.source=self.root/'original/scheduler-a.json.gz';self.dest=self.root/'derived'
        self.capture=decode_records(copy.deepcopy(VALID),[12],[len(VALID)+1],expected_threads={1},cutoff_ns=None)
        self.capture.update(schema=2,scope='registered validator thread windows only',process=1,
            cutoff_reason='backpressure',registration='registered_threads_v1')
        self.capture['quality']['probe_misses']=0
        self.write()

    def write(self):
        self.source.write_bytes(gzip.compress(json.dumps(self.capture).encode(),mtime=0))
        self.digest=rederive.file_hash(self.source)

    def run_derive(self,**changes):
        args=dict(source_sha256=self.digest,exporter_sha='1'*40,process=1,cutoff=12,reason='backpressure')
        args.update(changes)
        return rederive.rederive(self.source,self.dest,**args)

    def test_verified_arrays_original_untouched_and_external_provenance(self):
        before=self.source.read_bytes()
        original_check=rederive.independent_arrays
        def checked(path):
            self.assertFalse(self.dest.exists())
            return original_check(path)
        with patch.object(rederive,'independent_arrays',side_effect=checked):
            provenance=self.run_derive()
        output=self.dest/'capture/scheduler-a.json.gz'
        derived=json.loads(gzip.decompress(output.read_bytes()))
        self.assertEqual(self.source.read_bytes(),before)
        self.assertEqual(derived['records'],self.capture['records'])
        self.assertEqual(derived['intervals'],self.capture['intervals'])
        self.assertEqual(derived['quality']['wakeups_while_running'],2)
        self.assertEqual(derived['quality']['unmatched_wakeups'],0)
        self.assertEqual(provenance['original_quality']['unmatched_wakeups'],2)
        self.assertEqual(provenance['source_sha256'],self.digest)
        self.assertEqual(provenance['output_sha256'],rederive.file_hash(output))
        self.assertEqual(set(p.name for p in (self.dest/'capture').iterdir()),{'scheduler-a.json.gz'})
        self.assertEqual(json.loads((self.dest/'provenance.json').read_text()),provenance)
        self.assertFalse(list(self.root.glob('.scheduler-derive-*')))

    def test_identity_destination_and_source_location_refuse(self):
        with self.assertRaises(ValueError):self.run_derive(source_sha256='0'*64)
        with self.assertRaises(ValueError):self.run_derive(process=2)
        with self.assertRaises(ValueError):self.run_derive(cutoff=12.0)
        with self.assertRaises(ValueError):self.run_derive(reason='private value')
        self.dest.mkdir();(self.dest/'owned').write_text('preserve')
        with self.assertRaises(ValueError):self.run_derive()
        self.assertEqual((self.dest/'owned').read_text(),'preserve')
        self.dest=self.source.parent/'new-derived'
        with self.assertRaises(ValueError):self.run_derive()
        self.assertFalse(self.dest.exists())

    def test_missing_edge_and_residual_duplicate_reject(self):
        for records in ([r for r in VALID if r['ts']!=7],VALID[:4]+rows([(8,'wakeup',0)])+VALID[4:]):
            self.capture.update(decode_records(copy.deepcopy(records),[12],[len(records)+1],expected_threads={1},cutoff_ns=None))
            self.capture.update(schema=2,scope='registered validator thread windows only')
            self.capture['quality']['probe_misses']=0;self.write()
            with self.assertRaises(ValueError):self.run_derive()
            self.assertFalse(self.dest.exists())

    def test_wrong_original_count_and_probe_evidence_reject(self):
        for key,value in [('unmatched_wakeups',3),('probe_misses',1),('registered_threads',0)]:
            with self.subTest(key=key):
                original=self.capture['quality'][key];self.capture['quality'][key]=value;self.write()
                with self.assertRaises(ValueError):self.run_derive()
                self.assertFalse(self.dest.exists())
                self.capture['quality'][key]=original

    def test_corrupt_gzip_with_matching_file_hash_rejects(self):
        blob=bytearray(self.source.read_bytes());blob[-8]^=1
        self.source.write_bytes(blob);self.digest=rederive.file_hash(self.source)
        with self.assertRaises((OSError,ValueError)):self.run_derive()
        self.assertFalse(self.dest.exists())

    def test_source_change_between_passes_cannot_publish(self):
        actual=rederive.read_capture
        calls=0
        def changed(path,sink):
            nonlocal calls
            result=actual(path,sink);calls+=1
            if calls==1:
                self.capture['quality']['at_or_post_cutoff_records_pruned']+=1
                self.write()
            return result
        with patch.object(rederive,'read_capture',side_effect=changed):
            with self.assertRaises(ValueError):self.run_derive()
        self.assertFalse(self.dest.exists())
        self.assertFalse(list(self.root.glob('.scheduler-derive-*')))

    def test_independent_readback_mismatch_prevents_publication(self):
        actual=rederive.independent_arrays
        def mismatched(path):
            metadata,arrays=actual(path);arrays['records']['sha256']='0'*64
            return metadata,arrays
        with patch.object(rederive,'independent_arrays',side_effect=mismatched):
            with self.assertRaises(ValueError):self.run_derive()
        self.assertFalse(self.dest.exists())
        self.assertFalse(list(self.root.glob('.scheduler-derive-*')))

    def test_late_destination_collision_is_not_replaced(self):
        actual=rederive.independent_arrays
        def collide(path):
            result=actual(path);self.dest.mkdir();return result
        with patch.object(rederive,'independent_arrays',side_effect=collide):
            with self.assertRaises(OSError):self.run_derive()
        self.assertTrue(self.dest.is_dir());self.assertEqual(list(self.dest.iterdir()),[])
        self.assertFalse(list(self.root.glob('.scheduler-derive-*')))


if __name__=='__main__':unittest.main()
