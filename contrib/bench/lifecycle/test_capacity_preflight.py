import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import capacity_preflight as probe


class CapacityPreflightTests(unittest.TestCase):
    def test_owned_write_cleanup_and_same_filesystem_ordinal(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'second').mkdir()
            (root/'existing').write_bytes(b'unchanged')
            filesystems={}
            rows=[probe.probe('workspace',root,filesystems), probe.probe('runner_temp',root/'second',filesystems)]
            self.assertTrue(all(row['writable'] and row['write_tested'] for row in rows))
            self.assertEqual(rows[0]['filesystem'],rows[1]['filesystem'])
            self.assertGreater(rows[0]['free_bytes'],0)
            self.assertNotIn(directory,json.dumps(rows))
            self.assertEqual(sorted(p.name for p in root.iterdir()),['existing','second'])
            self.assertEqual((root/'existing').read_bytes(),b'unchanged')
            self.assertFalse(list((root/'second').iterdir()))

    def test_missing_unset_relative_and_redirected_paths_do_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'link').symlink_to(root,target_is_directory=True)
            cases=[(None,'unset'),('', 'unset'),('relative','invalid_path'),(root/'missing','missing'),(root/'link','redirected')]
            with patch('capacity_preflight.os.write',side_effect=AssertionError('no write')):
                for path,status in cases:
                    self.assertEqual(probe.probe('optional_scratch',path,{})['status'],status)

    def test_readonly_access_denied_and_write_failure_are_explicit_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            capacity=SimpleNamespace(f_blocks=10,f_frsize=4096,f_bavail=3,f_flag=os.ST_RDONLY)
            with patch('capacity_preflight.os.fstatvfs',return_value=capacity),patch('capacity_preflight.os.write',side_effect=AssertionError('no write')):
                row=probe.probe('workspace',directory,{})
                self.assertEqual((row['status'],row['writable'],row['write_tested']),('read_only',False,False))
                self.assertEqual(row['free_bytes'],12288)
            with patch('capacity_preflight.os.access',return_value=False):
                row=probe.probe('workspace',directory,{})
                self.assertEqual((row['status'],row['write_tested']),('access_denied',False))
            with patch('capacity_preflight.os.write',side_effect=OSError('PRIVATE_NATIVE_PATH')):
                row=probe.probe('workspace',directory,{})
                self.assertEqual((row['status'],row['write_tested']),('write_failed',True))
                self.assertNotIn('PRIVATE',json.dumps(row))
            self.assertFalse(list(Path(directory).iterdir()))

    def test_cleanup_failure_is_reported_without_exception_text(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('capacity_preflight.os.unlink',side_effect=OSError('PRIVATE_PATH')):
                row=probe.probe('workspace',directory,{})
            self.assertEqual((row['status'],row['writable']),('cleanup_failed',None))
            self.assertNotIn('PRIVATE',json.dumps(row))
            # The only leftover is the test's own one-byte file; the outer temporary
            # directory fixture removes it after this assertion.
            files=list(Path(directory).iterdir())
            self.assertEqual(len(files),1)
            self.assertEqual(files[0].read_bytes(),b'\0')

    def test_exclusive_name_collision_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);name='.tempo-capacity-collision';(root/name).write_bytes(b'owned elsewhere')
            with patch('capacity_preflight.uuid.uuid4',return_value=SimpleNamespace(hex='collision')):
                row=probe.probe('workspace',root,{})
            self.assertEqual(row['status'],'write_failed')
            self.assertEqual((root/name).read_bytes(),b'owned elsewhere')

    def test_only_four_authorized_roles_and_environment_entries_are_read(self):
        with patch.dict(os.environ,{'GITHUB_WORKSPACE':'/PRIVATE_WORKSPACE','RUNNER_TEMP':'/PRIVATE_TEMP','SECRET':'PRIVATE_SECRET'}),patch('capacity_preflight.probe',side_effect=lambda role,path,devices:dict(role=role)) as call:
            result=probe.collect()
            self.assertEqual([c.args[:2] for c in call.call_args_list],list(zip(probe.ROLES,('/', '/PRIVATE_WORKSPACE','/PRIVATE_TEMP','/schelk'))))
            self.assertNotIn('PRIVATE',json.dumps(result))
            self.assertEqual(result['schema'],1)

    def test_distinct_native_devices_become_local_ordinals_only(self):
        with tempfile.TemporaryDirectory() as directory:
            native=os.stat(directory)
            devices={999999999:1}
            with patch('capacity_preflight.os.access',return_value=False):
                row=probe.probe('workspace',directory,devices)
            self.assertEqual(row['filesystem'],2 if native.st_dev!=999999999 else 1)
            self.assertNotIn('999999999',json.dumps(row))
            self.assertEqual(set(row),{'role','exists','filesystem','total_bytes','free_bytes','read_only','writable','write_tested','status'})


if __name__=='__main__':unittest.main()
