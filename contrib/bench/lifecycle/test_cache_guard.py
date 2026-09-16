import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


@unittest.skipUnless(shutil.which('nu'), 'Nushell required')
class CacheGuardTests(unittest.TestCase):
    def run_build(self, available=62568, cache='hit', version=0, redirect=None, no_cache=False, root_available=None, paired=False):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); tools = root/'tools'; tools.mkdir()
            worktree = root/'worktree'; worktree.mkdir()
            second = root/'second-worktree'; second.mkdir()
            shared = root/'shared'; shared.mkdir(); (shared/'keep').write_text('keep')
            if redirect:
                (worktree/'target'/'profiling').mkdir(parents=True)
                target = worktree/'target' if redirect == 'target' else worktree/'target'/'profiling'/'tempo'
                if target.is_dir(): shutil.rmtree(target)
                target.symlink_to(shared if redirect == 'target' else shared/'keep')
            script = '''#!/usr/bin/env python3
import os,sys,json
from pathlib import Path
name=Path(sys.argv[0]).name
with open(os.environ['TEST_CALLS'],'a') as f:f.write(json.dumps([name,*sys.argv[1:]])+'\\n')
if name=='df':
 value=os.environ['TEST_ROOT_AVAILABLE'] if sys.argv[-1]=='/' else os.environ['TEST_AVAILABLE']
 print('Filesystem 1048576-blocks Used Available Capacity Mounted on')
 print('fixture 1000000 1 '+value+' 1% /fixture')
elif name=='mc':
 if sys.argv[1]=='stat':sys.exit(0 if os.environ['TEST_CACHE']=='hit' else 1)
 if sys.argv[1]=='cp' and sys.argv[2].startswith('minio/'):
  if os.environ['TEST_CACHE']!='hit':sys.exit(1)
  Path(sys.argv[3]).write_text('#!/bin/sh\\nprintf "verified\\n" >> "$TEST_VERIFIED"\\nexit '+os.environ['TEST_VERSION']+'\\n')
elif name=='cargo':pass
else:sys.exit(2)
'''
            for tool in ('df','mc','cargo'):
                path=tools/tool;path.write_text(script);path.chmod(0o755)
            calls=root/'calls';verified=root/'verified'
            env=dict(os.environ,PATH=str(tools)+os.pathsep+os.environ['PATH'],TEST_CALLS=str(calls),TEST_VERIFIED=str(verified),TEST_AVAILABLE=str(available),TEST_ROOT_AVAILABLE=str(root_available or available),TEST_CACHE=cache,TEST_VERSION=str(version),TEST_WORKTREE=str(worktree),TEST_SECOND=str(second))
            command='source tempo.nu; build-in-worktree --lifecycle-build --no-default-features '+('--no-cache ' if no_cache else '')+'$env.TEST_WORKTREE fixture profiling jemalloc,asm-keccak 0123456789abcdef; print accepted'
            if paired:
                command+='; build-in-worktree --lifecycle-build --no-default-features $env.TEST_SECOND fixture profiling jemalloc,asm-keccak fedcba9876543210'
            result=subprocess.run(['nu','--no-config-file','-c',command],cwd=ROOT,env=env,capture_output=True,text=True)
            return result, [json.loads(x) for x in calls.read_text().splitlines()] if calls.exists() else [], verified.read_text().count('verified') if verified.exists() else 0, (shared/'keep').read_text()

    def test_cache_hit_below_build_threshold_verifies_without_compiling(self):
        result,calls,verified,_=self.run_build()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(verified,1)
        self.assertFalse(any(c[0]=='cargo' for c in calls))
        self.assertIn(['mc','stat','minio/tempo-binaries/0123456789abcdef-no-default-jemalloc_asm-keccak/tempo'],calls)
        self.assertTrue(next(c for c in calls if c[:2]==['mc','cp'])[3].endswith('/target/profiling/tempo'))
        self.assertNotIn('65536 MiB required',result.stdout)

    def test_cache_miss_requires_full_build_headroom(self):
        for available,success in ((62568,False),(65536,True)):
            result,calls,verified,_=self.run_build(available,cache='miss')
            self.assertEqual(result.returncode==0,success,result.stderr)
            self.assertEqual(any(c[0]=='cargo' for c in calls),success)
            self.assertEqual(verified,0)
            self.assertIn('65536 MiB required',result.stdout)
            if success:
                cargo=next(c for c in calls if c[0]=='cargo')
                self.assertEqual(cargo,['cargo','build','--profile','profiling','--no-default-features','--features','jemalloc,asm-keccak','--bin','tempo'])

    def test_both_paired_binaries_use_exact_keys_and_are_verified(self):
        result,calls,verified,_=self.run_build(paired=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(verified,2)
        downloads=[c for c in calls if c[:2]==['mc','cp']]
        self.assertEqual(len(downloads),2)
        self.assertNotEqual(downloads[0][2],downloads[1][2])
        self.assertNotEqual(downloads[0][3],downloads[1][3])
        self.assertFalse(any(c[0]=='cargo' for c in calls))

    def test_invalid_cached_executable_is_not_a_cache_hit(self):
        result,calls,verified,_=self.run_build(version=1)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(verified,1)
        self.assertFalse(any(c[0]=='cargo' for c in calls))
        self.assertIn('65536 MiB required',result.stdout)

    def test_low_space_prevents_download_on_either_filesystem(self):
        for available,root_available in ((2708,2708),(65536,2708),(49151,65536)):
            result,calls,_,_=self.run_build(available,root_available=root_available)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(any(c[0] in ('mc','cargo') for c in calls))

    def test_redirected_target_or_binary_is_never_written(self):
        for redirect in ('target','binary'):
            result,calls,_,kept=self.run_build(redirect=redirect)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(any(c[0] in ('mc','cargo') for c in calls))
            self.assertEqual(kept,'keep')

    def test_no_cache_still_requires_build_headroom(self):
        result,calls,_,_=self.run_build(no_cache=True)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(c[0] in ('mc','cargo') for c in calls))
        self.assertIn('65536 MiB required',result.stdout)


if __name__=='__main__':unittest.main()
