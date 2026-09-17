import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

HELPER=Path(__file__).with_name('bench-owned-install.py')
spec=importlib.util.spec_from_file_location('owned_install',HELPER)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class OwnedInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.workspace=self.root/'workspace';self.workspace.mkdir()
        self.bin=self.root/'bin';self.bin.mkdir();self.record=self.root/'record.json'
        self.existing=self.workspace/'.bench-txgen-install-existing';self.existing.mkdir();(self.existing/'keep').write_bytes(b'keep')
        self.env=dict(os.environ,PATH=str(self.bin)+':'+os.environ['PATH'],GITHUB_WORKSPACE=str(self.workspace),
            TEST_RECORD=str(self.record),RUSTFLAGS='-C target-cpu=native',CARGO_HOME=str(self.root/'shared-cargo'),
            RUSTUP_TOOLCHAIN='fixture',RUSTC_WRAPPER='sccache',RUSTC_WORKSPACE_WRAPPER='',SCCACHE_DIR=str(self.root/'shared-cache'),
            CARGO_INSTALL_ROOT=str(self.root/'installed'),CARGO_TARGET_DIR=str(self.root/'foreign-target'),
            CARGO_BUILD_BUILD_DIR=str(self.root/'foreign-build'))
        self.args=['install','--git','https://example.invalid/fixed','--locked','--rev','a'*40,'txgen-tempo','bench-cli']

    def fake(self,tail):
        source='''#!/usr/bin/python3
import json,os,sys,time,signal
from pathlib import Path
keys=['CARGO_TARGET_DIR','CARGO_BUILD_TARGET_DIR','CARGO_BUILD_BUILD_DIR','TMPDIR','TMP','TEMP','CARGO_HOME','CARGO_INSTALL_ROOT','RUSTFLAGS','RUSTUP_TOOLCHAIN','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','SCCACHE_DIR']
Path(os.environ['CARGO_TARGET_DIR'],'intermediate').write_bytes(b'owned target')
Path(os.environ['TMPDIR'],'temporary').write_bytes(b'owned temp')
Path(os.environ['TEST_RECORD']).write_text(json.dumps(dict(args=sys.argv[1:],env={k:os.environ[k] for k in keys})))
'''+tail
        cargo=self.bin/'cargo';cargo.write_text(source);cargo.chmod(0o700)

    def run_helper(self):
        return subprocess.run(['/usr/bin/python3',str(HELPER),*self.args],env=self.env,capture_output=True,text=True,timeout=15)

    def assert_clean(self):
        self.assertEqual(list(self.workspace.iterdir()),[self.existing])
        self.assertEqual((self.existing/'keep').read_bytes(),b'keep')
        self.assertFalse((self.root/'foreign-target').exists())
        self.assertFalse((self.root/'foreign-build').exists())

    def test_success_exact_args_and_build_settings_preserved(self):
        self.fake('sys.exit(0)\n');result=self.run_helper();self.assertEqual(result.returncode,0,result.stderr)
        record=json.loads(self.record.read_text());self.assertEqual(record['args'],self.args)
        for key in ('CARGO_HOME','CARGO_INSTALL_ROOT','RUSTFLAGS','RUSTUP_TOOLCHAIN','SCCACHE_DIR'):
            self.assertEqual(record['env'][key],self.env[key])
        self.assertEqual(record['env']['RUSTC_WRAPPER'],'')
        self.assertEqual(record['env']['RUSTC_WORKSPACE_WRAPPER'],'')
        self.assertEqual(record['env']['CARGO_TARGET_DIR'],record['env']['CARGO_BUILD_BUILD_DIR'])
        self.assertEqual(record['env']['TMPDIR'],record['env']['TEMP'])
        self.assertTrue(Path(record['env']['CARGO_TARGET_DIR']).is_relative_to(self.workspace))
        self.assert_clean()

    def test_failure_cleanup_after_reaping_orphan_compiler(self):
        self.fake('''read,write=os.pipe()
pid=os.fork()
if pid==0:
 os.close(read);signal.signal(signal.SIGTERM,signal.SIG_IGN);os.write(write,b'1');os.close(write)
 time.sleep(60);os._exit(0)
os.close(write);os.read(read,1);os.close(read);sys.exit(7)
''')
        result=self.run_helper();self.assertEqual(result.returncode,7,result.stderr);self.assert_clean()

    def test_cancel_reaps_owned_group_before_cleanup(self):
        self.fake('signal.signal(signal.SIGTERM,signal.SIG_IGN)\ntime.sleep(60)\n')
        process=subprocess.Popen(['/usr/bin/python3',str(HELPER),*self.args],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+5
            while not self.record.exists() and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(self.record.exists());process.send_signal(signal.SIGTERM)
            out,err=process.communicate(timeout=12)
            self.assertEqual(process.returncode,130,err);self.assert_clean()
        finally:
            if process.poll() is None:process.kill();process.wait()

    def test_redirected_workspace_refused_without_execution(self):
        link=self.root/'link';link.symlink_to(self.workspace,target_is_directory=True)
        self.env['GITHUB_WORKSPACE']=str(link);self.fake('sys.exit(0)\n')
        result=self.run_helper();self.assertEqual(result.returncode,1);self.assertFalse(self.record.exists());self.assert_clean()
        self.assertNotIn(str(self.root),result.stderr)

    def test_exclusive_collision_never_removes_foreign_directory(self):
        with patch.object(module,'subreaper'),patch.object(module.uuid,'uuid4',return_value=type('Value',(),{'hex':'existing'})()):
            with self.assertRaises(FileExistsError):module.install(str(self.workspace),self.args)
        self.assert_clean()

    def test_owned_root_replacement_refuses_cleanup(self):
        self.fake('''target=Path(os.environ['CARGO_TARGET_DIR']).parent
renamed=target.with_name('preserved-original')
target.rename(renamed)
target.symlink_to(Path(os.environ['TEST_RECORD']).parent,target_is_directory=True)
sys.exit(0)
''')
        result=self.run_helper();self.assertEqual(result.returncode,1)
        self.assertTrue(self.record.exists());self.assertTrue((self.workspace/'preserved-original'/'target'/'intermediate').exists())
        self.assertNotIn(str(self.root),result.stderr)

    def test_cache_wrapper_not_invoked_or_given_owned_temp(self):
        wrapper=self.bin/'sccache';wrapper.write_text('#!/bin/sh\nexit 99\n');wrapper.chmod(0o700)
        self.env['RUSTC_WRAPPER']=str(wrapper)
        self.fake("assert not os.environ['RUSTC_WRAPPER'] and not os.environ['RUSTC_WORKSPACE_WRAPPER']\nsys.exit(0)\n")
        result=self.run_helper();self.assertEqual(result.returncode,0,result.stderr);self.assert_clean()

    def test_custom_environment_or_cargo_config_wrapper_refused(self):
        self.fake('sys.exit(0)\n')
        for key in ('RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_RUSTC_WRAPPER'):
            previous=self.env.get(key);self.env[key]='custom-codegen'
            result=self.run_helper();self.assertEqual(result.returncode,1);self.assertFalse(self.record.exists())
            if previous is None:self.env.pop(key)
            else:self.env[key]=previous
        cargo=Path(self.env['CARGO_HOME']);cargo.mkdir()
        (cargo/'config.toml').write_text('[build]\nrustc-wrapper="custom-codegen"\n')
        result=self.run_helper();self.assertEqual(result.returncode,1);self.assertFalse(self.record.exists());self.assert_clean()
        (cargo/'config.toml').write_text('[build]\nrustc-wrapper="sccache"\n')
        result=self.run_helper();self.assertEqual(result.returncode,0,result.stderr);self.assert_clean()

    def test_workflow_changes_only_install_invocation(self):
        root=HELPER.parents[2]
        text=(root/'.github/workflows/bench-e2e.yml').read_text()
        self.assertIn('python3 .github/scripts/bench-owned-install.py install "${install_args[@]}" txgen-tempo bench-cli',text)
        self.assertIn('install_args=(--git "$TXGEN_GIT_URL" --locked)',text)
        self.assertIn('install_args+=(--rev "${TXGEN_REV:-$BENCH_TXGEN_REF}")',text)
        self.assertNotIn('sccache --stop-server',text)

if __name__=='__main__':unittest.main()
