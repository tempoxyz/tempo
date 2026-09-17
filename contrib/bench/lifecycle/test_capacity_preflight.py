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


class WorkflowTests(unittest.TestCase):
    def test_two_bounded_slots_and_unique_artifacts_without_benchmark_steps(self):
        workflow=Path(__file__).resolve().parents[3]/'.github/workflows/bench-e2e.yml'
        text=workflow.read_text()
        self.assertIn('max-parallel: 2',text)
        self.assertIn('slot: [1, 2]',text)
        self.assertIn('name: bench-capacity-${{ matrix.slot }}',text)
        self.assertIn('never merge this replacement into main',text)
        self.assertEqual(text.count('uses:'),2)
        self.assertNotIn('run:',text)
        self.assertNotIn('actions/checkout',text)

    def run_workflow_script(self, directory, report, stderr=''):
        import subprocess
        import textwrap
        workflow=Path(__file__).resolve().parents[3]/'.github/workflows/bench-e2e.yml'
        text=workflow.read_text()
        script=textwrap.dedent(text.split('          script: |\n',1)[1].split('      - name: Upload',1)[0])
        harness=r'''
const actualRequire=require;
const fs=require('fs');
const calls=[];const logs=[];const outputs=[];const failures=[];
const source='print("pinned source fixture")';
const context={sha:'a'.repeat(40),repo:{owner:'fixture',repo:'fixture'}};
const github={rest:{repos:{getContent:async input=>{calls.push(input);return {data:{type:'file',encoding:'base64',size:source.length,content:Buffer.from(source).toString('base64')}}}}}};
const core={info:value=>logs.push(value),setOutput:(key,value)=>outputs.push([key,value]),setFailed:value=>failures.push(value)};
const scopedRequire=name=>name==='child_process'?{spawnSync:(binary,args,options)=>{
 if(binary!=='python3'||args[0]!=='-I'||args[1]!=='-c'||args[2]!==source)throw Error('wrong pinned invocation');
 return {status:0,stderr:process.env.TEST_STDERR,stdout:process.env.TEST_REPORT};
}}:actualRequire(name);
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
(async()=>{await new AsyncFunction('require','github','context','core',process.env.TEST_SCRIPT)(scopedRequire,github,context,core);console.log(JSON.stringify({calls,logs,outputs,failures}));})().catch(()=>process.exit(2));
'''
        env={**os.environ,'GITHUB_WORKSPACE':str(directory),'TEST_SCRIPT':script,
             'TEST_REPORT':json.dumps(report),'TEST_STDERR':stderr}
        result=subprocess.run(['node','-e',harness],env=env,text=True,capture_output=True,check=True)
        return json.loads(result.stdout)

    def report(self):
        return dict(schema=1,locations=[dict(role=role,exists=True,filesystem=1,
            total_bytes=1000000,free_bytes=500000,read_only=False,writable=True,
            write_tested=True,status='writable') for role in probe.ROLES])

    def test_pinned_invocation_and_relative_artifact_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'existing').write_bytes(b'unchanged')
            result=self.run_workflow_script(root,self.report())
            self.assertFalse(result['failures'])
            self.assertEqual(result['calls'][0]['ref'],'a'*40)
            self.assertEqual(result['calls'][0]['path'],'contrib/bench/lifecycle/capacity_preflight.py')
            relative=Path(result['outputs'][0][1]);self.assertFalse(relative.is_absolute())
            self.assertEqual(json.loads((root/relative).read_text()),self.report())
            self.assertEqual((root/'existing').read_bytes(),b'unchanged')
            self.assertNotIn(directory,json.dumps(result))

    def test_unknown_report_metadata_and_private_stderr_never_publish(self):
        for malformed,stderr in [(dict(self.report(),hostname='PRIVATE_HOST'),''),
                                 (self.report(),'PRIVATE_NATIVE_PATH')]:
            with tempfile.TemporaryDirectory() as directory:
                result=self.run_workflow_script(Path(directory),malformed,stderr)
                self.assertEqual(len(result['failures']),1)
                self.assertFalse(result['outputs']);self.assertFalse(result['logs'])
                self.assertNotIn('PRIVATE',json.dumps(result))
                self.assertFalse(list(Path(directory).iterdir()))


if __name__=='__main__':unittest.main()
