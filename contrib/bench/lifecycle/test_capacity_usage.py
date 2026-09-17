import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

import capacity_preflight as probe
import capacity_usage as usage


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

    def run_workflow_script(self, directory, report, stderr='', actual_sources=False):
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
const sourceFor=input=>process.env.TEST_ACTUAL==='1'?(input.path.endsWith('capacity_usage.py')?process.env.TEST_USAGE:process.env.TEST_BASE):source;
const context={sha:'a'.repeat(40),repo:{owner:'fixture',repo:'fixture'}};
const github={rest:{repos:{getContent:async input=>{calls.push(input);const source=sourceFor(input);return {data:{type:'file',encoding:'base64',size:source.length,content:Buffer.from(source).toString('base64')}}}}}};
const core={info:value=>logs.push(value),setOutput:(key,value)=>outputs.push([key,value]),setFailed:value=>failures.push(value)};
const scopedRequire=name=>name==='child_process'?{spawnSync:(binary,args,options)=>{
 if(process.env.TEST_ACTUAL==='1')return actualRequire('child_process').spawnSync(binary,args,options);
 if(binary!=='python3'||args[0]!=='-I'||args[1]!=='-c'||!args[2].includes('types.ModuleType')||options.timeout!==210000)throw Error('wrong pinned invocation');
 return {status:0,stderr:process.env.TEST_STDERR,stdout:process.env.TEST_REPORT};
}}:actualRequire(name);
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
(async()=>{await new AsyncFunction('require','github','context','core',process.env.TEST_SCRIPT)(scopedRequire,github,context,core);console.log(JSON.stringify({calls,logs,outputs,failures}));})().catch(()=>process.exit(2));
'''
        env={**os.environ,'GITHUB_WORKSPACE':str(directory),'TEST_SCRIPT':script,
             'TEST_REPORT':json.dumps(report),'TEST_STDERR':stderr}
        if actual_sources:
            env['TEST_ACTUAL']='1'
            env['TEST_BASE']=Path(probe.__file__).read_text()
            env['TEST_USAGE']=Path(usage.__file__).read_text().replace('report = validate(collect())', 'report = validate(json.loads('+repr(json.dumps(report))+'))')
        result=subprocess.run(['node','-e',harness],env=env,text=True,capture_output=True,check=True)
        return json.loads(result.stdout)

    def report(self):
        return dict(schema=2,scratch_locations=[dict(role=role,status='missing',exists=False,filesystem=None,total_bytes=None,free_bytes=None,read_only=None,mountpoint=None,distinct_from_parent=None) for role in usage.SCRATCH_ROLES],per_category_timeout_ms=15000,total_usage_budget_ms=150000,usage=[dict(role=role,status='ok',allocated_bytes=100,filesystem=1,elapsed_ms=1,exclusions_applied=True) for role in usage.ROLES],locations=[dict(role=role,exists=True,filesystem=1,
            total_bytes=1000000,free_bytes=500000,read_only=False,writable=True,
            write_tested=True,status='writable') for role in probe.ROLES])

    def test_pinned_invocation_and_relative_artifact_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'existing').write_bytes(b'unchanged')
            result=self.run_workflow_script(root,self.report())
            self.assertFalse(result['failures'])
            self.assertEqual(result['calls'][0]['ref'],'a'*40)
            self.assertEqual([c['path'] for c in result['calls']],['contrib/bench/lifecycle/capacity_preflight.py','contrib/bench/lifecycle/capacity_usage.py'])
            self.assertTrue(all(c['ref']=='a'*40 for c in result['calls']))
            relative=Path(result['outputs'][0][1]);self.assertFalse(relative.is_absolute())
            self.assertEqual(json.loads((root/relative).read_text()),self.report())
            self.assertEqual((root/'existing').read_bytes(),b'unchanged')
            self.assertNotIn(directory,json.dumps(result))

    def test_actual_isolated_python_imports_pinned_helper_without_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            result=self.run_workflow_script(Path(directory),self.report(),actual_sources=True)
            self.assertFalse(result['failures'])
            self.assertEqual(json.loads((Path(directory)/result['outputs'][0][1]).read_text()),self.report())

    def test_unknown_report_metadata_and_private_stderr_never_publish(self):
        for malformed,stderr in [(dict(self.report(),hostname='PRIVATE_HOST'),''),
                                 (self.report(),'PRIVATE_NATIVE_PATH')]:
            with tempfile.TemporaryDirectory() as directory:
                result=self.run_workflow_script(Path(directory),malformed,stderr)
                self.assertEqual(len(result['failures']),1)
                self.assertFalse(result['outputs']);self.assertFalse(result['logs'])
                self.assertNotIn('PRIVATE',json.dumps(result))
                self.assertFalse(list(Path(directory).iterdir()))

class UsageTests(unittest.TestCase):
    def test_allocated_not_apparent_and_protected_tree_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with (root/'sparse').open('wb') as file:
                file.write(b'x');file.truncate(16*1024*1024)
            (root/'snapshot-private').mkdir();(root/'snapshot-private'/'large').write_bytes(b'a'*8192)
            (root/'link').symlink_to(root/'snapshot-private',target_is_directory=True)
            expected=sum(p.lstat().st_blocks*512 for p in (root,root/'sparse',root/'link'))
            with patch('capacity_usage.os.geteuid',return_value=0):
                row=usage.usage('workspace',root,time.monotonic()+30,{})
            self.assertEqual(row['status'],'ok');self.assertEqual(row['allocated_bytes'],expected)
            self.assertLess(row['allocated_bytes'],16*1024*1024)
            self.assertNotIn(directory,json.dumps(row))
            self.assertEqual((root/'snapshot-private'/'large').stat().st_size,8192)

    def test_guarded_roots_do_not_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'link').symlink_to(root,target_is_directory=True)
            (root/'file').touch()
            cases=[(None,'unset'),('/','invalid_path'),('relative','invalid_path'),('/mnt/virgin','protected'),('/home/snapshots/cache','protected'),(root/'missing','missing'),(root/'link','redirected'),(root/'file','not_directory')]
            with patch('capacity_usage.run_du',side_effect=AssertionError('must not execute')):
                for path,status in cases:
                    self.assertEqual(usage.usage('workspace',path,time.monotonic()+30,{})['status'],status)

    def test_total_budget_and_per_category_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('capacity_usage.run_du',return_value=('timeout',None)) as run:
                row=usage.usage('workspace',directory,time.monotonic()+100,{})
                self.assertEqual(row['status'],'timeout');self.assertEqual(run.call_args.args[1],15)
                usage.usage('workspace',directory,time.monotonic()+.1,{})
                self.assertLessEqual(run.call_args.args[1],.1)
                run.reset_mock()
                self.assertEqual(usage.usage('workspace',directory,time.monotonic()-1,{})['status'],'budget_exhausted')
                run.assert_not_called()

    def test_timeout_kills_only_owned_group_then_reaps(self):
        process=MagicMock(pid=123456,returncode=-9)
        process.communicate.side_effect=[subprocess.TimeoutExpired('PRIVATE',1),(b'',None)]
        with patch('capacity_usage.subprocess.Popen',return_value=process) as start,patch('capacity_usage.os.killpg') as kill,patch('capacity_usage.os.geteuid',return_value=0):
            self.assertEqual(usage.run_du(Path('/PRIVATE'),1),('timeout',None))
            kill.assert_called_once_with(123456,signal.SIGKILL)
            self.assertEqual(process.communicate.call_count,2)
            self.assertTrue(start.call_args.kwargs['start_new_session'])
            self.assertEqual(start.call_args.kwargs['stderr'],subprocess.DEVNULL)
            self.assertEqual(start.call_args.args[0][:3],['/usr/bin/timeout','--signal=KILL','1.000000s'])
            self.assertIn('--one-file-system',start.call_args.args[0]);self.assertIn('--no-dereference',start.call_args.args[0])

    def test_privileged_timeout_owns_du_deadline(self):
        process=MagicMock(returncode=137);process.communicate.return_value=(b'',None)
        with patch('capacity_usage.subprocess.Popen',return_value=process) as start,patch('capacity_usage.os.geteuid',return_value=1234),patch('capacity_usage.Path.is_file',return_value=True):
            self.assertEqual(usage.run_du(Path('/PRIVATE'),.05),('timeout',None))
            self.assertEqual(start.call_args.args[0][:7],['/usr/bin/sudo','-n','--','/usr/bin/timeout','--signal=KILL','0.050000s','/usr/bin/du'])

    def test_partial_or_malformed_du_never_becomes_size(self):
        for code,output in [(1,b'999\tPRIVATE\0'),(0,b'PRIVATE\0'),(0,b'1\tPRIVATE\0OTHER\0'),(0,b'9007199254740992\tPRIVATE\0')]:
            process=MagicMock(returncode=code);process.communicate.return_value=(output,None)
            with patch('capacity_usage.subprocess.Popen',return_value=process),patch('capacity_usage.os.geteuid',return_value=0):
                self.assertEqual(usage.run_du(Path('/PRIVATE'),1),('unavailable',None))

    def test_env_roles_only_and_shared_filesystem_ordinals(self):
        env=dict(HOME='/PRIVATE',RUNNER_TEMP='/work/_temp',GITHUB_WORKSPACE='/work/repo',CARGO_HOME='/cargo',SCCACHE_DIR='/cache',XDG_CACHE_HOME='/xdg',SECRET='DO_NOT_EXPORT')
        self.assertEqual(usage.paths(env),('/work','/work/_temp','/work/repo','/cargo/registry','/cargo/git','/xdg/sccache','/cache','/home','/var','/tmp','/opt','/usr'))
        self.assertIsNone(usage.paths({'RUNNER_TEMP':'/unusual'})[0])
        with tempfile.TemporaryDirectory() as directory,patch('capacity_usage.run_du',return_value=('ok',42)):
            devices={os.stat(directory).st_dev:1}
            row=usage.usage('workspace',directory,time.monotonic()+30,devices)
            self.assertEqual(row['filesystem'],1)

    def test_scratch_capacity_never_writes_or_traverses(self):
        with tempfile.TemporaryDirectory() as directory,patch('capacity_usage.os.write',side_effect=AssertionError('no write')),patch('capacity_usage.run_du',side_effect=AssertionError('no scan')):
            root=Path(directory);devices={root.stat().st_dev:1}
            row=usage.scratch_capacity('bench_scratch_a',root,devices)
            self.assertEqual(row['status'],'ok');self.assertEqual(row['filesystem'],1)
            self.assertFalse(row['distinct_from_parent']);self.assertFalse(row['mountpoint'])
            self.assertFalse(list(root.iterdir()))
            (root/'link').symlink_to(root,target_is_directory=True)
            self.assertEqual(usage.scratch_capacity('bench_scratch_b',root/'link',devices)['status'],'redirected')

    def test_closed_python_and_js_schemas_reject_identity_and_wrong_numbers(self):
        helper=WorkflowTests();base=helper.report();usage.validate(base)
        mutations=[]
        for key,value in [('native_path','PRIVATE'),('allocated_bytes',True),('elapsed_ms',-1),('status','PRIVATE'),('filesystem',99),('exclusions_applied',False)]:
            row=copy.deepcopy(base);row['usage'][0][key]=value;mutations.append(row)
        row=copy.deepcopy(base);row['usage'][0]['status']='timeout';mutations.append(row)
        row=copy.deepcopy(base);row['usage'].reverse();mutations.append(row)
        row=copy.deepcopy(base);row['hostname']='PRIVATE';mutations.append(row)
        for malformed in mutations:
            with self.assertRaises(AssertionError):usage.validate(malformed)
            with tempfile.TemporaryDirectory() as directory:
                result=helper.run_workflow_script(Path(directory),malformed)
                self.assertTrue(result['failures']);self.assertFalse(result['outputs']);self.assertFalse(result['logs'])
                self.assertNotIn('PRIVATE',json.dumps(result))

if __name__=='__main__':unittest.main()
