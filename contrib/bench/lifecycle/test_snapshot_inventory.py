import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import yaml
import snapshot_inventory as m

ROOT = Path(__file__).resolve().parents[3]


class Inventory(unittest.TestCase):
    def fixture(self, root):
        roots=[]
        for side in ('a','b'):
            mount=root/side;mount.mkdir()
            state=root/(side+'.json')
            state.write_text(json.dumps(dict(is_mounted=True,mount_point=str(mount),dm_era_name='PRIVATE-'+side)))
            for name in m.REQUIRED:
                p=mount/m.DATASET/name;p.parent.mkdir(parents=True,exist_ok=True);p.touch()
            roots.append((state,mount))
        return roots

    def test_exact_required_vocabulary_and_bloat_conversion(self):
        source=(ROOT/'bench-e2e.nu').read_text()
        self.assertIn('($bloat_mib)mb',source)
        # Execute the harness conversion instead of repeating the inventory's assumption.
        conversion = 'def e2e-bloat-gib-to-mib ' + source.split('def e2e-bloat-gib-to-mib ', 1)[1].split('\ndef ', 1)[0]
        run = subprocess.run(['nu', '--no-config-file', '-c', conversion + '\ne2e-bloat-gib-to-mib 100 | to json'], capture_output=True, text=True, check=True)
        self.assertEqual(m.DATASET, f'tempo_e2e_{json.loads(run.stdout)}mb')
        self.assertIn('const BENCH_META_SUBDIR = ".bench-meta"',(ROOT/'tempo.nu').read_text())
        for name in m.REQUIRED:
            self.assertIn(name.split('/')[-1],source.split('def e2e-snapshot-required-files',1)[1].split('\ndef ',1)[0])

    def test_complete_masks_and_closed_state_no_contents(self):
        with tempfile.TemporaryDirectory() as d:
            roots=self.fixture(Path(d))
            with patch.object(m,'mounted',return_value=1):result=m.inspect(roots)
            self.assertTrue(result['dm_names_distinct'])
            for side in result['sides']:
                self.assertEqual(side['required']['present'],511)
                self.assertEqual(side['required']['readable'],511)
                self.assertEqual(side['state']['status'],0)
                self.assertTrue(side['state_observation_unchanged'])
            self.assertNotIn('PRIVATE',json.dumps(result));self.assertNotIn(d,json.dumps(result))

    def test_missing_denied_and_symlink_are_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);roots=self.fixture(root);data=roots[0][1]/m.DATASET
            (data/'signing.key').unlink();(data/'enode.key').unlink();(data/'enode.key').symlink_to('/does-not-exist')
            original=m.parent_fd
            def denied(path):
                if path.name=='signing.share':raise PermissionError()
                return original(path)
            with patch.object(m,'parent_fd',side_effect=denied):result=m.path_masks(data)
            self.assertEqual(result['missing'],1<<3)
            self.assertEqual(result['denied'],1<<4)
            self.assertEqual(result['unsafe'],1<<5)

    def test_state_missing_invalid_bool_duplicates_oversize_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);state=root/'state';mount=root/'mount'
            self.assertEqual(m.state(state,mount)[0]['status'],1)
            for data in [dict(is_mounted=1),dict(is_mounted=False,mount_point='/foreign')]:
                state.write_text(json.dumps(data));self.assertEqual(m.state(state,mount)[0]['status'],3)
            for data in ['{"is_mounted":true,"is_mounted":false}', ' '*65537]:
                state.write_text(data);self.assertEqual(m.state(state,mount)[0]['status'],3)
            state.unlink();state.symlink_to('/does-not-exist');self.assertEqual(m.state(state,mount)[0]['status'],3)

    def test_state_and_mount_changes_are_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            roots=self.fixture(Path(d))
            with patch.object(m,'mounted',side_effect=[0,1,1,1]):result=m.inspect(roots)
            self.assertFalse(result['sides'][0]['mount_observation_unchanged'])
            self.assertFalse(result['snapshot_atomic'])

    def test_mount_failure_is_unknown_not_unmounted(self):
        for code,expected in [(0,1),(32,0),(1,2),(127,2)]:
            with patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],code)):
                self.assertEqual(m.mounted(Path('/private')),expected)
        with patch.object(m.subprocess,'run',side_effect=subprocess.TimeoutExpired([],5)):
            self.assertEqual(m.mounted(Path('/private')),2)

    def test_workflow_actual_scripts_success_failure_privacy_cleanup(self):
        workflow=yaml.safe_load((ROOT/'.github/workflows/bench-e2e.yml').read_text())
        job=workflow['jobs']['inventory'];steps=job['steps']
        self.assertEqual(job['strategy']['matrix']['slot'],[1,2,3,4,5])
        self.assertIn('always()',steps[-1]['if'])
        self.assertEqual(job['env']['INVENTORY_SOURCE_SHA256'],hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory() as d:
            roots=self.fixture(Path(d))
            with patch.object(m,'mounted',return_value=1):view=m.inspect(roots)
            for mode in ['ok','command_failure','private_field','foreign_file']:
                with self.subTest(mode=mode):
                    self.node_fixture(steps,job['env'],view,mode)

    def node_fixture(self,steps,env,view,mode):
        with tempfile.TemporaryDirectory() as d:
            code='''
const fs=require('fs'),path=require('path'),cp=require('child_process');
const input=JSON.parse(fs.readFileSync(0,'utf8')),outputs={};let failed=0,cleanFail=0;
process.env.RUNNER_TEMP=input.directory;process.env.INVENTORY_SOURCE_SHA256=input.hash;
process.env.GITHUB_RUN_ATTEMPT='1';process.env.INVENTORY_SLOT='1';
const context={repo:{owner:'tempoxyz',repo:'tempo'},sha:'a'.repeat(40),runId:123};
const github={rest:{repos:{getContent:async()=>({data:{type:'file',encoding:'base64',size:Buffer.byteLength(input.source),content:Buffer.from(input.source).toString('base64')}})}}};
const core={setOutput:(k,v)=>outputs[k]=v,info:()=>{},setFailed:()=>failed++};
cp.spawnSync=(command,args)=>{
 if(input.mode==='command_failure')return {status:1,stdout:'PRIVATE',stderr:'PRIVATE'};
 if(command==='nu')return {status:0,stdout:'true'};
 if(args.includes('/bin/sh'))return {status:0,stdout:''};
 const value=structuredClone(input.view);value.privileged=command==='sudo';
 if(input.mode==='private_field')value.private='SECRET';
 return {status:0,stdout:JSON.stringify(value)};
};
(async()=>{
 await new (Object.getPrototypeOf(async function(){}).constructor)('require','process','context','github','core',input.gather)(require,process,context,github,core);
 if(input.mode==='ok' && (failed || !outputs.path))throw Error('success rejected');
 if(['command_failure','private_field'].includes(input.mode) && (!failed || outputs.path))throw Error('failure accepted');
 if(outputs.path){const raw=fs.readFileSync(outputs.path,'utf8');if(raw.includes('PRIVATE')||raw.includes('SECRET'))throw Error('privacy');}
 if(input.mode==='foreign_file')fs.writeFileSync(path.join(outputs.directory,'foreign'),'keep');
 process.env.INVENTORY_DIRECTORY=outputs.directory;process.env.INVENTORY_OWNER=outputs.owner;
 core.setFailed=()=>cleanFail++;
 await new (Object.getPrototypeOf(async function(){}).constructor)('require','process','core',input.cleanup)(require,process,core);
 if(input.mode==='foreign_file'){if(!cleanFail || !fs.existsSync(path.join(outputs.directory,'foreign')))throw Error('foreign deletion');}
 else if(cleanFail || fs.existsSync(outputs.directory))throw Error('cleanup');
})().catch(()=>{process.exitCode=1});
'''
            data=dict(directory=d,hash=env['INVENTORY_SOURCE_SHA256'],source=Path(m.__file__).read_text(),
                      gather=steps[0]['with']['script'],cleanup=steps[-1]['with']['script'],view=view,mode=mode)
            run=subprocess.run(['node','-e',code],input=json.dumps(data),capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)


if __name__=='__main__':unittest.main()
