import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[3]
WORKFLOW=ROOT/'.github/workflows/bench-e2e.yml'
HELPER=Path(__file__).with_name('owned_capacity_inventory.py')

class WorkflowTests(unittest.TestCase):
    def test_closed_workflow_contract(self):
        self.assertEqual(WORKFLOW.read_bytes(), (ROOT/'.github/workflows/bench-owned-capacity.yml').read_bytes())
        d=yaml.safe_load(WORKFLOW.read_text());self.assertEqual(set(d['jobs']), {'inventory'});job=d['jobs']['inventory']
        self.assertEqual(d['permissions'],{'contents':'read'})
        self.assertEqual(job['strategy'],{'fail-fast':False,'max-parallel':5,'matrix':{'slot':[1,2,3,4,5]}})
        self.assertEqual(job['timeout-minutes'],5)
        self.assertEqual(len(job['steps']),2)
        self.assertIn('actions/github-script@',job['steps'][0]['uses'])
        self.assertIn('actions/upload-artifact@',job['steps'][1]['uses'])
        self.assertEqual(job['env']['INVENTORY_SOURCE_SHA256'],hashlib.sha256(HELPER.read_bytes()).hexdigest())
        for step in job['steps']:self.assertNotIn('run',step)
    def test_actual_javascript_helper_success_and_hash_rejection(self):
        job=yaml.safe_load(WORKFLOW.read_text())['jobs']['inventory'];script=job['steps'][0]['with']['script']
        driver=r'''
const fs=require('fs'), path=require('path');
const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
let outputs={}, failed=[], calls=0;
const core={setOutput:(k,v)=>outputs[k]=v,info:()=>{},setFailed:v=>failed.push(v)};
const source=fs.readFileSync(config.helper);
const github={rest:{repos:{getContent:async args=>{
 calls++;if(args.ref!==config.sha || args.path!=='contrib/bench/lifecycle/owned_capacity_inventory.py')throw Error('bad source request');
 return {data:{type:'file',encoding:'base64',size:source.length,content:source.toString('base64')}};
}}}};
(async()=>{
 await new (Object.getPrototypeOf(async function(){}).constructor)('require','github','context','core',config.script)(require,github,{repo:{owner:'owned',repo:'fixture'},sha:config.sha,runId:7},core);
 let report=outputs.path?JSON.parse(fs.readFileSync(outputs.path,'utf8')):null;
 console.log(JSON.stringify({calls,failed,report,output_inside_temp:outputs.path?outputs.path.startsWith(process.env.RUNNER_TEMP+'/tempo-owned-inventory-'):null}));
})().catch(()=>process.exit(2));
'''
        for valid in [True,False]:
            with self.subTest(valid=valid),tempfile.TemporaryDirectory() as tmp:
                t=Path(tmp);work=t/'workspace';work.mkdir();home=t/'home';home.mkdir();runtime=t/'runtime';runtime.mkdir()
                marker=work/'precious-existing';marker.write_bytes(b'unchanged')
                cfg=t/'input.json';cfg.write_text(json.dumps(dict(helper=str(HELPER),sha='a'*40,script=script)))
                js=t/'test.cjs';js.write_text(driver)
                env=dict(os.environ,GITHUB_WORKSPACE=str(work),RUNNER_TEMP=str(runtime),HOME=str(home),GITHUB_SHA='a'*40,GITHUB_RUN_ID='7',GITHUB_RUN_ATTEMPT='1',CAPACITY_SLOT='2',INVENTORY_SOURCE_SHA256=job['env']['INVENTORY_SOURCE_SHA256'] if valid else '0'*64)
                result=json.loads(subprocess.check_output(['node',str(js),str(cfg)],env=env))
                self.assertEqual(result['calls'],1);self.assertEqual(marker.read_bytes(),b'unchanged');self.assertEqual(list(work.iterdir()),[marker])
                if valid:
                    self.assertEqual(result['failed'],[]);self.assertTrue(result['output_inside_temp']);self.assertEqual(result['report']['slot'],2);self.assertEqual(result['report']['roots'][0]['counters']['files'],1)
                else:
                    self.assertEqual(result['failed'],['Owned capacity inventory unavailable; no benchmark or cleanup performed']);self.assertIsNone(result['report']);self.assertEqual(list(runtime.iterdir()),[])

if __name__=='__main__':unittest.main()
