import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('inventory',Path(__file__).with_name('owned_capacity_inventory.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def test_counts_closed_roles_and_retains_every_byte(self):
        files={'target/private-name':b'x'*9000,'.bench-worktrees/secret/deps/y':b'z'*5000,
               'bench-results/private-run/lifecycle/feature-1.zip':b'a'*100,
               'bench-results/private-run/lifecycle/baseline-1/lifecycle.json':b'{}',
               'bench-results/private-run/lifecycle-raw/feature-2/a.jsonl':b'{}',
               'bench-results/private-run/logs-baseline-2-a/private.log':b'secret',
               'localnet/signing.key':b'NEVER READ CONTENT'}
        for name,data in files.items():
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        before={k:(self.root/k).read_bytes() for k in files}
        r=m.scan(self.root,'workspace',classify=True)
        self.assertEqual(r['status'],'complete_no_follow');self.assertEqual(r['counters']['files'],7)
        self.assertEqual(set(r['categories']),{'checkout_target','build_worktrees','retained_results','localnet'})
        self.assertEqual(set(r['result_runs'][0]['phases']),{'feature-1:archive','baseline-1:expanded_report','feature-2:raw_capture','baseline-2:copied_logs'})
        self.assertFalse(r['exclusive_task_ownership_proven'])
        out=json.dumps(r)
        for secret in ['private-name','private-run','private.log','signing.key','NEVER READ CONTENT',str(self.root)]:self.assertNotIn(secret,out)
        self.assertEqual(before,{k:(self.root/k).read_bytes() for k in files})
    def test_symlinks_and_fifo_are_never_followed(self):
        (self.root/'outside').mkdir();(self.root/'outside'/'secret').write_bytes(b'x'*123)
        work=self.root/'work';work.mkdir();(work/'redirect').symlink_to(self.root/'outside',target_is_directory=True);os.mkfifo(work/'pipe')
        r=m.scan(work,'workspace');self.assertEqual(r['counters']['files'],0);self.assertEqual(r['counters']['symlinks_skipped'],1);self.assertEqual(r['counters']['special_files_skipped'],1);self.assertEqual(r['status'],'partial')
        self.assertEqual(m.scan(work/'redirect','workspace')['status'],'redirected_or_relative')
    def test_hardlinks_deduplicate_in_each_category(self):
        (self.root/'target').mkdir();f=self.root/'target'/'a';f.write_bytes(b'x'*9000);os.link(f,self.root/'target'/'b')
        r=m.scan(self.root,'workspace',classify=True);self.assertEqual(r['counters']['files'],1);self.assertEqual(r['counters']['hardlinks_deduplicated'],1);self.assertEqual(r['categories']['checkout_target']['files'],1)
    def test_bounds_and_missing_never_claim_zero_complete(self):
        for i in range(4):(self.root/str(i)).write_bytes(b'x')
        r=m.scan(self.root,'workspace',limit=2);self.assertEqual(r['status'],'partial');self.assertEqual(r['entries_examined'],2)
        self.assertEqual(m.scan(self.root/'missing','workspace')['status'],'missing')
        self.assertEqual(m.scan(self.root,'workspace',seconds=0)['status'],'partial')
    def test_binding_and_arbitrary_cache_path_is_ignored(self):
        temp=self.root/'temp';temp.mkdir();home=self.root/'home';home.mkdir()
        env=dict(GITHUB_WORKSPACE=str(self.root),RUNNER_TEMP=str(temp),HOME=str(home),GITHUB_SHA='a'*40,GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1',CAPACITY_SLOT='5',SCCACHE_DIR='/')
        r=m.collect(env);self.assertEqual(r['slot'],5);self.assertFalse(r['roots'][-1]['active_cache_location_confirmed']);self.assertEqual(r['roots'][-1]['status'],'missing');self.assertFalse(r['cleanup_authorized'])
        env['CAPACITY_SLOT']='6'
        with self.assertRaises(ValueError):m.collect(env)

if __name__=='__main__':unittest.main()
