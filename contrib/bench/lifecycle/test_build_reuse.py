"""Exercise the actual Nu build/selection path without compiling or launching nodes."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


@unittest.skipUnless(shutil.which('nu'), 'Nushell required')
class BuildReuseTests(unittest.TestCase):
    def run_plan(self, *, enabled=True, no_cache=False, feature=None, sides=2, revision=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for side in ('baseline', 'feature'):
                (root / side).mkdir()
            a = dict(label='baseline', sha=revision or 'a'*40, features='jemalloc,asm-keccak',
                     extra_rustflags='', bench_features='jemalloc,asm-keccak', wt=str(root/'baseline'))
            b = {**a, 'label':'feature', 'wt':str(root/'feature'), **(feature or {})}
            builds = [a, b][:sides]
            source = (ROOT/'bench-e2e.nu').read_text()
            body = '    let reuse_baseline_binary = '+source.split('    let reuse_baseline_binary = ', 1)[1].split('    let regenesis_tempo = ', 1)[0]
            # Run the production selection and loop. The builder is a filesystem
            # fixture, making a duplicate fetch/build observable as a second file.
            script = 'source contrib/bench/lifecycle/run-plan.nu\nsource contrib/bench/lifecycle/owned-worktrees.nu\nlet owned_build_worktrees = []\n'
            script += 'let prebuilt = false; let prebuilt_directory = ""; let baseline = ""; let feature = ""; let baseline_tbc = {features: ""}; let feature_tbc = {features: ""}; const E2E_A_CPUS = ""; const E2E_B_CPUS = ""\n'
            script += f'let builds = ({json.dumps(json.dumps(builds))} | from json)\n'
            script += f'let lifecycle = {str(enabled).lower()}; let effective_no_cache = {str(no_cache).lower()}\n'
            script += f'let baseline_wt = {json.dumps(str(root/"baseline"))}; let feature_wt = {json.dumps(str(root/"feature"))}\n'
            script += f'let needs_baseline = true; let needs_feature = {str(sides==2).lower()}; let profile = "profiling"\n'
            script += 'def worktree-bin [wt, profile, name] { $wt | path join $name }; def lifecycle-trim-worktree [wt, profile] {}\n'
            script += 'let build_binary = { |b| "fixture" | save ($b.wt | path join "tempo") }\n'
            script += body+'\n{reuse: $reuse_baseline_binary, baseline: $baseline_tempo, feature: $feature_tempo} | to json --raw'
            result = subprocess.run(['nu','-c',script],cwd=ROOT,text=True,capture_output=True,check=True)
            plan = json.loads(result.stdout)
            count = sum((root/side/'tempo').exists() for side in ('baseline','feature'))
            self.assertTrue(Path(plan['baseline']).is_file())
            if sides == 2:
                self.assertTrue(Path(plan['feature']).is_file())
                self.assertEqual(plan['baseline']==plan['feature'], plan['reuse'])
            return plan['reuse'], count

    def test_identical_immutable_inputs_build_once(self):
        self.assertEqual(self.run_plan(), (True, 1))

    def test_different_effective_inputs_build_separately(self):
        for delta in ({'sha':'b'*40}, {'features':'jemalloc'},
                      {'extra_rustflags':'-C target-cpu=native'}, {'bench_features':'different'}):
            with self.subTest(delta=delta):
                self.assertEqual(self.run_plan(feature=delta), (False, 2))

    def test_mutable_refs_no_cache_and_ordinary_runs_do_not_reuse(self):
        self.assertEqual(self.run_plan(feature={'sha':'main'}), (False, 2))
        self.assertEqual(self.run_plan(revision='main'), (False, 2))
        self.assertEqual(self.run_plan(revision='a'*12), (False, 2))
        self.assertEqual(self.run_plan(no_cache=True), (False, 2))
        self.assertEqual(self.run_plan(enabled=False), (False, 2))
        self.assertEqual(self.run_plan(sides=1), (False, 1))


if __name__ == '__main__':
    unittest.main()
