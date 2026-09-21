"""Execute actual Nu creation/build cleanup with real disposable Git worktrees."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import worktree_owner

ROOT=Path(__file__).resolve().parents[3]


def quoted(value):return json.dumps(str(value))


@unittest.skipUnless(shutil.which('nu'),'Nushell required')
class BuildCleanupTests(unittest.TestCase):
    def exercise(self,case,*,cleanup_failure=False,replace=False):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);repo=root/'repo';repo.mkdir()
            def git(*args):return subprocess.check_output(['git',*args],cwd=repo,stderr=subprocess.DEVNULL,text=True).strip()
            git('init');git('config','user.name','fixture');git('config','user.email','fixture@example.invalid')
            (repo/'tracked').write_text('owned fixture');git('add','.');git('commit','-m','fixture');sha=git('rev-parse','HEAD')
            (repo/'contrib'/'bench').mkdir(parents=True);(repo/'contrib'/'bench'/'lifecycle').symlink_to(ROOT/'contrib'/'bench'/'lifecycle',target_is_directory=True)
            bins=root/'bin';bins.mkdir()
            (bins/'df').write_text('#!/bin/sh\nprintf "Filesystem 1M-blocks Used Available Use%% Mounted\\nfixture 999999 0 %s 0%% /\\n" "$CAPACITY_MIB"\n')
            (bins/'cargo').write_text('#!/bin/sh\nif [ "$CASE" = build ]; then echo "fixture original compiler diagnostic" >&2; exit 7; fi\nexit 0\n')
            realgit=shutil.which('git')
            (bins/'git').write_text('#!/bin/sh\nif [ "$FAIL_CLEANUP" = 1 ] && [ "$1" = worktree ] && [ "$2" = remove ]; then echo "cleanup secondary failure" >&2; exit 8; fi\nexec '+quoted(realgit)+' "$@"\n')
            for f in bins.iterdir():f.chmod(0o755)
            source=(ROOT/'bench-e2e.nu').read_text()
            creation=source.split('    for wt in $worktrees {',1)[1].split('    let global_build_features =',1)[0]
            creation='    for wt in $worktrees {'+creation
            body='    let reuse_baseline_binary = '+source.split('    let reuse_baseline_binary = ',1)[1].split('    let regenesis_tempo = ',1)[0]
            helper=(ROOT/'tempo.nu').read_text().split('def build-in-worktree ',1)[1].split('# Get the path to a built binary',1)[0]
            helper='def build-in-worktree '+helper
            a=root/'baseline';b=root/'feature';other=root/'unrelated';other.mkdir();(other/'keep').write_text('untouched')
            script='source contrib/bench/lifecycle/run-plan.nu\nsource contrib/bench/lifecycle/owned-worktrees.nu\n'
            script+=(ROOT/'contrib/bench/lifecycle/disk.nu').read_text().split('def lifecycle-trim-worktree',1)[0]+'\n'
            script+='const RUSTFLAGS = ""\ndef bench-cache-key [sha, features, no_defaults] { $sha }\ndef try-cache-download [wt, profile, sha, key] { false }\ndef cargo-feature-args [features, no_defaults] { [] }\ndef cache-upload [wt, profile, sha, key] {}\n'
            script+=helper+'\n'
            script+='def lifecycle-trim-worktree [wt, profile] { if $env.CASE == "trim" { error make {msg: "fixture original trim", help: "retained original help"} } }\ndef worktree-bin [wt, profile, name] { $wt | path join $name }\n'
            script+=f'let baseline_wt = {quoted(a)}; let feature_wt = {quoted(b)}; let baseline = "{sha}"; let feature = "{sha}"\nlet needs_baseline = true; let needs_feature = true; let lifecycle = true; let effective_no_cache = false; let profile = "profiling"; let worktrees = [$baseline_wt $feature_wt]\n'
            script+=creation+'\n'
            if replace:
                script+=f'^mv {quoted(a)} {quoted(root/"moved-owned")}\nmkdir {quoted(a)}\n"replacement" | save {quoted(a/"keep")}\n'
            script+='let prebuilt = false; let prebuilt_directory = ""; let baseline_tbc = {features: ""}; let feature_tbc = {features: ""}; const E2E_A_CPUS = ""; const E2E_B_CPUS = ""\n'
            script+='let builds = [{label: "baseline", wt: $baseline_wt, ref_name: $baseline, sha: $baseline, features: "", extra_rustflags: "", bench_features: ""}, {label: "feature", wt: $feature_wt, ref_name: $feature, sha: $feature, features: "", extra_rustflags: "", bench_features: ""}]\n'
            script+='let build_binary = {|b| build-in-worktree --lifecycle-build $b.wt $b.ref_name $profile $b.features $b.sha }\n'+body
            env=dict(os.environ,PATH=str(bins)+os.pathsep+os.environ['PATH'],CASE=case,FAIL_CLEANUP=str(int(cleanup_failure)),CAPACITY_MIB=str(1 if case=='retrieval' else 63000 if case=='compile_guard' else 100000))
            result=subprocess.run(['nu','-c',script],cwd=repo,env=env,text=True,capture_output=True)
            self.assertEqual((other/'keep').read_text(),'untouched')
            if case=='success':
                self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(a.exists() and b.exists())
            else:
                self.assertEqual(result.returncode,7 if case=="build" else 1,result.stdout+result.stderr)
                expected={'retrieval':'before binary retrieval','compile_guard':'before benchmark build','build':'fixture original compiler diagnostic','trim':'fixture original trim'}[case]
                self.assertIn(expected,result.stdout+result.stderr)
                if case=='trim':self.assertIn('retained original help',result.stderr)
                self.assertNotIn('cleanup secondary failure',result.stdout+result.stderr)
                if cleanup_failure:self.assertTrue(a.exists() and b.exists())
                elif replace:
                    self.assertEqual((a/'keep').read_text(),'replacement');self.assertTrue((root/'moved-owned').exists());self.assertFalse(b.exists())
                else:self.assertFalse(a.exists() or b.exists())
            return result.returncode

    def test_failure_stages_cleanup_only_owned_worktrees(self):
        for case in ('retrieval','compile_guard','build','trim'):
            with self.subTest(case=case):
                self.exercise(case)
    def test_success_keeps_worktrees_for_capture(self):self.exercise('success')
    def test_cleanup_failure_preserves_original_diagnostic(self):self.exercise('trim',cleanup_failure=True)
    def test_replacement_directory_is_not_deleted(self):self.exercise('compile_guard',replace=True)


class ReceiptTests(unittest.TestCase):
    def test_replaced_git_marker_and_symlink_refuse_removal(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'owned';p.mkdir();marker=p/'.git';marker.write_text('gitdir: fixture\n');receipt=worktree_owner.snapshot(p)
            marker.unlink();marker.write_text('gitdir: different\n');self.assertFalse(worktree_owner.remove(receipt))
            marker.unlink();marker.symlink_to(Path(d)/'missing')
            with self.assertRaises(ValueError):worktree_owner.snapshot(p)

if __name__=='__main__':unittest.main()
