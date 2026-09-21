import copy
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from prebuilt import Rejected, TOOLS
from prebuilt_workflow import inputs

ROOT=Path(__file__).resolve().parents[3]


def without_main_runner_updates(workflow):
    # Reverse only the reviewed main d84e56a00b runner updates for frozen history.
    blocks = [
        '  # Allow Aegis to finish its 90-second Socket lookup before Cargo times out.\n  CARGO_HTTP_TIMEOUT: "180"\n',
        '    permissions:\n      actions: read\n      contents: read\n      id-token: write\n',
        '      - name: Secure runner\n        uses: tempoxyz/gh-actions/actions/secure-runner@68851d67c611dc0050e9f3fcd5bd47f3f899a00e\n\n',
    ]
    for block in blocks:
        assert workflow.count(block) == 1
        workflow = workflow.replace(block, '')
    for action, previous, count in [
        ('actions/github-sts', 'c0292122e255def866c64c55e5844d1e7d5fe7ad', 3),
        ('vendor/dtolnay/rust-toolchain', '3626124474a987bc74b41fc7ae65b2e23f8e4e4e', 1),
        ('vendor/mozilla-actions/sccache-action', '3626124474a987bc74b41fc7ae65b2e23f8e4e4e', 1),
    ]:
        current = 'tempoxyz/gh-actions/' + action + '@68851d67c611dc0050e9f3fcd5bd47f3f899a00e'
        assert workflow.count(current) == count
        workflow = workflow.replace(current, 'tempoxyz/gh-actions/' + action + '@' + previous)
    return workflow


def without_workspace_guard(workflow):
    workflow = without_main_runner_updates(workflow)
    guarded_reset = '''        env:
          CLEANUP_DIRECTORY: ${{ steps.runner-cleanup.outputs.directory }}
        run: |
          set -euo pipefail
          sudo -n /usr/bin/python3 -I "$CLEANUP_DIRECTORY/cleanup.py" --check-workspace "$GITHUB_WORKSPACE"
          sudo rm -rf --one-file-system -- "$GITHUB_WORKSPACE"
'''
    assert workflow.count(guarded_reset) == 1
    workflow = workflow.replace(guarded_reset, '        run: |\n          sudo rm -rf "$GITHUB_WORKSPACE"\n')
    return workflow


def without_prebuilt(workflow):
    workflow,count=re.subn(r'      BENCH_BINARY_MODE: "prebuilt_v1"\n      BENCH_RUN_CLEANUP_CONTRACT: "owned_artifacts_v1"\n      # Filled only.*?\n      BENCH_PREBUILT_PLAN_SHA256: "[0-9a-f]{64}"\n','',workflow)
    assert count==1
    workflow,count=re.subn(r'      - name: Admit exact prebuilt binaries\n.*?(?=      - name:)','',workflow,flags=re.DOTALL)
    assert count==1
    tracy="(env.BENCH_TRACY != 'off' && env.BENCH_BINARY_MODE != 'prebuilt_v1')"
    assert workflow.count(tracy)==2
    workflow=workflow.replace(tracy,"(env.BENCH_TRACY != 'off')")
    condition=" && (env.BENCH_BINARY_MODE != 'prebuilt_v1')"
    assert workflow.count(condition)==3
    workflow=workflow.replace(condition,'')
    addition='          [ "$BENCH_BINARY_MODE" = "prebuilt_v1" ] && cmd+=(--prebuilt-directory "$BENCH_PREBUILT_DIRECTORY")\n'
    assert workflow.count(addition)==1
    return workflow.replace(addition,'')


class Workflow(unittest.TestCase):
    def test_only_explicit_prebuilt_boundary_changes_workflow(self):
        source=(ROOT/'.github/workflows/bench-e2e.yml').read_text()
        # Frozen workflow including reviewed final cleanup; works in source-only checkouts.
        self.assertEqual(hashlib.sha256(without_prebuilt(without_workspace_guard(source)).encode()).hexdigest(),'b5d893409234ae42d29d9202dfe72085edc23bbb4db1a52d8dfcec533ab3732b')
        self.assertIn('prebuilt_workflow.py',source)
        self.assertLess(source.index('id: refs'),source.index('- name: Admit exact prebuilt binaries'))
        self.assertLess(source.index('- name: Admit exact prebuilt binaries'),source.index('- name: Run e2e benchmark'))

    def test_inputs_reject_all_compile_or_unverified_environment_routes(self):
        env=dict(BENCH_BINARY_MODE='prebuilt_v1',BENCH_LIFECYCLE='true',BENCH_NO_SLACK='true',BENCH_FORCE_BLOAT='false',BENCH_NO_CACHE='false',BENCH_SAMPLY='false',BENCH_OTLP='false',BENCH_VALSCOPE='false',BENCH_TRACY='off',BENCH_TXGEN_REF=TOOLS,BENCH_FEATURES='jemalloc,asm-keccak,keccak-cache-global',BENCH_RUN_SIDE='feature')
        self.assertEqual(inputs(env),['feature'])
        for key,value in [('BENCH_FORCE_BLOAT','true'),('BENCH_NO_CACHE','true'),('BENCH_TRACY','tracy'),('BENCH_LIFECYCLE','false'),('BENCH_VALSCOPE','true'),('BENCH_FEATURE_FEATURES','otlp'),('BENCH_FEATURE_ENV','RUSTFLAGS=native'),('BENCH_TXGEN_REF','main')]:
            with self.subTest(key=key),self.assertRaises(Rejected):inputs({**env,key:value})

    @unittest.skipUnless(shutil.which('nu'),'Nu required for actual helper regression')
    def test_actual_snapshot_guard_never_calls_generation(self):
        helper=(ROOT/'contrib/bench/lifecycle/prebuilt.nu').read_text()
        with tempfile.TemporaryDirectory() as d:
            script=Path(d)/'test.nu';marker=Path(d)/'compile'
            for ready,force,init,success in [('true','false','false',True),('false','false','false',False),('true','true','false',False),('true','false','true',False)]:
                script.write_text(helper+f'\nprebuilt-require-snapshot true {ready} {force} {init}\nprint "admitted"\n')
                run=subprocess.run(['nu','--no-config-file',str(script)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                self.assertEqual(run.returncode==0,success)
                self.assertEqual(b'admitted' in run.stdout,success)
                self.assertFalse(marker.exists())

    @unittest.skipUnless(shutil.which('nu'),'Nu required')
    def test_actual_build_closure_calls_only_verified_selector(self):
        source=(ROOT/'bench-e2e.nu').read_text()
        closure='let build_binary = '+source.split('let build_binary = ',1)[1].split('    let reuse_baseline_binary',1)[0]
        helper=(ROOT/'contrib/bench/lifecycle/prebuilt.nu').read_text()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fake=root/'python3'
            fake.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" > "$CALL_LOG"\nprintf \'{"tempo":"/verified","txgen_tempo":"/tools","bench":"/bench"}\\n\'\n')
            fake.chmod(0o755)
            common=helper+'''\nlet prebuilt = true; let prebuilt_directory = "/owned"
let effective_no_cache = false; let lifecycle = true; let no_default_features = true; let profile = "profiling"
const E2E_A_CPUS = "0-1"; const E2E_B_CPUS = "2-3"
'''+closure+'\ndo $build_binary {label: "feature", sha: "'+('1'*40)+'", features: "jemalloc,asm-keccak,keccak-cache-global"}\n'
            result=subprocess.run(['nu','--no-config-file','-c',common],cwd=ROOT,text=True,capture_output=True,env={**os.environ,'PATH':str(root)+os.pathsep+os.environ['PATH'],'CALL_LOG':str(root/'called')})
            self.assertEqual(result.returncode,0,result.stderr)
            call=(root/'called').read_text()
            self.assertIn('prebuilt_consumer.py select',call)
            self.assertIn('--runtime '+('1'*40),call)
            self.assertNotIn('cargo',call)

    def test_actual_nu_routes_prebuilt_before_build_and_before_init(self):
        source=(ROOT/'bench-e2e.nu').read_text()
        closure=source.split('let build_binary = { |b|',1)[1].split('let reuse_baseline_binary',1)[0]
        self.assertRegex(closure,r'if \$prebuilt \{\s+prebuilt-select')
        self.assertIn('} else if $effective_no_cache {',closure)
        self.assertIn('if not $prebuilt { lifecycle-trim-worktree',source)
        self.assertLess(source.index('prebuilt-require-snapshot $prebuilt'),source.index('if $should_init_snapshots {'))
        admission=source.split('validate-schelk-state $E2E_A_STATE_PATH $E2E_B_STATE_PATH',1)[1]
        self.assertLess(admission.index('prebuilt-require-snapshot true'),admission.index('cleanup-local-e2e-processes'))
        self.assertLess(admission.index('prebuilt-require-snapshot true'),admission.index('bench-restore-at'))
        phase=source.split('def run-local-e2e-phase',1)[1].split('def e2e-load',1)[0]
        self.assertLess(phase.index('prebuilt-select'),phase.index('cleanup-local-e2e-processes'))
        self.assertLess(phase.index('prebuilt-admission.json'),phase.index('phase_archive.py pack'))


if __name__=='__main__':unittest.main()
