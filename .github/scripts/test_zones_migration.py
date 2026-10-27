"""Regression coverage for the shared workspace's CI and benchmark boundaries."""

import fnmatch
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPF_RANGE = runpy.run_path(str(ROOT / 'zones/contrib/bench/validate-spf-range.py'))


class SnapshotCacheTests(unittest.TestCase):
    def test_zones_commits_reuse_baseline_but_core_changes_invalidate_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            def git(*args):
                subprocess.run(['git', '-C', tmp, *args], check=True, capture_output=True)
            git('init', '-q')
            git('config', 'user.name', 'Test')
            git('config', 'user.email', 'test@example.invalid')
            for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                         'bin/tempo/main.rs', 'crates/evm/lib.rs', 'crates/zones/node/lib.rs',
                         'xtask/src/genesis.rs', 'xtask/src/zones/mod.rs'):
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('initial\n')
            git('add', '.')
            git('commit', '-qm', 'test: initial')
            def cache_key():
                return subprocess.check_output(
                    ['bash', '-eu', '-c', 'source "$1"; l1_snapshot_tempo_source_hash',
                     'bash', str(ROOT / 'zones/contrib/bench/l1-snapshot.sh')],
                    env=dict(os.environ, TEMPO_ROOT=tmp), text=True).strip()
            initial = cache_key()
            (repo / 'crates/zones/node/lib.rs').write_text('zones change\n')
            git('commit', '-qam', 'test: zones')
            self.assertEqual(cache_key(), initial)
            (repo / 'xtask/src/zones/mod.rs').write_text('zones generator change\n')
            git('commit', '-qam', 'test: zones generator')
            self.assertEqual(cache_key(), initial)
            (repo / 'xtask/src/genesis.rs').write_text('core generator change\n')
            git('commit', '-qam', 'test: core generator')
            self.assertNotEqual(cache_key(), initial)
            initial = cache_key()
            (repo / 'crates/evm/lib.rs').write_text('core change\n')
            git('commit', '-qam', 'test: core')
            self.assertNotEqual(cache_key(), initial)


class ProverPathTests(unittest.TestCase):
    def test_shared_runtime_and_packaging_changes_dispatch_e2e(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/zones-prover-e2e.yml').read_text())
        step = next(step for step in workflow['jobs']['dispatch']['steps']
                    if step.get('name') == 'Detect merge-queue changes')
        patterns = yaml.safe_load(step['with']['filters'])['prover']
        for path in ('crates/evm/src/lib.rs', 'crates/precompiles/src/lib.rs',
                     'crates/nitro-attestation/src/lib.rs', 'crates/zones/l1/src/lib.rs',
                     'crates/payload/types/src/lib.rs', 'bin/prover/enclave/src/main.rs',
                     'zones/docker/Dockerfile.prover-host', 'zones/scripts/run-prover-host.sh',
                     'Cargo.lock', 'rust-toolchain.toml'):
            with self.subTest(path=path):
                self.assertTrue(any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns))
        self.assertFalse(any(fnmatch.fnmatchcase('docs/README.md', pattern) for pattern in patterns))


class DockerWorkflowTests(unittest.TestCase):
    def test_image_filters_skip_test_only_batches_but_keep_runtime_inputs(self):
        tests = ['crates/node/tests/it/main.rs', 'crates/zones/node/tests/it/main.rs']
        common = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml',
                  'mainnet-network-identity.json', '.gitmodules', 'crates/evm/src/lib.rs',
                  'crates/zones/node/build.rs', 'bin/tempo/main.rs', 'xtask/src/main.rs']
        for name, detector, included, excluded in (
            ('zones-docker', 'detect-changes', common + [
                'zones/docker/Dockerfile', 'zones/scripts/package-prover-eif.sh',
                '.github/workflows/zones-docker.yml'], tests + ['docs/README.md']),
            ('network-e2e', 'detect', common + [
                'Dockerfile', '.dockerignore', 'docker-bake.hcl', 'scripts/build.sh',
                '.github/workflows/docker.yml', 'tips/verify/src/main.rs',
                'crates/node/tests/assets/test-genesis.json', 'crates/node/tests/new-fixture.json',
                'future-inputs/new.json'], tests + ['docs/README.md', 'contrib/Dockerfile',
                'localnet/index.ts', 'tips/tip-1234.md']),
        ):
            workflow = yaml.safe_load((ROOT / f'.github/workflows/{name}.yml').read_text())
            step = next(s for s in workflow['jobs'][detector]['steps'] if s.get('id') == 'paths')
            patterns = yaml.safe_load(step['with']['filters'])['images']
            if name == 'zones-docker':
                # PyYAML reads the unquoted workflow key "on" as True.
                self.assertEqual(patterns, workflow[True]['pull_request']['paths'])
            cases = [([p], False) for p in excluded] + [(excluded, False)]
            cases += [(files, True) for p in included for files in ([p], excluded + [p])]
            for files, expected in cases:
                with self.subTest(workflow=name, files=files):
                    matched = any(any(fnmatch.fnmatchcase(f, p) for p in patterns if not p.startswith('!'))
                                  and not any(fnmatch.fnmatchcase(f, p[1:]) for p in patterns if p.startswith('!'))
                                  for f in files)
                    self.assertEqual(matched, expected)

    def test_failed_detection_keeps_queue_builds_enabled(self):
        # Pin the safety guard that regressed, rather than emulate GitHub's evaluator.
        for name, detector, output, consumers in (
            ('network-e2e', 'detect', 'images_required', ['build']),
            ('zones-docker', 'detect-changes', 'required',
             ['resolve-production-build-inputs', 'eif-toolchain']),
        ):
            jobs = yaml.safe_load((ROOT / f'.github/workflows/{name}.yml').read_text())['jobs']
            self.assertIn("steps.paths.outputs.changes == '' ||", jobs[detector]['outputs'][output])
            fallback = ("!cancelled() && ((github.event_name == 'merge_group' && "
                        f"(needs.{detector}.result != 'success' || needs.{detector}.outputs.{output} != 'false')) ||")
            for consumer in consumers:
                with self.subTest(workflow=name, job=consumer):
                    guard = ' '.join(jobs[consumer]['if'].split()).removeprefix('${{ ')
                    self.assertTrue(guard.startswith(fallback), guard)
            if name == 'zones-docker':
                self.assertIn('!cancelled()', jobs['build-and-push']['if'])


class DockerIgnoreTests(unittest.TestCase):
    def test_all_dockerfiles_use_the_same_context_filter(self):
        dockerfiles = sorted((ROOT / 'zones/docker').glob('Dockerfile*'))
        dockerfiles = [path for path in dockerfiles if not path.name.endswith('.dockerignore')]
        self.assertTrue(dockerfiles)
        expected = dockerfiles[0].with_name(dockerfiles[0].name + '.dockerignore').read_bytes()
        for dockerfile in dockerfiles:
            with self.subTest(dockerfile=dockerfile.name):
                self.assertEqual(dockerfile.with_name(dockerfile.name + '.dockerignore').read_bytes(), expected)


class SpfRangeTests(unittest.TestCase):
    def test_zero_portal_hash_polls_until_the_first_submission(self):
        submitted = '0x' + 'ab' * 32
        hashes = iter(['0x' + '00' * 32] * 2 + [submitted])
        commands = []

        def check_output(command, **_):
            commands.append(command[:3])
            return (next(hashes) if command[1] == 'call' else '7') + '\n'

        with mock.patch('subprocess.check_output', side_effect=check_output), mock.patch('time.sleep'):
            SPF_RANGE['wait_for_submission'](5, 'portal', 'l1', 'zone', 120)
        self.assertEqual(commands, [['cast', 'call', 'portal']] * 3 + [['cast', 'block', submitted]])

    def test_user_transactions_count_only_measured_blocks(self):
        # Setup traffic in block 1 and later traffic in block 5 share batches with the range.
        batches = {
            2: [(1, 2), (2, 0), (3, 1)],
            4: [(4, 0), (5, 3)],
        }

        def generate(cursor, output):
            blocks = [{'number': number, 'transactions': ['0x00'] * count}
                      for number, count in batches[cursor]]
            output.write_text(json.dumps({'zoneBlocks': blocks}))

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'manifest.json'
            with mock.patch('builtins.print'):
                result = SPF_RANGE['validate_range'](2, 4, output, generate)
            self.assertEqual(json.loads(output.read_text()), result)
        self.assertEqual(result, {
            'status': 'complete',
            'from_block': 2,
            'to_block': 4,
            'user_transactions': 1,
            'batches': [{'from_block': 1, 'to_block': 3}, {'from_block': 4, 'to_block': 5}],
        })
