"""Regression coverage for the shared workspace's CI and benchmark boundaries."""

import fnmatch
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


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


class DockerIgnoreTests(unittest.TestCase):
    def test_all_dockerfiles_use_the_same_context_filter(self):
        dockerfiles = sorted((ROOT / 'zones/docker').glob('Dockerfile*'))
        dockerfiles = [path for path in dockerfiles if not path.name.endswith('.dockerignore')]
        self.assertTrue(dockerfiles)
        expected = dockerfiles[0].with_name(dockerfiles[0].name + '.dockerignore').read_bytes()
        for dockerfile in dockerfiles:
            with self.subTest(dockerfile=dockerfile.name):
                self.assertEqual(dockerfile.with_name(dockerfile.name + '.dockerignore').read_bytes(), expected)
